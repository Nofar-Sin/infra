# Egress gateway pool for sandbox live migration support.
#
# Each gateway is a MIG (size=1) with auto-healing and a static internal IP
# that survives VM recreation. The orchestrator-side health checker uses Linux
# nexthop groups for atomic failover — no blackhole window during route updates.
#
# Resilience features:
#   - Static internal IPs: MIG auto-heal recreates the VM with the same IP,
#     so orchestrator tunnels keep working without a roll.
#   - Nexthop groups: route changes are a single atomic kernel operation.
#   - Consistent ECMP: fib_multipath_hash_policy=1 ensures the same
#     HostIP+connection always hits the same gateway across migrations.
#   - End-to-end health check: verifies tunnel + SNAT + Cloud NAT outbound.
#
# Draining:
#   1. Set active = false → terraform apply
#   2. Roll orchestrator nodes → they stop tunneling to this gateway
#   3. Once drained, remove the key → terraform apply (destroys MIG)
#
# Adding:
#   1. Add key with active = true → terraform apply (creates MIG + VM)
#   2. Roll orchestrator nodes → they pick up the new gateway

locals {
  egress_gw_enabled = var.sandbox_egress_gateway_enabled

  egress_gw_startup_script = <<-SCRIPT
    #!/bin/bash
    set -euo pipefail

    SANDBOX_CIDR="${var.sandbox_host_network_cidr}"

    sysctl -w net.ipv4.ip_forward=1
    echo "net.ipv4.ip_forward=1" >> /etc/sysctl.conf

    # Reduce conntrack timeout (default 432000s = 5 days). 1 day is enough
    # for most sandbox connections and speeds up drain completion.
    sysctl -w net.netfilter.nf_conntrack_tcp_timeout_established=86400

    modprobe ipip

    INTERNAL_IP=$(curl -sf -H 'Metadata-Flavor: Google' http://metadata.google.internal/computeMetadata/v1/instance/network-interfaces/0/ip)

    ip tunnel add egress0 mode ipip remote 0.0.0.0 local "$INTERNAL_IP"
    ip link set egress0 up

    iptables -t nat -A POSTROUTING -s "$SANDBOX_CIDR" -o ens4 -j SNAT --to-source "$INTERNAL_IP"
    iptables -A FORWARD -i egress0 -j ACCEPT
    iptables -A FORWARD -o egress0 -j ACCEPT

    # End-to-end health check for MIG auto-healing.
    # Verifies: (1) tunnel UP, (2) SNAT rule present, (3) outbound connectivity.
    mkdir -p /opt/egress-health
    cat > /opt/egress-health/check.py <<PYEOF
import http.server, subprocess, urllib.request

SANDBOX_CIDR = "$SANDBOX_CIDR"
INTERNAL_IP = "$INTERNAL_IP"

class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        failed = []

        r = subprocess.run(["ip", "link", "show", "egress0"], capture_output=True)
        if r.returncode != 0 or b"UP" not in r.stdout:
            failed.append("tunnel_down")

        r = subprocess.run(["iptables", "-t", "nat", "-C", "POSTROUTING",
            "-s", SANDBOX_CIDR, "-o", "ens4", "-j", "SNAT",
            "--to-source", INTERNAL_IP], capture_output=True)
        if r.returncode != 0:
            failed.append("snat_missing")

        try:
            urllib.request.urlopen("http://connectivitycheck.gstatic.com/generate_204", timeout=3)
        except Exception:
            failed.append("no_outbound")

        if failed:
            self.send_response(503)
            self.end_headers()
            self.wfile.write(",".join(failed).encode())
        else:
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"ok")

    def log_message(self, *args):
        pass

http.server.HTTPServer(("", 8080), Handler).serve_forever()
PYEOF

    python3 /opt/egress-health/check.py &

    echo "Egress gateway ready (ip=$INTERNAL_IP)"
  SCRIPT
}

# ---------- Subnet for egress gateways ----------

resource "google_compute_subnetwork" "egress_gateway" {
  count = local.egress_gw_enabled ? 1 : 0

  name          = "${var.prefix}egress-gw-subnet"
  ip_cidr_range = var.sandbox_egress_gateway_subnet_cidr
  region        = var.gcp_region
  network       = var.network_name
}

# ---------- Static internal IPs for gateway VMs ----------
# Reserved so MIG auto-healed instances get the same IP. Orchestrator
# tunnels point to these and never need reconfiguration.

resource "google_compute_address" "egress_gateway_internal" {
  for_each = local.egress_gw_enabled ? var.sandbox_egress_gateways : {}

  name         = "${var.prefix}egress-gw-${each.key}-internal"
  subnetwork   = google_compute_subnetwork.egress_gateway[0].self_link
  address_type = "INTERNAL"
  region       = var.gcp_region
}

# ---------- Static external IPs for Cloud NAT ----------

resource "google_compute_address" "sandbox_egress_ips" {
  count  = local.egress_gw_enabled ? var.sandbox_egress_ip_count : 0
  name   = "${var.prefix}sandbox-egress-ip-${count.index + 1}"
  region = var.gcp_region
}

# ---------- Cloud Router + Cloud NAT ----------

resource "google_compute_router" "sandbox_egress" {
  count   = local.egress_gw_enabled ? 1 : 0
  name    = "${var.prefix}sandbox-egress-router"
  network = var.network_name
  region  = var.gcp_region
}

resource "google_compute_router_nat" "sandbox_egress" {
  count = local.egress_gw_enabled ? 1 : 0

  name                               = "${var.prefix}sandbox-egress-nat"
  router                             = google_compute_router.sandbox_egress[0].name
  nat_ip_allocate_option             = "MANUAL_ONLY"
  nat_ips                            = google_compute_address.sandbox_egress_ips[*].self_link
  source_subnetwork_ip_ranges_to_nat = "LIST_OF_SUBNETWORKS"
  min_ports_per_vm                   = var.sandbox_egress_min_ports_per_vm

  subnetwork {
    name                    = google_compute_subnetwork.egress_gateway[0].self_link
    source_ip_ranges_to_nat = ["ALL_IP_RANGES"]
  }

  log_config {
    enable = true
    filter = "ERRORS_ONLY"
  }

  lifecycle {
    create_before_destroy = true
  }
}

# ---------- Health check for MIG auto-healing ----------

resource "google_compute_health_check" "egress_gateway" {
  count = local.egress_gw_enabled ? 1 : 0

  name                = "${var.prefix}egress-gw-health"
  check_interval_sec  = 10
  timeout_sec         = 5
  healthy_threshold   = 2
  unhealthy_threshold = 3

  http_health_check {
    port         = 8080
    request_path = "/"
  }
}

# ---------- Instance template per gateway ----------

resource "google_compute_instance_template" "egress_gateway" {
  for_each = local.egress_gw_enabled ? var.sandbox_egress_gateways : {}

  name_prefix = "${var.prefix}egress-gw-${each.key}-"

  machine_type   = each.value.machine_type
  can_ip_forward = true

  disk {
    auto_delete  = true
    boot         = true
    source_image = "debian-cloud/debian-12"
    disk_size_gb = 10
  }

  network_interface {
    subnetwork = google_compute_subnetwork.egress_gateway[0].self_link
    network_ip = google_compute_address.egress_gateway_internal[each.key].address
  }

  metadata_startup_script = local.egress_gw_startup_script

  tags = ["${var.prefix}egress-gateway"]

  labels = merge(var.labels, {
    egress_gateway = each.key
  })

  service_account {
    email  = var.google_service_account_email
    scopes = ["cloud-platform"]
  }

  lifecycle {
    create_before_destroy = true
  }
}

# ---------- MIG per gateway (size=1, auto-healing) ----------

resource "google_compute_instance_group_manager" "egress_gateway" {
  for_each = local.egress_gw_enabled ? var.sandbox_egress_gateways : {}

  name               = "${var.prefix}egress-gw-${each.key}"
  base_instance_name = "${var.prefix}egress-gw-${each.key}"
  zone               = each.value.zone != "" ? each.value.zone : var.gcp_zone
  target_size        = 1

  version {
    name              = "primary"
    instance_template = google_compute_instance_template.egress_gateway[each.key].id
  }

  auto_healing_policies {
    health_check      = google_compute_health_check.egress_gateway[0].id
    initial_delay_sec = 120
  }

  update_policy {
    type                  = "PROACTIVE"
    minimal_action        = "REPLACE"
    max_surge_fixed       = 1
    max_unavailable_fixed = 0
  }
}

# ---------- Firewall ----------

resource "google_compute_firewall" "allow_ipip_to_egress_gw" {
  count = local.egress_gw_enabled ? 1 : 0

  name    = "${var.prefix}allow-ipip-to-egress-gw"
  network = var.network_name

  allow {
    protocol = "ipip"
  }

  source_tags = [var.cluster_tag_name]
  target_tags = ["${var.prefix}egress-gateway"]
}

resource "google_compute_firewall" "allow_egress_gw_to_orchestrators" {
  count = local.egress_gw_enabled ? 1 : 0

  name    = "${var.prefix}allow-egress-gw-return"
  network = var.network_name

  allow {
    protocol = "ipip"
  }

  source_tags = ["${var.prefix}egress-gateway"]
  target_tags = [var.cluster_tag_name]
}

resource "google_compute_firewall" "allow_egress_gw_healthcheck" {
  count = local.egress_gw_enabled ? 1 : 0

  name    = "${var.prefix}allow-egress-gw-healthcheck"
  network = var.network_name

  allow {
    protocol = "tcp"
    ports    = ["8080"]
  }

  source_ranges = ["130.211.0.0/22", "35.191.0.0/16"]
  target_tags   = ["${var.prefix}egress-gateway"]
}

# ---------- Outputs ----------
# IPs come from the static address resources, not data source lookups.

output "egress_gateway_all" {
  description = "Map of gateway name to static internal IP and active status."
  value = {
    for k, v in google_compute_address.egress_gateway_internal : k => {
      internal_ip = v.address
      active      = var.sandbox_egress_gateways[k].active
    }
  }
}

output "sandbox_egress_external_ips" {
  description = "List of external IPs used by sandbox egress Cloud NAT."
  value       = google_compute_address.sandbox_egress_ips[*].address
}
