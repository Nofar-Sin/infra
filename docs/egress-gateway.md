# Sandbox Egress Gateway

Egress gateways enable live migration of Firecracker sandboxes without breaking
outbound TCP connections. They replace per-node MASQUERADE with a centralized
NAT layer that preserves conntrack state across migrations.

## Problem

Without egress gateways, each orchestrator node MASQUERADEs sandbox traffic to
its own IP. When a sandbox migrates to a different node:

1. Source IP changes (new node IP) — remote peers see a different source
2. Conntrack entries are lost — the new node has no NAT mapping for existing flows
3. Outbound TCP connections break

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│ Orchestrator Node (any)                                         │
│                                                                 │
│   Sandbox (HostIP 10.11.x.x)                                   │
│     │                                                           │
│     ▼                                                           │
│   netns SNAT (169.254.0.21 → 10.11.x.x)                        │
│     │                                                           │
│     ▼                                                           │
│   Policy route: src 10.11.0.0/16 → nexthop group               │
│     │                   ┌──────────────┐                        │
│     └──IPIP tunnel──────┤ Nexthop      │                        │
│                         │ Group (ECMP) │                        │
│                         └──┬───────┬───┘                        │
└────────────────────────────┼───────┼────────────────────────────┘
                             │       │
                    ┌────────┘       └────────┐
                    ▼                         ▼
           ┌──────────────┐          ┌──────────────┐
           │ Gateway gw-1 │          │ Gateway gw-2 │
           │ (static IP)  │          │ (static IP)  │
           │ SNAT → own   │          │ SNAT → own   │
           │ internal IP  │          │ internal IP  │
           └──────┬───────┘          └──────┬───────┘
                  │                         │
                  └────────┬────────────────┘
                           ▼
                    ┌──────────────┐
                    │  Cloud NAT   │
                    │  (200 IPs)   │
                    └──────┬───────┘
                           ▼
                        Internet
```

### Why connections survive migration

1. Sandbox keeps the **same HostIP** across nodes (stored in metadata, not
   derived from slot index)
2. The orchestrator's ECMP hash is based on L4 fields (src IP + dst IP +
   src port + dst port) — same connection always hits the same gateway
3. The gateway's conntrack still maps `(HostIP, port) → (gateway_internal_IP, port)`
4. Cloud NAT's conntrack still maps `(gateway_internal_IP, port) → (external_IP, port)`
5. Remote peer sees the same source IP and port — TCP connection continues

## Enabling

Set in your `.tfvars`:

```hcl
sandbox_egress_gateway_enabled = true

sandbox_egress_gateways = {
  gw-1 = { active = true }
  gw-2 = { active = true }
}

sandbox_egress_ip_count = 200  # number of external NAT IPs
```

Then:

```bash
make plan    # review changes
make apply   # creates gateways, Cloud NAT, firewall rules
# Roll orchestrator nodes to pick up the new tunnels
```

## Operations

### Adding a gateway

Add a new key to `sandbox_egress_gateways`:

```hcl
sandbox_egress_gateways = {
  gw-1 = { active = true }
  gw-2 = { active = true }
  gw-3 = { active = true }   # new
}
```

Apply, then roll orchestrator nodes. New nodes create tunnels to all active
gateways and include them in the ECMP nexthop group.

### Draining a gateway

Set `active = false`:

```hcl
sandbox_egress_gateways = {
  gw-1 = { active = true }
  gw-2 = { active = false }  # draining
}
```

Apply, then roll orchestrator nodes. Newly booted orchestrators won't tunnel
to gw-2. The gateway VM keeps running so existing connections on un-rolled
orchestrators continue to work. Once all orchestrators have rolled, remove
the key entirely and apply to destroy the VM.

### Gateway crash recovery

Each gateway runs as a MIG (Managed Instance Group) with auto-healing:

1. **Immediate** (~5s): The orchestrator health checker detects the dead gateway
   via ping failure. The nexthop group is atomically updated to exclude it.
   Traffic shifts to surviving gateways with zero blackhole window.

2. **Auto-heal** (~2-3 min): GCP MIG detects the health check failure and
   recreates the VM. Because the gateway uses a **static internal IP**, the
   new VM gets the same IP. Orchestrator tunnels automatically reconnect.
   The health checker detects recovery and re-adds the gateway to the
   nexthop group.

Connections that were going through the crashed gateway are lost (their
conntrack died with the VM), but no new connections are affected.

### Adding/removing NAT IPs

Change `sandbox_egress_ip_count` and apply. Cloud NAT handles the pool
automatically. No gateway or orchestrator changes needed.

### Placing gateways in specific zones

```hcl
sandbox_egress_gateways = {
  gw-us-c1a = { active = true, zone = "us-central1-a" }
  gw-us-c1b = { active = true, zone = "us-central1-b" }
}
```

## Resilience design

| Concern | How it's handled |
|---------|-----------------|
| Gateway crash | MIG auto-heals. Health checker excludes it in ~5s. |
| Route update race | Nexthop groups — `ip nexthop replace` is atomic, no blackhole window. |
| Gateway IP change | Static internal IPs survive MIG recreation. |
| ECMP consistency | `fib_multipath_hash_policy=1` — L4 hash ensures same connection hits same gateway. |
| Silent forwarding failure | Gateway health check verifies tunnel UP + SNAT rule + outbound connectivity. |
| Cloud NAT exhaustion | Gateway health check tests outbound HTTP. MIG replaces if it fails. |

## Go code changes

Two small changes in the orchestrator's network package:

- **`network.go`**: Removed per-sandbox MASQUERADE rule. Widened FORWARD rules
  to not pin to a specific egress interface (routing table decides).
- **`slot.go`**: `NewSlot()` accepts an optional `hostIP` parameter. When
  provided (during migration/resume), the sandbox keeps its original HostIP
  instead of deriving one from the slot index.

All existing callers pass `nil` — zero behavior change for non-migration flows.

## File inventory

| File | Role |
|------|------|
| `iac/provider-gcp/nomad-cluster/egress-gateway.tf` | Gateway MIGs, Cloud NAT, static IPs, firewall, health check |
| `iac/provider-gcp/nomad-cluster/scripts/start-client.sh` | IPIP tunnels, nexthop groups, health checker daemon |
| `iac/provider-gcp/nomad-cluster/worker-cluster/nodepool.tf` | `can_ip_forward` on orchestrator templates |
| `packages/orchestrator/pkg/sandbox/network/network.go` | Removed MASQUERADE, widened FORWARD rules |
| `packages/orchestrator/pkg/sandbox/network/slot.go` | Optional stable HostIP parameter |
