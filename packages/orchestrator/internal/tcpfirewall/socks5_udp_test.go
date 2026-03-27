package tcpfirewall

import (
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMarshalSOCKS5UDPDatagram_IPv4(t *testing.T) {
	t.Parallel()

	dst := net.ParseIP("1.2.3.4")
	data := []byte("hello")

	buf := marshalSOCKS5UDPDatagram(dst, 8080, data)

	require.Len(t, buf, 15)

	assert.Equal(t, byte(0x00), buf[0], "RSV[0]")
	assert.Equal(t, byte(0x00), buf[1], "RSV[1]")
	assert.Equal(t, byte(0x00), buf[2], "FRAG")
	assert.Equal(t, byte(socks5AtypIPv4), buf[3], "ATYP")
	assert.Equal(t, net.IP{1, 2, 3, 4}, net.IP(buf[4:8]), "DST.ADDR")
	assert.Equal(t, byte(0x1F), buf[8], "PORT high")
	assert.Equal(t, byte(0x90), buf[9], "PORT low")
	assert.Equal(t, []byte("hello"), buf[10:], "DATA")
}

func TestMarshalSOCKS5UDPDatagram_IPv6(t *testing.T) {
	t.Parallel()

	dst := net.ParseIP("::1")
	data := []byte("world")

	buf := marshalSOCKS5UDPDatagram(dst, 443, data)

	require.Len(t, buf, 27)
	assert.Equal(t, byte(socks5AtypIPv6), buf[3])
}

func TestUnmarshalSOCKS5UDPDatagram_IPv4(t *testing.T) {
	t.Parallel()

	original := marshalSOCKS5UDPDatagram(net.ParseIP("10.0.0.1"), 53, []byte("dns-query"))

	dgram, err := unmarshalSOCKS5UDPDatagram(original)
	require.NoError(t, err)

	assert.True(t, net.ParseIP("10.0.0.1").Equal(dgram.DstAddr))
	assert.Equal(t, uint16(53), dgram.DstPort)
	assert.Equal(t, []byte("dns-query"), dgram.Data)
}

func TestUnmarshalSOCKS5UDPDatagram_IPv6(t *testing.T) {
	t.Parallel()

	dst := net.ParseIP("2001:db8::1")
	original := marshalSOCKS5UDPDatagram(dst, 443, []byte("tls"))

	dgram, err := unmarshalSOCKS5UDPDatagram(original)
	require.NoError(t, err)

	assert.True(t, dst.Equal(dgram.DstAddr))
	assert.Equal(t, uint16(443), dgram.DstPort)
	assert.Equal(t, []byte("tls"), dgram.Data)
}

func TestUnmarshalSOCKS5UDPDatagram_RoundTrip(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		ip   string
		port uint16
		data []byte
	}{
		{"ipv4 DNS", "8.8.8.8", 53, []byte{0x01, 0x02, 0x03}},
		{"ipv4 HTTP", "93.184.216.34", 80, []byte("GET / HTTP/1.1\r\n")},
		{"ipv6 loopback", "::1", 9999, []byte("test")},
		{"empty data", "1.1.1.1", 443, []byte{}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			ip := net.ParseIP(tt.ip)
			buf := marshalSOCKS5UDPDatagram(ip, tt.port, tt.data)

			dgram, err := unmarshalSOCKS5UDPDatagram(buf)
			require.NoError(t, err)

			assert.True(t, ip.Equal(dgram.DstAddr), "IP mismatch: got %s want %s", dgram.DstAddr, ip)
			assert.Equal(t, tt.port, dgram.DstPort)
			assert.Equal(t, tt.data, dgram.Data)
		})
	}
}

func TestUnmarshalSOCKS5UDPDatagram_TooShort(t *testing.T) {
	t.Parallel()

	_, err := unmarshalSOCKS5UDPDatagram([]byte{0, 0, 0})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "too short")
}

func TestUnmarshalSOCKS5UDPDatagram_BadAtyp(t *testing.T) {
	t.Parallel()

	buf := []byte{0, 0, 0, 0xFF, 0, 0, 0, 0, 0, 0}
	_, err := unmarshalSOCKS5UDPDatagram(buf)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported ATYP")
}

func TestUDPProxyRemoveSandbox(t *testing.T) {
	t.Parallel()

	p := &UDPProxy{
		sessions: make(map[string]*udpSession),
	}

	p.RemoveSandbox("sbx-nonexistent")

	assert.Empty(t, p.sessions)
}

func TestUDPProxyClose(t *testing.T) {
	t.Parallel()

	p := &UDPProxy{
		sessions: make(map[string]*udpSession),
	}

	p.Close()
	assert.Empty(t, p.sessions)
}
