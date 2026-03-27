package tcpfirewall

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"

	xproxy "golang.org/x/net/proxy"
)

const (
	socks5Version      = 0x05
	socks5CmdUDPAssoc  = 0x03
	socks5AtypIPv4     = 0x01
	socks5AtypDomain   = 0x03
	socks5AtypIPv6     = 0x04
	socks5AuthNone     = 0x00
	socks5AuthPassword = 0x02
	socks5AuthVersion  = 0x01
)

type socks5UDPSession struct {
	controlConn net.Conn     // must stay open; closing tears down the relay
	relayAddr   *net.UDPAddr
}

func socks5UDPAssociate(proxyAddr string, auth *xproxy.Auth) (*socks5UDPSession, error) {
	conn, err := net.Dial("tcp", proxyAddr)
	if err != nil {
		return nil, fmt.Errorf("dial SOCKS5 proxy: %w", err)
	}

	if err := socks5Handshake(conn, auth); err != nil {
		conn.Close()
		return nil, err
	}

	relayAddr, err := socks5SendUDPAssociate(conn)
	if err != nil {
		conn.Close()
		return nil, err
	}

	return &socks5UDPSession{
		controlConn: conn,
		relayAddr:   relayAddr,
	}, nil
}

func (s *socks5UDPSession) Close() error {
	return s.controlConn.Close()
}

func socks5Handshake(conn net.Conn, auth *xproxy.Auth) error {
	var methods []byte
	if auth != nil {
		methods = []byte{socks5AuthNone, socks5AuthPassword}
	} else {
		methods = []byte{socks5AuthNone}
	}

	// Send: VER | NMETHODS | METHODS
	msg := append([]byte{socks5Version, byte(len(methods))}, methods...)
	if _, err := conn.Write(msg); err != nil {
		return fmt.Errorf("write auth methods: %w", err)
	}

	// Receive: VER | METHOD
	var resp [2]byte
	if _, err := io.ReadFull(conn, resp[:]); err != nil {
		return fmt.Errorf("read auth method response: %w", err)
	}

	if resp[0] != socks5Version {
		return fmt.Errorf("unexpected SOCKS version %d", resp[0])
	}

	switch resp[1] {
	case socks5AuthNone:
		return nil
	case socks5AuthPassword:
		if auth == nil {
			return fmt.Errorf("proxy requires auth but no credentials provided")
		}

		return socks5AuthenticatePassword(conn, auth.User, auth.Password)
	default:
		return fmt.Errorf("unsupported auth method 0x%02x", resp[1])
	}
}

func socks5AuthenticatePassword(conn net.Conn, user, pass string) error {
	// VER(1) | ULEN(1) | UNAME(1-255) | PLEN(1) | PASSWD(1-255)
	msg := make([]byte, 0, 3+len(user)+len(pass))
	msg = append(msg, socks5AuthVersion, byte(len(user)))
	msg = append(msg, []byte(user)...)
	msg = append(msg, byte(len(pass)))
	msg = append(msg, []byte(pass)...)

	if _, err := conn.Write(msg); err != nil {
		return fmt.Errorf("write auth request: %w", err)
	}

	var resp [2]byte
	if _, err := io.ReadFull(conn, resp[:]); err != nil {
		return fmt.Errorf("read auth response: %w", err)
	}

	if resp[1] != 0x00 {
		return fmt.Errorf("SOCKS5 auth failed (status 0x%02x)", resp[1])
	}

	return nil
}

func socks5SendUDPAssociate(conn net.Conn) (*net.UDPAddr, error) {
	// VER | CMD | RSV | ATYP | DST.ADDR | DST.PORT
	// DST.ADDR=0.0.0.0, DST.PORT=0 per RFC 1928 when client doesn't know yet
	req := []byte{
		socks5Version, socks5CmdUDPAssoc, 0x00,
		socks5AtypIPv4, 0, 0, 0, 0, 0, 0,
	}

	if _, err := conn.Write(req); err != nil {
		return nil, fmt.Errorf("write UDP ASSOCIATE: %w", err)
	}

	return socks5ReadReply(conn)
}

func socks5ReadReply(conn net.Conn) (*net.UDPAddr, error) {
	// VER(1) | REP(1) | RSV(1) | ATYP(1)
	var header [4]byte
	if _, err := io.ReadFull(conn, header[:]); err != nil {
		return nil, fmt.Errorf("read reply header: %w", err)
	}

	if header[1] != 0x00 {
		return nil, fmt.Errorf("SOCKS5 command failed (rep=0x%02x)", header[1])
	}

	var ip net.IP

	switch header[3] {
	case socks5AtypIPv4:
		addr := make([]byte, 4)
		if _, err := io.ReadFull(conn, addr); err != nil {
			return nil, fmt.Errorf("read IPv4 bind addr: %w", err)
		}

		ip = net.IP(addr)
	case socks5AtypIPv6:
		addr := make([]byte, 16)
		if _, err := io.ReadFull(conn, addr); err != nil {
			return nil, fmt.Errorf("read IPv6 bind addr: %w", err)
		}

		ip = net.IP(addr)
	case socks5AtypDomain:
		var domainLen [1]byte
		if _, err := io.ReadFull(conn, domainLen[:]); err != nil {
			return nil, fmt.Errorf("read domain length: %w", err)
		}

		domain := make([]byte, domainLen[0])
		if _, err := io.ReadFull(conn, domain); err != nil {
			return nil, fmt.Errorf("read domain: %w", err)
		}

		ips, err := net.LookupHost(string(domain))
		if err != nil || len(ips) == 0 {
			return nil, fmt.Errorf("resolve relay domain %q: %w", string(domain), err)
		}

		ip = net.ParseIP(ips[0])
	default:
		return nil, fmt.Errorf("unsupported ATYP 0x%02x", header[3])
	}

	var portBuf [2]byte
	if _, err := io.ReadFull(conn, portBuf[:]); err != nil {
		return nil, fmt.Errorf("read bind port: %w", err)
	}

	port := binary.BigEndian.Uint16(portBuf[:])

	return &net.UDPAddr{IP: ip, Port: int(port)}, nil
}

type socks5UDPDatagram struct {
	DstAddr net.IP
	DstPort uint16
	Data    []byte
}

// marshalSOCKS5UDPDatagram: RSV(2) | FRAG(1) | ATYP(1) | DST.ADDR(4|16) | DST.PORT(2) | DATA
func marshalSOCKS5UDPDatagram(dst net.IP, dstPort uint16, data []byte) []byte {
	ip4 := dst.To4()
	isV4 := ip4 != nil

	var atyp byte
	var addr []byte

	if isV4 {
		atyp = socks5AtypIPv4
		addr = ip4
	} else {
		atyp = socks5AtypIPv6
		addr = dst.To16()
	}

	buf := make([]byte, 0, 4+len(addr)+2+len(data))
	buf = append(buf, 0x00, 0x00, 0x00, atyp)
	buf = append(buf, addr...)
	buf = append(buf, byte(dstPort>>8), byte(dstPort))
	buf = append(buf, data...)

	return buf
}

func unmarshalSOCKS5UDPDatagram(buf []byte) (*socks5UDPDatagram, error) {
	if len(buf) < 10 {
		return nil, fmt.Errorf("UDP datagram too short (%d bytes)", len(buf))
	}

	atyp := buf[3]
	offset := 4

	var ip net.IP

	switch atyp {
	case socks5AtypIPv4:
		if len(buf) < offset+4+2 {
			return nil, fmt.Errorf("datagram too short for IPv4")
		}

		ip = net.IP(buf[offset : offset+4])
		offset += 4
	case socks5AtypIPv6:
		if len(buf) < offset+16+2 {
			return nil, fmt.Errorf("datagram too short for IPv6")
		}

		ip = net.IP(buf[offset : offset+16])
		offset += 16
	default:
		return nil, fmt.Errorf("unsupported ATYP 0x%02x in UDP datagram", atyp)
	}

	port := binary.BigEndian.Uint16(buf[offset : offset+2])
	offset += 2

	return &socks5UDPDatagram{
		DstAddr: ip,
		DstPort: port,
		Data:    buf[offset:],
	}, nil
}
