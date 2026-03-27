package tcpfirewall

import (
	"context"
	"fmt"
	"net"
	"sync"
	"syscall"
	"time"

	"go.uber.org/zap"
	xproxy "golang.org/x/net/proxy"
	"golang.org/x/sys/unix"

	"github.com/e2b-dev/infra/packages/orchestrator/internal/sandbox"
	"github.com/e2b-dev/infra/packages/shared/pkg/featureflags"
	"github.com/e2b-dev/infra/packages/shared/pkg/logger"
)

const (
	udpReadBufSize    = 65535
	udpSessionTimeout = 60 * time.Second
)

type udpSession struct {
	socks    *socks5UDPSession
	relay    *net.UDPConn
	listener *net.UDPConn
	srcAddr  *net.UDPAddr
	lastUse  time.Time
	cancel   context.CancelFunc
}

func (s *udpSession) close() {
	s.cancel()

	if s.relay != nil {
		s.relay.Close()
	}

	if s.socks != nil {
		s.socks.Close()
	}
}

// UDPProxy transparently proxies sandbox UDP traffic through a SOCKS5 upstream.
type UDPProxy struct {
	logger       logger.Logger
	sandboxes    *sandbox.Map
	featureFlags *featureflags.Client
	port         uint16

	mu       sync.Mutex
	sessions map[string]*udpSession
}

func NewUDPProxy(logger logger.Logger, sandboxes *sandbox.Map, featureFlags *featureflags.Client, port uint16) *UDPProxy {
	return &UDPProxy{
		logger:       logger,
		sandboxes:    sandboxes,
		featureFlags: featureFlags,
		port:         port,
		sessions:     make(map[string]*udpSession),
	}
}

func (p *UDPProxy) RemoveSandbox(sandboxID string) {
	p.mu.Lock()
	sess, ok := p.sessions[sandboxID]
	if ok {
		delete(p.sessions, sandboxID)
	}
	p.mu.Unlock()

	if ok {
		sess.close()
	}
}

func (p *UDPProxy) Close() {
	p.mu.Lock()
	sessions := p.sessions
	p.sessions = make(map[string]*udpSession)
	p.mu.Unlock()

	for _, sess := range sessions {
		sess.close()
	}
}

func (p *UDPProxy) Start(ctx context.Context) error {
	addr := fmt.Sprintf("0.0.0.0:%d", p.port)

	lc := net.ListenConfig{
		Control: func(_, _ string, c syscall.RawConn) error {
			var opErr error
			if err := c.Control(func(fd uintptr) {
				opErr = unix.SetsockoptInt(int(fd), unix.SOL_IP, unix.IP_RECVORIGDSTADDR, 1)
			}); err != nil {
				return err
			}

			return opErr
		},
	}

	pc, err := lc.ListenPacket(ctx, "udp4", addr)
	if err != nil {
		return fmt.Errorf("listen UDP: %w", err)
	}

	p.logger.Info(ctx, "UDP egress proxy started", zap.Uint16("port", p.port))

	go p.idleReaper(ctx)

	go func() {
		<-ctx.Done()
		pc.Close()
	}()

	go p.readLoop(ctx, pc.(*net.UDPConn))

	return nil
}

func (p *UDPProxy) readLoop(ctx context.Context, conn *net.UDPConn) {
	buf := make([]byte, udpReadBufSize)
	oob := make([]byte, 64)

	for {
		n, oobn, _, srcAddr, err := conn.ReadMsgUDP(buf, oob)
		if err != nil {
			if ctx.Err() != nil {
				return
			}

			p.logger.Error(ctx, "UDP read error", zap.Error(err))

			continue
		}

		origDst, parseErr := parseOrigDst(oob[:oobn])
		if parseErr != nil {
			p.logger.Error(ctx, "failed to parse original destination", zap.Error(parseErr))

			continue
		}

		data := make([]byte, n)
		copy(data, buf[:n])

		go p.handlePacket(ctx, conn, srcAddr, origDst, data)
	}
}

func (p *UDPProxy) handlePacket(ctx context.Context, listener *net.UDPConn, src *net.UDPAddr, origDst *net.UDPAddr, data []byte) {
	sbx, err := p.sandboxes.GetByHostPort(src.String())
	if err != nil {
		p.logger.Error(ctx, "UDP: sandbox not found for source", zap.String("src", src.String()), zap.Error(err))

		return
	}

	sandboxID := sbx.Runtime.SandboxID

	proxyAddr := p.featureFlags.StringFlag(ctx, featureflags.SandboxEgressProxy,
		featureflags.TeamContext(sbx.Runtime.TeamID))
	if proxyAddr == "" {
		return
	}

	sess, err := p.getOrCreateSession(ctx, sandboxID, proxyAddr, sbx.Runtime, listener)
	if err != nil {
		p.logger.Error(ctx, "UDP: failed to create SOCKS5 session",
			zap.String("sandbox_id", sandboxID),
			zap.Error(err))

		return
	}

	dgram := marshalSOCKS5UDPDatagram(origDst.IP, uint16(origDst.Port), data)
	if _, err := sess.relay.WriteToUDP(dgram, sess.socks.relayAddr); err != nil {
		p.logger.Error(ctx, "UDP: relay write failed",
			zap.String("sandbox_id", sandboxID),
			zap.Error(err))

		return
	}

	p.mu.Lock()
	sess.srcAddr = src
	sess.lastUse = time.Now()
	p.mu.Unlock()
}

func (p *UDPProxy) getOrCreateSession(ctx context.Context, sandboxID, proxyAddr string, rt sandbox.RuntimeMetadata, listener *net.UDPConn) (*udpSession, error) {
	p.mu.Lock()
	if sess, ok := p.sessions[sandboxID]; ok {
		p.mu.Unlock()

		return sess, nil
	}
	p.mu.Unlock()

	auth := socks5AuthFromRuntime(rt)
	sess, err := p.createSession(ctx, sandboxID, proxyAddr, auth, listener)
	if err != nil {
		return nil, err
	}

	p.mu.Lock()
	if existing, ok := p.sessions[sandboxID]; ok {
		p.mu.Unlock()
		sess.close()

		return existing, nil
	}

	p.sessions[sandboxID] = sess
	p.mu.Unlock()

	return sess, nil
}

func (p *UDPProxy) createSession(ctx context.Context, sandboxID, proxyAddr string, auth *xproxy.Auth, listener *net.UDPConn) (*udpSession, error) {
	socks, err := socks5UDPAssociate(proxyAddr, auth)
	if err != nil {
		return nil, fmt.Errorf("SOCKS5 UDP ASSOCIATE: %w", err)
	}

	relay, err := net.DialUDP("udp", nil, nil)
	if err != nil {
		socks.Close()

		return nil, fmt.Errorf("create UDP relay socket: %w", err)
	}

	sessCtx, cancel := context.WithCancel(ctx)
	sess := &udpSession{
		socks:    socks,
		relay:    relay,
		listener: listener,
		lastUse:  time.Now(),
		cancel:   cancel,
	}

	go p.relayResponses(sessCtx, sandboxID, sess)

	// Tear down session when the SOCKS5 TCP control connection drops.
	go func() {
		buf := make([]byte, 1)
		_, _ = socks.controlConn.Read(buf)

		p.mu.Lock()
		if current, ok := p.sessions[sandboxID]; ok && current == sess {
			delete(p.sessions, sandboxID)
		}
		p.mu.Unlock()

		sess.close()
	}()

	return sess, nil
}

func (p *UDPProxy) relayResponses(ctx context.Context, sandboxID string, sess *udpSession) {
	buf := make([]byte, udpReadBufSize)

	for {
		sess.relay.SetReadDeadline(time.Now().Add(udpSessionTimeout))

		n, _, err := sess.relay.ReadFromUDP(buf)
		if err != nil {
			if ctx.Err() != nil {
				return
			}

			continue
		}

		dgram, err := unmarshalSOCKS5UDPDatagram(buf[:n])
		if err != nil {
			p.logger.Error(ctx, "UDP: failed to unmarshal relay response",
				zap.String("sandbox_id", sandboxID),
				zap.Error(err))

			continue
		}

		p.mu.Lock()
		dst := sess.srcAddr
		sess.lastUse = time.Now()
		p.mu.Unlock()

		if dst != nil {
			if _, writeErr := sess.listener.WriteToUDP(dgram.Data, dst); writeErr != nil {
				p.logger.Error(ctx, "UDP: failed to write response back to sandbox",
					zap.String("sandbox_id", sandboxID),
					zap.Error(writeErr))
			}
		}
	}
}

func (p *UDPProxy) idleReaper(ctx context.Context) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			p.reapIdle()
		}
	}
}

func (p *UDPProxy) reapIdle() {
	now := time.Now()

	p.mu.Lock()
	var expired []*udpSession
	for id, sess := range p.sessions {
		if now.Sub(sess.lastUse) > udpSessionTimeout {
			expired = append(expired, sess)
			delete(p.sessions, id)
		}
	}
	p.mu.Unlock()

	for _, sess := range expired {
		sess.close()
	}
}

// parseOrigDst extracts the original destination address from the
// IP_RECVORIGDSTADDR ancillary data returned by recvmsg.
func parseOrigDst(oob []byte) (*net.UDPAddr, error) {
	msgs, err := unix.ParseSocketControlMessage(oob)
	if err != nil {
		return nil, fmt.Errorf("parse control message: %w", err)
	}

	for _, msg := range msgs {
		if msg.Header.Level == unix.SOL_IP && msg.Header.Type == unix.IP_ORIGDSTADDR {
			if len(msg.Data) < 8 {
				continue
			}
			// struct sockaddr_in: family(2) + port(2 big-endian) + addr(4)
			port := int(msg.Data[2])<<8 | int(msg.Data[3])
			ip := net.IPv4(msg.Data[4], msg.Data[5], msg.Data[6], msg.Data[7])

			return &net.UDPAddr{IP: ip, Port: port}, nil
		}
	}

	return nil, fmt.Errorf("IP_ORIGDSTADDR not found in ancillary data")
}
