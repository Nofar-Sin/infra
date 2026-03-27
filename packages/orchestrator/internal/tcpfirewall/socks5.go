package tcpfirewall

import (
	"context"
	"fmt"
	"net"
	"strings"

	xproxy "golang.org/x/net/proxy"

	"github.com/e2b-dev/infra/packages/orchestrator/internal/sandbox"
)

type DialContextFunc func(ctx context.Context, network, addr string) (net.Conn, error)

const sandboxIDPlaceholder = "{{sandboxID}}"

// socks5AuthFromRuntime derives SOCKS5 credentials from sandbox runtime metadata.
//
// Precedence:
//  1. EgressProxyUser set → customer-provided credentials. The username may
//     contain the placeholder {{sandboxID}} which is replaced with the actual
//     sandbox ID (useful for residential IP providers that encode session info
//     in the username, e.g. "customer-user-session_{{sandboxID}}").
//  2. EgressProxyToken set → E2B identity: sandboxID as user, token as password.
//  3. Neither → nil (no auth).
func socks5AuthFromRuntime(rt sandbox.RuntimeMetadata) *xproxy.Auth {
	switch {
	case rt.EgressProxyUser != "":
		user := strings.ReplaceAll(rt.EgressProxyUser, sandboxIDPlaceholder, rt.SandboxID)

		return &xproxy.Auth{
			User:     user,
			Password: rt.EgressProxyPassword,
		}
	case rt.EgressProxyToken != "":
		return &xproxy.Auth{
			User:     rt.SandboxID,
			Password: rt.EgressProxyToken,
		}
	default:
		return nil
	}
}

// newSOCKS5DialContext creates a SOCKS5 dialer for the given proxy address and
// optional auth. Creation is cheap (no I/O, just struct init), so we create a
// fresh dialer per connection to support per-sandbox auth credentials without
// needing a cache.
func newSOCKS5DialContext(proxyAddr string, auth *xproxy.Auth) (DialContextFunc, error) {
	dialer, err := xproxy.SOCKS5("tcp", proxyAddr, auth, xproxy.Direct)
	if err != nil {
		return nil, fmt.Errorf("failed to create SOCKS5 dialer for %q: %w", proxyAddr, err)
	}

	ctxDialer, ok := dialer.(xproxy.ContextDialer)
	if !ok {
		return nil, fmt.Errorf("SOCKS5 dialer does not support DialContext")
	}

	return ctxDialer.DialContext, nil
}

type socks5CtxKey struct{}

func withSOCKS5DialContext(ctx context.Context, fn DialContextFunc) context.Context {
	return context.WithValue(ctx, socks5CtxKey{}, fn)
}

func socks5DialContextFromCtx(ctx context.Context) DialContextFunc {
	fn, _ := ctx.Value(socks5CtxKey{}).(DialContextFunc)

	return fn
}
