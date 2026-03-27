package tcpfirewall

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	xproxy "golang.org/x/net/proxy"

	"github.com/e2b-dev/infra/packages/orchestrator/internal/sandbox"
)

func TestNewSOCKS5DialContext_WithoutAuth(t *testing.T) {
	t.Parallel()

	fn, err := newSOCKS5DialContext("127.0.0.1:1080", nil)
	require.NoError(t, err)
	assert.NotNil(t, fn, "dialer function should be non-nil")
}

func TestNewSOCKS5DialContext_WithAuth(t *testing.T) {
	t.Parallel()

	auth := &xproxy.Auth{
		User:     "sandbox-123",
		Password: "token-456",
	}

	fn, err := newSOCKS5DialContext("127.0.0.1:1080", auth)
	require.NoError(t, err)
	assert.NotNil(t, fn, "dialer function should be non-nil")
}

func TestSOCKS5DialContextRoundTrip(t *testing.T) {
	t.Parallel()

	ctx := context.Background()

	assert.Nil(t, socks5DialContextFromCtx(ctx), "empty context should return nil")

	fn, err := newSOCKS5DialContext("127.0.0.1:1080", nil)
	require.NoError(t, err)

	ctx = withSOCKS5DialContext(ctx, fn)

	got := socks5DialContextFromCtx(ctx)
	assert.NotNil(t, got, "context with dialer should return non-nil")
}

func TestSOCKS5DialContextFromCtx_EmptyContext(t *testing.T) {
	t.Parallel()

	fn := socks5DialContextFromCtx(context.Background())
	assert.Nil(t, fn)
}

func TestSOCKS5DialContextFromCtx_WrongType(t *testing.T) {
	t.Parallel()

	ctx := context.WithValue(context.Background(), socks5CtxKey{}, "not a function")
	fn := socks5DialContextFromCtx(ctx)
	assert.Nil(t, fn, "wrong type should return nil via type assertion")
}

func TestSocks5AuthFromRuntime(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name         string
		runtime      sandbox.RuntimeMetadata
		wantNil      bool
		wantUser     string
		wantPassword string
	}{
		{
			name:    "no auth when all fields empty",
			runtime: sandbox.RuntimeMetadata{SandboxID: "sbx-1"},
			wantNil: true,
		},
		{
			name: "token mode: sandboxID as user, token as password",
			runtime: sandbox.RuntimeMetadata{
				SandboxID:        "sbx-1",
				EgressProxyToken: "tok-secret",
			},
			wantUser:     "sbx-1",
			wantPassword: "tok-secret",
		},
		{
			name: "customer credentials override token",
			runtime: sandbox.RuntimeMetadata{
				SandboxID:           "sbx-1",
				EgressProxyToken:    "tok-secret",
				EgressProxyUser:     "customer-user",
				EgressProxyPassword: "customer-pass",
			},
			wantUser:     "customer-user",
			wantPassword: "customer-pass",
		},
		{
			name: "customer credentials without token",
			runtime: sandbox.RuntimeMetadata{
				SandboxID:           "sbx-1",
				EgressProxyUser:     "bright-data-user",
				EgressProxyPassword: "bright-data-pass",
			},
			wantUser:     "bright-data-user",
			wantPassword: "bright-data-pass",
		},
		{
			name: "customer user with empty password is valid",
			runtime: sandbox.RuntimeMetadata{
				SandboxID:       "sbx-1",
				EgressProxyUser: "user-only",
			},
			wantUser:     "user-only",
			wantPassword: "",
		},
		{
			name: "sandboxID placeholder in username",
			runtime: sandbox.RuntimeMetadata{
				SandboxID:           "sbx-42",
				EgressProxyUser:     "cust-session_{{sandboxID}}",
				EgressProxyPassword: "proxy-pass",
			},
			wantUser:     "cust-session_sbx-42",
			wantPassword: "proxy-pass",
		},
		{
			name: "multiple sandboxID placeholders replaced",
			runtime: sandbox.RuntimeMetadata{
				SandboxID:           "sbx-99",
				EgressProxyUser:     "{{sandboxID}}-user-{{sandboxID}}",
				EgressProxyPassword: "pass",
			},
			wantUser:     "sbx-99-user-sbx-99",
			wantPassword: "pass",
		},
		{
			name: "no placeholder — username passed as-is",
			runtime: sandbox.RuntimeMetadata{
				SandboxID:           "sbx-1",
				EgressProxyUser:     "static-user",
				EgressProxyPassword: "static-pass",
			},
			wantUser:     "static-user",
			wantPassword: "static-pass",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			auth := socks5AuthFromRuntime(tt.runtime)

			if tt.wantNil {
				assert.Nil(t, auth)

				return
			}

			require.NotNil(t, auth)
			assert.Equal(t, tt.wantUser, auth.User)
			assert.Equal(t, tt.wantPassword, auth.Password)
		})
	}
}
