package nbd_test

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"github.com/e2b-dev/infra/packages/orchestrator/pkg/sandbox/block"
	"github.com/e2b-dev/infra/packages/orchestrator/pkg/sandbox/nbd"
	"github.com/e2b-dev/infra/packages/orchestrator/pkg/sandbox/nbd/testutils"
	"github.com/e2b-dev/infra/packages/shared/pkg/featureflags"
	"github.com/e2b-dev/infra/packages/shared/pkg/storage/header"
)

var errInjected = errors.New("injected backend error")

// ErrorDevice wraps a ReadonlyDevice and allows injecting errors into
// ReadAt and WriteAt calls. Thread-safe via atomics.
type ErrorDevice struct {
	inner         block.ReadonlyDevice
	failNextRead  atomic.Bool
	failAllReads  atomic.Bool
	failAllWrites atomic.Bool
}

var _ block.Device = (*ErrorDevice)(nil)

func NewErrorDevice(inner block.ReadonlyDevice) *ErrorDevice {
	return &ErrorDevice{inner: inner}
}

func (e *ErrorDevice) ReadAt(ctx context.Context, p []byte, off int64) (int, error) {
	if e.failAllReads.Load() || e.failNextRead.CompareAndSwap(true, false) {
		return 0, errInjected
	}
	return e.inner.ReadAt(ctx, p, off)
}

func (e *ErrorDevice) WriteAt(p []byte, _ int64) (int, error) {
	if e.failAllWrites.Load() {
		return 0, errInjected
	}
	return len(p), nil
}

func (e *ErrorDevice) Size(ctx context.Context) (int64, error) { return e.inner.Size(ctx) }
func (e *ErrorDevice) BlockSize() int64                        { return e.inner.BlockSize() }
func (e *ErrorDevice) Close() error                            { return e.inner.Close() }
func (e *ErrorDevice) Header() *header.Header                  { return e.inner.Header() }

func (e *ErrorDevice) Slice(ctx context.Context, off, length int64) ([]byte, error) {
	return e.inner.Slice(ctx, off, length)
}

// HangingDevice wraps a ReadonlyDevice and blocks all reads until the
// unblock channel is closed or the context is cancelled.
type HangingDevice struct {
	inner   block.ReadonlyDevice
	unblock chan struct{}
}

var _ block.Device = (*HangingDevice)(nil)

func NewHangingDevice(inner block.ReadonlyDevice) *HangingDevice {
	return &HangingDevice{inner: inner, unblock: make(chan struct{})}
}

func (h *HangingDevice) ReadAt(ctx context.Context, p []byte, off int64) (int, error) {
	select {
	case <-h.unblock:
		return h.inner.ReadAt(ctx, p, off)
	case <-ctx.Done():
		return 0, ctx.Err()
	}
}

func (h *HangingDevice) WriteAt(p []byte, _ int64) (int, error) {
	return len(p), nil
}

func (h *HangingDevice) Size(ctx context.Context) (int64, error) { return h.inner.Size(ctx) }
func (h *HangingDevice) BlockSize() int64                        { return h.inner.BlockSize() }
func (h *HangingDevice) Close() error                            { return h.inner.Close() }
func (h *HangingDevice) Header() *header.Header                  { return h.inner.Header() }

func (h *HangingDevice) Slice(ctx context.Context, off, length int64) ([]byte, error) {
	return h.inner.Slice(ctx, off, length)
}

func (h *HangingDevice) Unblock() { close(h.unblock) }

// setupErrorNBDDevice creates an NBD device backed by the given block.Device
// and returns the device file, the mount cleanup function, and the device path.
func setupErrorNBDDevice(
	t *testing.T,
	ctx context.Context,
	device block.Device,
	flags int,
	mountOpts ...nbd.MountOption,
) (*os.File, *testutils.Cleaner, string) {
	t.Helper()

	if os.Geteuid() != 0 {
		t.Skip("nbd requires root privileges")
	}

	featureFlags, err := featureflags.NewClient()
	require.NoError(t, err)

	devicePath, cleanup, err := testutils.GetNBDDevice(ctx, device, featureFlags, mountOpts...)
	require.NoError(t, err)

	deviceFile, err := os.OpenFile(devicePath, flags, 0)
	require.NoError(t, err)
	t.Cleanup(func() { deviceFile.Close() })

	return deviceFile, cleanup, devicePath
}

func newOverlayDevice(t *testing.T, inner block.ReadonlyDevice, size int64) block.Device {
	t.Helper()

	const blockSize = header.RootfsBlockSize

	cowCachePath := filepath.Join(os.TempDir(), fmt.Sprintf("test-eio-%s", uuid.New().String()))
	t.Cleanup(func() { os.RemoveAll(cowCachePath) })

	cache, err := block.NewCache(size, blockSize, cowCachePath, false)
	require.NoError(t, err)

	overlay := block.NewOverlay(inner, cache)
	t.Cleanup(func() { overlay.Close() })

	return overlay
}

// --- Mode 2: Backend read error produces transient EIO ---

func TestBackendReadError_TransientEIO(t *testing.T) {
	t.Parallel()

	const size = int64(10 * 1024 * 1024)

	emptyDevice, err := testutils.NewZeroDevice(size, header.RootfsBlockSize)
	require.NoError(t, err)

	errDev := NewErrorDevice(emptyDevice)
	overlay := newOverlayDevice(t, errDev, size)

	deviceFile, cleanup, _ := setupErrorNBDDevice(t, context.Background(), overlay, os.O_RDONLY)
	t.Cleanup(func() { cleanup.Run(t.Context(), 30*time.Second) })

	buf := make([]byte, 4096)

	// First read with error injected — should return EIO
	errDev.failNextRead.Store(true)
	_, err = deviceFile.ReadAt(buf, 0)
	require.Error(t, err, "expected EIO from injected backend error")
	require.True(t, errors.Is(err, syscall.EIO), "expected EIO, got: %v", err)

	// Second read with error cleared — device should recover
	_, err = deviceFile.ReadAt(buf, 0)
	require.NoError(t, err, "read should succeed after transient error clears")
}

// --- Mode 3: Backend write error produces transient EIO ---

func TestBackendWriteError_TransientEIO(t *testing.T) {
	t.Parallel()

	const size = int64(10 * 1024 * 1024)

	emptyDevice, err := testutils.NewZeroDevice(size, header.RootfsBlockSize)
	require.NoError(t, err)

	// Use ErrorDevice directly (not through overlay) because the overlay's
	// WriteAt goes to the cache, bypassing the error injection.
	errDev := NewErrorDevice(emptyDevice)

	deviceFile, cleanup, _ := setupErrorNBDDevice(t, context.Background(), errDev, os.O_RDWR)
	t.Cleanup(func() { cleanup.Run(t.Context(), 30*time.Second) })

	buf := make([]byte, 4096)

	// Write with error injected
	errDev.failAllWrites.Store(true)
	_, err = deviceFile.WriteAt(buf, 0)
	require.Error(t, err, "expected EIO from injected write error")
	require.True(t, errors.Is(err, syscall.EIO), "expected EIO, got: %v", err)

	// Write with error cleared — device should recover
	errDev.failAllWrites.Store(false)
	_, err = deviceFile.WriteAt(buf, 0)
	require.NoError(t, err, "write should succeed after transient error clears")
}

// --- Mode 5: Dispatch handler exit causes permanent EIO ---

func TestMountClose_WhileReading_PermanentEIO(t *testing.T) {
	t.Parallel()

	const size = int64(10 * 1024 * 1024)

	emptyDevice, err := testutils.NewZeroDevice(size, header.RootfsBlockSize)
	require.NoError(t, err)

	hangDev := NewHangingDevice(emptyDevice)
	overlay := newOverlayDevice(t, hangDev, size)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	deviceFile, cleanup, _ := setupErrorNBDDevice(t, ctx, overlay, os.O_RDONLY,
		nbd.WithIOTimeout(30*time.Second),
		nbd.WithDeadconnTimeout(5*time.Second),
	)

	readDone := make(chan error, 1)
	go func() {
		buf := make([]byte, 4096)
		_, err := deviceFile.ReadAt(buf, 0)
		readDone <- err
	}()

	// Give the read time to reach the dispatch handler
	time.Sleep(200 * time.Millisecond)

	// Kill the mount — this cancels the context, closes sockets, and
	// exits the dispatch handler while the read is still in flight.
	hangDev.Unblock()
	err = cleanup.Run(context.Background(), 30*time.Second)
	// Cleanup errors are expected (disconnect on dead device, etc.)
	t.Logf("cleanup error (expected): %v", err)

	// The in-flight read should fail
	readErr := <-readDone
	require.Error(t, readErr, "in-flight read should fail after mount close")
	t.Logf("in-flight read error: %v", readErr)

	// All subsequent reads should also fail permanently
	buf := make([]byte, 4096)
	_, err = deviceFile.ReadAt(buf, 4096)
	require.Error(t, err, "reads after mount close should fail permanently")
	t.Logf("subsequent read error: %v", err)
}

// --- Mode 4: Context cancellation during slow read ---

func TestContextCancel_DuringRead(t *testing.T) {
	t.Parallel()

	const size = int64(10 * 1024 * 1024)

	emptyDevice, err := testutils.NewZeroDevice(size, header.RootfsBlockSize)
	require.NoError(t, err)

	slowDev := NewSlowDevice(emptyDevice, 10*time.Second)
	overlay := newOverlayDevice(t, slowDev, size)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	deviceFile, cleanup, _ := setupErrorNBDDevice(t, ctx, overlay, os.O_RDONLY,
		nbd.WithIOTimeout(30*time.Second),
		nbd.WithDeadconnTimeout(5*time.Second),
	)
	t.Cleanup(func() { cleanup.Run(context.Background(), 30*time.Second) })

	readDone := make(chan error, 1)
	go func() {
		buf := make([]byte, 4096)
		_, err := deviceFile.ReadAt(buf, 0)
		readDone <- err
	}()

	// Let the read reach the slow backend
	time.Sleep(200 * time.Millisecond)

	// Cancel the context — this should cause the dispatch handler to
	// send an error response and then exit.
	cancel()

	select {
	case readErr := <-readDone:
		require.Error(t, readErr, "read should fail after context cancellation")
		t.Logf("read error after cancel: %v", readErr)
	case <-time.After(40 * time.Second):
		t.Fatal("timed out waiting for read to fail after context cancel")
	}
}

// --- Mode 6: fsync on dead NBD device returns EIO ---

func TestFsyncOnDeadDevice_ReturnsEIO(t *testing.T) {
	t.Parallel()

	const size = int64(10 * 1024 * 1024)

	emptyDevice, err := testutils.NewZeroDevice(size, header.RootfsBlockSize)
	require.NoError(t, err)

	overlay := newOverlayDevice(t, emptyDevice, size)

	deviceFile, cleanup, _ := setupErrorNBDDevice(t, context.Background(), overlay, os.O_RDONLY)

	// Verify reads work before teardown
	buf := make([]byte, 4096)
	_, err = deviceFile.ReadAt(buf, 0)
	require.NoError(t, err, "read should succeed on healthy device")

	// Tear down the mount — kills dispatch handlers, disconnects NBD
	err = cleanup.Run(context.Background(), 30*time.Second)
	t.Logf("cleanup error (expected): %v", err)

	// The device file descriptor is still open but the NBD backend is gone.
	// fsync should fail with EIO.
	err = syscall.Fsync(int(deviceFile.Fd()))
	require.Error(t, err, "fsync on dead NBD device should return an error")
	require.True(t, errors.Is(err, syscall.EIO), "expected EIO from fsync, got: %v", err)
}

// --- Mode 6 negative: fsync on healthy NBD device succeeds ---

func TestFsyncOnHealthyDevice_Succeeds(t *testing.T) {
	t.Parallel()

	const size = int64(10 * 1024 * 1024)

	emptyDevice, err := testutils.NewZeroDevice(size, header.RootfsBlockSize)
	require.NoError(t, err)

	overlay := newOverlayDevice(t, emptyDevice, size)

	deviceFile, cleanup, _ := setupErrorNBDDevice(t, context.Background(), overlay, os.O_RDONLY)
	t.Cleanup(func() { cleanup.Run(t.Context(), 30*time.Second) })

	// Verify reads work
	buf := make([]byte, 4096)
	_, err = deviceFile.ReadAt(buf, 0)
	require.NoError(t, err, "read should succeed on healthy device")

	// fsync on a healthy device should succeed (flush is not advertised,
	// so the kernel handles it as a no-op on the NBD layer).
	err = syscall.Fsync(int(deviceFile.Fd()))
	require.NoError(t, err, "fsync on healthy NBD device should succeed")
}
