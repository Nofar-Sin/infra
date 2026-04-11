package rootfs

import (
	"context"
	"fmt"
	"os"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
	"go.uber.org/zap"

	"github.com/e2b-dev/infra/packages/shared/pkg/logger"
	"github.com/e2b-dev/infra/packages/shared/pkg/storage/header"
)

var tracer = otel.Tracer("github.com/e2b-dev/infra/packages/orchestrator/pkg/sandbox/rootfs")

type Provider interface {
	Start(ctx context.Context) error
	Close(ctx context.Context) error
	Path() (string, error)
	ExportDiff(ctx context.Context, out *os.File, closeSandbox func(context.Context) error) (*header.DiffMetadata, error)
}

// flush flushes dirty pages for the given block device path.
// Uses file.Sync() (fdatasync) which is sufficient for block devices —
// metadata sync (fsync) adds no value for NBD devices without FlagSendFlush.
func flush(ctx context.Context, path string) error {
	ctx, span := tracer.Start(ctx, "flush", trace.WithAttributes(attribute.String("path", path)))
	defer span.End()

	file, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("failed to open path: %w", err)
	}
	defer func() {
		err := file.Close()
		if err != nil {
			logger.L().Error(ctx, "failed to close path", zap.Error(err))
		}
	}()

	if err := file.Sync(); err != nil {
		return fmt.Errorf("failed to sync path: %w", err)
	}

	return nil
}
