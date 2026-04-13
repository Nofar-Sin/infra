package storage

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"os"
	"testing"
	"time"

	gcsstorage "cloud.google.com/go/storage"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/api/iterator"
)

const (
	rangeFetch2MB = 2 * 1024 * 1024
	rangeFetch4MB = 4 * 1024 * 1024

	envBucketName    = "ANYWHERE_CACHE_TEST_BUCKET"
	envBucketPrefix  = "ANYWHERE_CACHE_TEST_PREFIX"
	envMinObjectSize = "ANYWHERE_CACHE_TEST_MIN_SIZE"
)

func skipUnlessAnywhereCacheTest(t *testing.T) string {
	t.Helper()

	bucket := os.Getenv(envBucketName)
	if bucket == "" {
		t.Skipf("skipping: set %s to run Anywhere Cache tests (e.g. ANYWHERE_CACHE_TEST_BUCKET=e2b-staging-template-bucket)", envBucketName)
	}

	return bucket
}

// findTestObject discovers a single object in the bucket that is large enough
// for the requested range read. It respects the optional ANYWHERE_CACHE_TEST_PREFIX
// env var to narrow the listing.
func findTestObject(ctx context.Context, client *gcsstorage.Client, bucket string, minSize int64) (string, int64, error) {
	prefix := os.Getenv(envBucketPrefix)

	var q *gcsstorage.Query
	if prefix != "" {
		q = &gcsstorage.Query{Prefix: prefix}
	}

	it := client.Bucket(bucket).Objects(ctx, q)
	for {
		attrs, err := it.Next()
		if errors.Is(err, iterator.Done) {
			break
		}
		if err != nil {
			return "", 0, fmt.Errorf("listing objects: %w", err)
		}

		if attrs.Size >= minSize {
			return attrs.Name, attrs.Size, nil
		}
	}

	return "", 0, fmt.Errorf("no object >= %d bytes found in gs://%s (prefix=%q)", minSize, bucket, prefix)
}

// TestAnywhereCacheRangeFetch validates that GCS range reads (via the storage
// lib) return correct, complete data at 2MB and 4MB chunk sizes. When run
// against a bucket with GCP Anywhere Cache enabled the latency numbers printed
// by the test show whether the cache is being hit.
//
// Usage:
//
//	ANYWHERE_CACHE_TEST_BUCKET=<staging-bucket> go test -v -run TestAnywhereCacheRangeFetch -count=1 ./packages/shared/pkg/storage/
//
// Optional env vars:
//
//	ANYWHERE_CACHE_TEST_PREFIX  – restrict object listing to a prefix
func TestAnywhereCacheRangeFetch(t *testing.T) {
	bucket := skipUnlessAnywhereCacheTest(t)
	ctx := t.Context()

	provider, err := NewGCP(ctx, bucket, nil)
	require.NoError(t, err, "failed to create GCP storage provider")

	t.Logf("storage: %s", provider.GetDetails())

	for _, chunkSize := range []struct {
		name string
		size int64
	}{
		{"2MB", rangeFetch2MB},
		{"4MB", rangeFetch4MB},
	} {
		t.Run(chunkSize.name, func(t *testing.T) {
			gcpRaw, err := gcsstorage.NewClient(ctx)
			require.NoError(t, err)
			defer gcpRaw.Close()

			objectPath, objectSize, err := findTestObject(ctx, gcpRaw, bucket, chunkSize.size*2)
			require.NoError(t, err, "need an object >= %d bytes in bucket", chunkSize.size*2)

			t.Logf("object: gs://%s/%s (%d bytes)", bucket, objectPath, objectSize)

			seekable, err := provider.OpenSeekable(ctx, objectPath, UnknownSeekableObjectType)
			require.NoError(t, err)

			t.Run("ReadAt", func(t *testing.T) {
				testReadAtConsistency(t, ctx, seekable, chunkSize.size, objectSize)
			})

			t.Run("OpenRangeReader", func(t *testing.T) {
				testOpenRangeReaderConsistency(t, ctx, seekable, chunkSize.size, objectSize)
			})
		})
	}
}

// testReadAtConsistency performs two ReadAt calls at the same offset and verifies
// the returned data matches byte-for-byte. It also reports timing so the caller
// can observe Anywhere Cache hit vs miss latency.
func testReadAtConsistency(t *testing.T, ctx context.Context, seekable Seekable, chunkSize, objectSize int64) {
	t.Helper()

	offset := alignedMiddleOffset(objectSize, chunkSize)
	buf1 := make([]byte, chunkSize)
	buf2 := make([]byte, chunkSize)

	start1 := time.Now()
	n1, err := seekable.ReadAt(ctx, buf1, offset)
	elapsed1 := time.Since(start1)
	require.NoError(t, ignoreEOF(err))
	require.Positive(t, n1, "ReadAt returned 0 bytes")
	t.Logf("ReadAt #1: offset=%d read=%d bytes in %s", offset, n1, elapsed1.Round(time.Millisecond))

	start2 := time.Now()
	n2, err := seekable.ReadAt(ctx, buf2, offset)
	elapsed2 := time.Since(start2)
	require.NoError(t, ignoreEOF(err))
	t.Logf("ReadAt #2: offset=%d read=%d bytes in %s", offset, n2, elapsed2.Round(time.Millisecond))

	assert.Equal(t, n1, n2, "byte counts must match across reads")
	assert.Equal(t, sha256.Sum256(buf1[:n1]), sha256.Sum256(buf2[:n2]), "data must be identical across reads")

	if elapsed2 < elapsed1 {
		t.Logf("second read was %s faster (%.0f%% speedup) — possible cache hit",
			(elapsed1 - elapsed2).Round(time.Millisecond),
			float64(elapsed1-elapsed2)/float64(elapsed1)*100)
	}
}

// testOpenRangeReaderConsistency performs two streaming range reads at the same
// offset and verifies data integrity.
func testOpenRangeReaderConsistency(t *testing.T, ctx context.Context, seekable Seekable, chunkSize, objectSize int64) {
	t.Helper()

	offset := alignedMiddleOffset(objectSize, chunkSize)

	read := func(label string) ([]byte, time.Duration) {
		start := time.Now()
		rc, err := seekable.OpenRangeReader(ctx, offset, chunkSize)
		require.NoError(t, err, "%s: OpenRangeReader failed", label)

		data, err := io.ReadAll(rc)
		elapsed := time.Since(start)
		require.NoError(t, rc.Close())
		require.NoError(t, err, "%s: ReadAll failed", label)
		require.NotEmpty(t, data, "%s: got 0 bytes", label)
		t.Logf("%s: offset=%d read=%d bytes in %s", label, offset, len(data), elapsed.Round(time.Millisecond))

		return data, elapsed
	}

	data1, elapsed1 := read("RangeReader #1")
	data2, elapsed2 := read("RangeReader #2")

	assert.Equal(t, len(data1), len(data2), "byte counts must match")
	assert.Equal(t, sha256.Sum256(data1), sha256.Sum256(data2), "data must be identical across reads")

	if elapsed2 < elapsed1 {
		t.Logf("second read was %s faster (%.0f%% speedup) — possible cache hit",
			(elapsed1 - elapsed2).Round(time.Millisecond),
			float64(elapsed1-elapsed2)/float64(elapsed1)*100)
	}
}

// TestAnywhereCacheRangeFetch_MultiOffset reads multiple non-overlapping ranges
// from the same object and cross-validates against a full ReadAt to detect any
// data corruption introduced by the caching layer.
func TestAnywhereCacheRangeFetch_MultiOffset(t *testing.T) {
	bucket := skipUnlessAnywhereCacheTest(t)
	ctx := t.Context()

	provider, err := NewGCP(ctx, bucket, nil)
	require.NoError(t, err)

	gcpRaw, err := gcsstorage.NewClient(ctx)
	require.NoError(t, err)
	defer gcpRaw.Close()

	// We need an object at least 4 * 4MB = 16MB to have 4 non-overlapping 4MB ranges.
	const numRanges = 4
	minSize := int64(numRanges * rangeFetch4MB)

	objectPath, objectSize, err := findTestObject(ctx, gcpRaw, bucket, minSize)
	require.NoError(t, err, "need an object >= %d bytes", minSize)
	t.Logf("object: gs://%s/%s (%d bytes)", bucket, objectPath, objectSize)

	seekable, err := provider.OpenSeekable(ctx, objectPath, UnknownSeekableObjectType)
	require.NoError(t, err)

	for _, chunkSize := range []int64{rangeFetch2MB, rangeFetch4MB} {
		label := fmt.Sprintf("%dMB", chunkSize/(1024*1024))
		t.Run(label, func(t *testing.T) {
			for i := range numRanges {
				offset := int64(i) * chunkSize
				if offset+chunkSize > objectSize {
					break
				}

				t.Run(fmt.Sprintf("offset_%d", offset), func(t *testing.T) {
					// Read via OpenRangeReader (streaming)
					rc, err := seekable.OpenRangeReader(ctx, offset, chunkSize)
					require.NoError(t, err)

					rangeData, err := io.ReadAll(rc)
					require.NoError(t, rc.Close())
					require.NoError(t, err)
					require.Len(t, rangeData, int(chunkSize), "OpenRangeReader returned unexpected length")

					// Read via ReadAt (random access)
					readAtBuf := make([]byte, chunkSize)
					n, err := seekable.ReadAt(ctx, readAtBuf, offset)
					require.NoError(t, ignoreEOF(err))
					require.Equal(t, int(chunkSize), n, "ReadAt returned unexpected length")

					assert.Equal(t,
						sha256.Sum256(rangeData),
						sha256.Sum256(readAtBuf[:n]),
						"OpenRangeReader and ReadAt must return identical data at offset %d", offset,
					)
				})
			}
		})
	}
}

func alignedMiddleOffset(objectSize, chunkSize int64) int64 {
	mid := objectSize / 2
	return (mid / chunkSize) * chunkSize
}
