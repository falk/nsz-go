package zstd

import (
	"sync"

	"github.com/klauspost/compress/zstd"
)

var (
	decoder, _ = zstd.NewReader(nil)

	// Encoder pools by compression level
	encoderPools = make(map[int]*sync.Pool)
	poolMu       sync.RWMutex
)

func getEncoderPool(level int) *sync.Pool {
	poolMu.RLock()
	pool, ok := encoderPools[level]
	poolMu.RUnlock()
	if ok {
		return pool
	}

	poolMu.Lock()
	defer poolMu.Unlock()

	if pool, ok = encoderPools[level]; ok {
		return pool
	}

	pool = &sync.Pool{
		New: func() interface{} {
			enc, _ := zstd.NewWriter(nil,
				zstd.WithEncoderLevel(zstd.EncoderLevelFromZstd(level)),
				zstd.WithEncoderConcurrency(1),
			)
			return enc
		},
	}
	encoderPools[level] = pool
	return pool
}

// Compress compresses data using Zstd with encoder pooling.
func Compress(src []byte, level int) []byte {
	pool := getEncoderPool(level)
	enc := pool.Get().(*zstd.Encoder)
	defer pool.Put(enc)

	return enc.EncodeAll(src, make([]byte, 0, len(src)))
}

// Decompress decompresses Zstd data.
func Decompress(src []byte) ([]byte, error) {
	return decoder.DecodeAll(src, nil)
}
