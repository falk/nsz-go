package fs

import (
	"encoding/binary"
	"fmt"
	"io"
	"runtime"
	"sync"

	"github.com/falk/nsz-go/pkg/crypto"
	"github.com/falk/nsz-go/pkg/nsz"
	github_zstd "github.com/falk/nsz-go/pkg/zstd"
)

const (
	DefaultBlockSizeEx      = 20 // 1MB blocks (2^20)
	DefaultCompressionLevel = 18 // Matches Python default
)

// CompressNca compresses a single NCA stream to NCZ format.
func CompressNca(r io.ReaderAt, w io.Writer, totalSize int64, titleKey []byte, compressionLevel int) (int64, error) {
	nca, err := NewNCA(r)
	if err != nil {
		return 0, err
	}

	if titleKey != nil {
		nca.Header.TitleKey = titleKey
	}

	ws, ok := w.(io.WriteSeeker)
	if !ok {
		return 0, fmt.Errorf("writer must support seeking")
	}

	startPos, _ := ws.Seek(0, io.SeekCurrent)

	// 1. Copy uncompressable header
	headerBuf := make([]byte, NcaFullHeaderSize)
	if _, err := r.ReadAt(headerBuf, 0); err != nil {
		return 0, err
	}
	if _, err := ws.Write(headerBuf); err != nil {
		return 0, err
	}

	// 2. Write section header
	sections, err := nca.GetEncryptionSections()
	if err != nil {
		return 0, err
	}
	if err := nsz.WriteNczHeader(ws, sections); err != nil {
		return 0, err
	}

	// 3. Write block header
	blockSize := int64(1) << DefaultBlockSizeEx
	dataSize := totalSize - NcaFullHeaderSize
	blockCount := uint32((dataSize + blockSize - 1) / blockSize)

	blockHeader := nsz.NczBlockHeader{
		Version:          2,
		Type:             1,
		BlockSizeExp:     DefaultBlockSizeEx,
		BlockCount:       blockCount,
		DecompressedSize: uint64(dataSize),
	}
	copy(blockHeader.Magic[:], nsz.MagicNCZBLOCK)

	if err := binary.Write(ws, binary.LittleEndian, blockHeader); err != nil {
		return 0, err
	}

	// Reserve space for compressed size table
	sizeListOffset, _ := ws.Seek(0, io.SeekCurrent)
	if _, err := ws.Write(make([]byte, blockCount*4)); err != nil {
		return 0, err
	}

	// 4. Parallel compression
	compressedBlocks, err := compressBlocks(r, totalSize, blockSize, blockCount, sections, compressionLevel)
	if err != nil {
		return 0, err
	}

	// 5. Write compressed blocks and collect sizes
	compressedSizes := make([]uint32, blockCount)
	for i := uint32(0); i < blockCount; i++ {
		if _, err := ws.Write(compressedBlocks[i]); err != nil {
			return 0, fmt.Errorf("write block %d: %w", i, err)
		}
		compressedSizes[i] = uint32(len(compressedBlocks[i]))
	}

	// 6. Write size table
	endPos, err := ws.Seek(0, io.SeekCurrent)
	if err != nil {
		return 0, err
	}
	if _, err := ws.Seek(sizeListOffset, io.SeekStart); err != nil {
		return 0, err
	}
	if err := binary.Write(ws, binary.LittleEndian, compressedSizes); err != nil {
		return 0, err
	}
	if _, err := ws.Seek(endPos, io.SeekStart); err != nil {
		return 0, err
	}

	return endPos - startPos, nil
}

// compressBlocks handles parallel reading, decryption, and compression.
func compressBlocks(r io.ReaderAt, totalSize, blockSize int64, blockCount uint32, sections []nsz.NczSectionEntry, compressionLevel int) ([][]byte, error) {
	numWorkers := runtime.NumCPU()
	results := make([][]byte, blockCount)

	// Work represents a block to process
	type work struct {
		index  uint32
		offset int64
		size   int64
	}

	workCh := make(chan work, numWorkers*4)
	resultCh := make(chan struct {
		index uint32
		data  []byte
	}, numWorkers*4)

	// Result collector
	var collectWg sync.WaitGroup
	collectWg.Add(1)
	go func() {
		defer collectWg.Done()
		for r := range resultCh {
			results[r.index] = r.data
		}
	}()

	// Workers: read, decrypt, compress
	var workerWg sync.WaitGroup
	var workerErr error
	var errOnce sync.Once

	for i := 0; i < numWorkers; i++ {
		workerWg.Add(1)
		go func() {
			defer workerWg.Done()
			buf := make([]byte, blockSize)

			for w := range workCh {
				// Read
				chunk := buf[:w.size]
				n, err := r.ReadAt(chunk, w.offset)
				if err != nil && n == 0 {
					errOnce.Do(func() { workerErr = fmt.Errorf("read block %d: %w", w.index, err) })
					continue
				}
				chunk = chunk[:n]

				// Decrypt sections that intersect this block
				decryptChunk(chunk, w.offset, sections)

				// Compress
				compressed := github_zstd.Compress(chunk, compressionLevel)

				// Use smaller of compressed/uncompressed
				var data []byte
				if len(compressed) < len(chunk) {
					data = compressed
				} else {
					data = make([]byte, len(chunk))
					copy(data, chunk)
				}

				resultCh <- struct {
					index uint32
					data  []byte
				}{w.index, data}
			}
		}()
	}

	// Submit work
	for i := uint32(0); i < blockCount; i++ {
		offset := NcaFullHeaderSize + int64(i)*blockSize
		size := blockSize
		if offset+size > totalSize {
			size = totalSize - offset
		}
		workCh <- work{i, offset, size}
	}

	close(workCh)
	workerWg.Wait()
	close(resultCh)
	collectWg.Wait()

	if workerErr != nil {
		return nil, workerErr
	}

	return results, nil
}

// decryptChunk decrypts portions of a chunk that fall within encrypted sections.
func decryptChunk(chunk []byte, chunkOffset int64, sections []nsz.NczSectionEntry) {
	chunkStart := uint64(chunkOffset)
	chunkEnd := chunkStart + uint64(len(chunk))

	for _, sec := range sections {
		secEnd := sec.Offset + sec.Size

		// Check for intersection
		if chunkStart >= secEnd || chunkEnd <= sec.Offset {
			continue
		}

		// Calculate intersection
		start := chunkStart
		if sec.Offset > start {
			start = sec.Offset
		}
		end := chunkEnd
		if secEnd < end {
			end = secEnd
		}

		// Get slice to decrypt
		slice := chunk[start-chunkStart : end-chunkStart]

		if sec.CryptoType == 3 || sec.CryptoType == 4 {
			stream, err := crypto.NewCTRStream(sec.CryptoKey[:], sec.CryptoCounter[:], int64(start))
			if err == nil {
				stream.XORKeyStream(slice, slice)
			}
		}
	}
}
