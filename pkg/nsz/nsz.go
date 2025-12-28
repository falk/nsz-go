package nsz

import (
	"encoding/binary"
	"io"
)

const (
	MagicNSZ = "NSZ%"
)

// NSZHeader structure (Little Endian)
// Offset 0x00: Magic "NSZ%" (4 bytes)
// Offset 0x04: Version (4 bytes)
// Offset 0x08: Target Block Size Exponent (4 bytes) (e.g. 20 for 1MB)
// Offset 0x0C: Number of Sections (4 bytes) (Always 1 for simplified flow)
// Offset 0x10: Data Offset (8 bytes)
type NSZHeader struct {
	Magic        [4]byte
	Version      uint32
	BlockSizeExp uint32
	SectionCount uint32
	DataOffset   uint64
}

// SectionHeader inside NSZ
type SectionHeader struct {
	FileOffset    uint64
	Size          uint64
	CryptoType    int64
	Padding       [8]byte
	CryptoKey     [16]byte
	CryptoCounter [16]byte
}

func NewHeader(blockSizeExp uint32) *NSZHeader {
	h := &NSZHeader{
		Version:      0,
		BlockSizeExp: blockSizeExp,
		SectionCount: 1, // We treat the whole file as one section for now? Or is it one section per NCA section?
		// Usually NSZ just compresses the whole file as a continuous stream of blocks,
		// but skipping headers.
		// For simplicity, we'll try to follow the "Block Compression" format where we have a block table.
	}
	copy(h.Magic[:], MagicNSZ)
	return h
}

// WriteHeader writes the NSZ header to the writer.
func (h *NSZHeader) Write(w io.Writer) error {
	return binary.Write(w, binary.LittleEndian, h)
}
