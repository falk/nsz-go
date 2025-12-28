package fs

import (
	"encoding/binary"
	"io"
	"os"
)

type Pfs0Writer struct {
	f           *os.File
	stringTable []byte
	entries     []PFS0FileEntry
	headerSize  int64
	dataOffset  int64 // Current write position relative to data start
}

func NewPfs0Writer(path string, fileNames []string) (*Pfs0Writer, error) {
	f, err := os.Create(path)
	if err != nil {
		return nil, err
	}

	// Calculate String Table
	stringTable := make([]byte, 0)
	nameOffsets := make([]uint32, len(fileNames))

	for i, name := range fileNames {
		nameOffsets[i] = uint32(len(stringTable))
		stringTable = append(stringTable, []byte(name)...)
		stringTable = append(stringTable, 0) // Null terminator
	}

	// Prepare Entries
	entries := make([]PFS0FileEntry, len(fileNames))
	for i := range entries {
		entries[i].NameOffset = nameOffsets[i]
	}

	// Calculate Header Size
	// Header (16) + Entries (24 * N) + StringTable
	headerSize := int64(16 + len(entries)*24 + len(stringTable))

	// Write Placeholder
	// We seek past the header
	if _, err := f.Seek(headerSize, 0); err != nil {
		f.Close()
		return nil, err
	}

	return &Pfs0Writer{
		f:           f,
		stringTable: stringTable,
		entries:     entries,
		headerSize:  headerSize,
		dataOffset:  0,
	}, nil
}

// AddFile writes data for the i-th file.
// It assumes files are added in order.
func (w *Pfs0Writer) AddFile(index int, r io.Reader, size int64) error {
	w.entries[index].DataOffset = uint64(w.dataOffset)
	w.entries[index].DataSize = uint64(size)

	n, err := io.Copy(w.f, r)
	if err != nil {
		return err
	}
	w.dataOffset += n
	return nil
}

// AddCompressedFile compresses and writes the i-th file.
func (w *Pfs0Writer) AddCompressedFile(index int, r io.ReaderAt, size int64, titleKey []byte, compressionLevel int) error {
	w.entries[index].DataOffset = uint64(w.dataOffset)

	// CompressNca writes to w.f
	n, err := CompressNca(r, w.f, size, titleKey, compressionLevel)
	if err != nil {
		return err
	}

	w.entries[index].DataSize = uint64(n) // Compressed Size
	w.dataOffset += n
	return nil
}

// WriteHeader finalizes the PFS0 file.
func (w *Pfs0Writer) Close() error {
	// Seek to 0
	if _, err := w.f.Seek(0, 0); err != nil {
		return err
	}

	header := PFS0Header{
		NumFiles:        uint32(len(w.entries)),
		StringTableSize: uint32(len(w.stringTable)),
	}
	copy(header.Magic[:], "PFS0")

	if err := binary.Write(w.f, binary.LittleEndian, header); err != nil {
		return err
	}

	if err := binary.Write(w.f, binary.LittleEndian, w.entries); err != nil {
		return err
	}

	if _, err := w.f.Write(w.stringTable); err != nil {
		return err
	}

	return w.f.Close()
}
