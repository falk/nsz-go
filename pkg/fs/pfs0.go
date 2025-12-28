package fs

import (
	"encoding/binary"
	"fmt"
	"io"
	"os"
)

// PFS0Header represents the header of a PFS0 partition.
type PFS0Header struct {
	Magic           [4]byte
	NumFiles        uint32
	StringTableSize uint32
	Reserved        uint32
}

// PFS0FileEntry represents a file entry in the PFS0 header.
type PFS0FileEntry struct {
	DataOffset uint64
	DataSize   uint64
	NameOffset uint32
	Reserved   uint32
}

type Pfs0File struct {
	Name  string
	Entry PFS0FileEntry
}

// OpenPfs0 reads a PFS0 file and returns the file entries.
func OpenPfs0(f *os.File) ([]Pfs0File, int64, error) {
	var header PFS0Header
	if err := binary.Read(f, binary.LittleEndian, &header); err != nil {
		return nil, 0, err
	}

	if string(header.Magic[:]) != "PFS0" {
		return nil, 0, fmt.Errorf("invalid magic: expected PFS0, got %s", header.Magic)
	}

	entries := make([]PFS0FileEntry, header.NumFiles)
	if err := binary.Read(f, binary.LittleEndian, &entries); err != nil {
		return nil, 0, err
	}

	stringTable := make([]byte, header.StringTableSize)
	if _, err := io.ReadFull(f, stringTable); err != nil {
		return nil, 0, err
	}

	files := make([]Pfs0File, header.NumFiles)
	for i, entry := range entries {
		nameVal, err := getName(stringTable, entry.NameOffset)
		if err != nil {
			return nil, 0, err
		}
		files[i] = Pfs0File{
			Name:  nameVal,
			Entry: entry,
		}
	}

	// Data starts after Header + Entries + StringTable
	headerSize := int64(16 + len(entries)*24 + len(stringTable))
	return files, headerSize, nil
}

// ReadPfs0 reads a PFS0 file and prints its content.
func ReadPfs0(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()

	files, _, err := OpenPfs0(f)
	if err != nil {
		return err
	}

	fmt.Printf("Found %d files in PFS0 container:\n", len(files))
	for i, file := range files {
		fmt.Printf("File %d: %s (Size: %d bytes)\n", i, file.Name, file.Entry.DataSize)
	}

	return nil
}

func getName(stringTable []byte, offset uint32) (string, error) {
	if offset >= uint32(len(stringTable)) {
		return "", fmt.Errorf("offset out of bounds")
	}
	end := offset
	for end < uint32(len(stringTable)) && stringTable[end] != 0 {
		end++
	}
	return string(stringTable[offset:end]), nil
}
