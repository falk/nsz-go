package nsz

import (
	"encoding/binary"
	"io"
)

const (
	MagicNCZSECTN = "NCZSECTN"
	MagicNCZBLOCK = "NCZBLOCK"
)

type NczSectionHeader struct {
	Magic        [8]byte // NCZSECTN
	SectionCount uint64
}

type NczSectionEntry struct {
	Offset        uint64
	Size          uint64
	CryptoType    uint64
	Padding       uint64
	CryptoKey     [16]byte
	CryptoCounter [16]byte
}

type NczBlockHeader struct {
	Magic            [8]byte // NCZBLOCK
	Version          uint8   // 2
	Type             uint8   // 1
	Unused           uint8
	BlockSizeExp     uint8
	BlockCount       uint32
	DecompressedSize uint64
}

func WriteNczHeader(w io.Writer, sections []NczSectionEntry) error {
	var h NczSectionHeader
	copy(h.Magic[:], MagicNCZSECTN)
	h.SectionCount = uint64(len(sections))

	if err := binary.Write(w, binary.LittleEndian, h); err != nil {
		return err
	}

	for _, s := range sections {
		if err := binary.Write(w, binary.LittleEndian, s); err != nil {
			return err
		}
	}
	return nil
}
