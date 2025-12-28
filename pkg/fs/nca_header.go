package fs

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"

	"github.com/falk/nsz-go/pkg/crypto"
	"github.com/falk/nsz-go/pkg/keys"
)

const (
	NcaHeaderStructSize = 0xC00  // NCA header structure size
	NcaFullHeaderSize   = 0x4000 // Full header (uncompressable in NCZ)
	MediaSize           = 0x200  // Sector/media unit size
	MagicNCA3           = "NCA3"

	// Crypto types from FS header
	CryptoTypeNone = 1
	CryptoTypeXTS  = 2
	CryptoTypeCTR  = 3
	CryptoTypeBKTR = 4
)

type NcaHeader struct {
	FixedKeySig    [0x100]byte     // 0x000
	NpkSignature   [0x100]byte     // 0x100
	Magic          [4]byte         // 0x200 "NCA3"
	DistType       byte            // 0x204
	ContentType    byte            // 0x205
	KeyGeneration  byte            // 0x206
	KeyAreaIndex   byte            // 0x207
	ContentSize    uint64          // 0x208
	ProgID         uint64          // 0x210
	ContentIdx     uint32          // 0x218
	SdkAddonVer    uint32          // 0x21C
	KeyGeneration2 byte            // 0x220
	Signature2     [0xF]byte       // 0x221
	RightsID       [0x10]byte      // 0x230
	SectionTables  [4]SectionEntry // 0x240
	KeyArea        [0x40]byte      // 0x300 (Fixed offset for Key Area?)
	// Note: KeyArea is at 0x300 relative to start of file (decrypted)
	// struct padding might be needed if we Read directly into struct.
	// But we use binary.Read on parts.

	TitleKey  []byte // Decrypted Title Key
	FsHeaders [4]FsHeader
}

type SectionEntry struct {
	MediaStartOffset uint32
	MediaEndOffset   uint32
	Unknown1         uint32
	Unknown2         uint32
}

type FsHeader struct {
	Version       uint16
	FsType        uint8
	HashType      uint8
	CryptoType    uint8
	Reserved      [0x13B]byte // Padding to 0x140
	CryptoCounter [8]byte     // 0x140
	Reserved2     [0xB8]byte  // Padding to 0x200

	// BKTR info (from offsets 0x100-0x140 in FS header)
	BktrRelocation *BktrHeader // 0x100-0x120
	BktrSubsection *BktrHeader // 0x120-0x140
}

// ParseNcaHeader reads and decrypts the NCA header.
func ParseNcaHeader(r io.ReaderAt) (*NcaHeader, error) {
	encryptedHeader := make([]byte, NcaHeaderStructSize)
	if _, err := r.ReadAt(encryptedHeader, 0); err != nil {
		return nil, err
	}

	headerKey := keys.Get("header_key")
	if headerKey == nil {
		return nil, fmt.Errorf("header_key not found")
	}

	// Decrypt in sectors of 0x200 bytes
	decrypted := make([]byte, len(encryptedHeader))
	sectorSize := 0x200
	for i := 0; i < len(encryptedHeader)/sectorSize; i++ {
		start := i * sectorSize
		end := start + sectorSize
		chunk := encryptedHeader[start:end]

		out, err := crypto.XTSDecrypt(chunk, headerKey, uint64(i))
		if err != nil {
			return nil, fmt.Errorf("failed to decrypt sector %d: %v", i, err)
		}
		copy(decrypted[start:end], out)
	}

	// Parse Main Header at 0x200
	type MainHeaderBlock struct {
		Magic       [4]byte
		DistType    byte
		ContentType byte
		KeyGen      byte
		KeyAreaIdx  byte
		ContentSize uint64
		ProgID      uint64
		ContentIdx  uint32
		SdkAddonVer uint32
		KeyGen2     byte
		Sig2        [0xF]byte
		RightsID    [0x10]byte
	}

	var mainBlock MainHeaderBlock
	if err := binary.Read(bytes.NewReader(decrypted[0x200:]), binary.LittleEndian, &mainBlock); err != nil {
		return nil, err
	}

	if string(mainBlock.Magic[:]) != MagicNCA3 {
		return nil, fmt.Errorf("invalid magic: expected NCA3, got %s", mainBlock.Magic)
	}

	var header NcaHeader
	header.Magic = mainBlock.Magic
	header.ContentType = mainBlock.ContentType
	header.KeyGeneration = mainBlock.KeyGen
	header.KeyGeneration2 = mainBlock.KeyGen2
	header.ContentSize = mainBlock.ContentSize
	header.RightsID = mainBlock.RightsID

	// Read Section Tables (0x240)
	secReader := bytes.NewReader(decrypted[0x240:])
	if err := binary.Read(secReader, binary.LittleEndian, &header.SectionTables); err != nil {
		return nil, err
	}

	// Read Key Area (0x300)
	copy(header.KeyArea[:], decrypted[0x300:0x340])

	// Get Title Key
	keyGen := int(header.KeyGeneration)
	if header.KeyGeneration2 > header.KeyGeneration {
		keyGen = int(header.KeyGeneration2)
	}
	keyGen = keyGen - 1
	if keyGen < 0 {
		keyGen = 0
	}

	// Decrypt Key Area
	// Usually Title Key is at index 2 (offset 0x20 in KeyArea)
	encryptedTitleKey := header.KeyArea[0x20:0x30]

	// Only decrypt if we have keys (check rightsID?)
	// If RightsID is zero, use Key Area. If RightsID is set, usually title key is from ticket.
	// For Standard crypto (e.g. Program), RightsID might be 0 or set.
	// If set, we need ticket.
	// Simplification: Assume Key Area contains the key (Standard Crypto).

	// Check if Key Area is used (Crypto Type != 0)
	// Wait, FS Header determines Crypto Type.
	// But getting the key block happens here.

	titleKey, err := keys.UnwrapAesWrappedTitleKey(encryptedTitleKey, keyGen)
	if err == nil {
		header.TitleKey = titleKey
	} else {
		// fmt.Printf("Warning: Failed to unwrap title key: %v\n", err)
	}

	// Parse FS Headers (0x400, 0x600, 0x800, 0xA00)
	for i := 0; i < 4; i++ {
		offset := 0x400 + i*0x200
		data := decrypted[offset : offset+0x200]

		var h FsHeader
		h.Version = binary.LittleEndian.Uint16(data[0x0:0x2])
		h.FsType = data[0x3]
		h.CryptoType = data[0x4]
		copy(h.CryptoCounter[:], data[0x140:0x148])

		// Parse BKTR headers if this is a BKTR section
		if h.CryptoType == CryptoTypeBKTR {
			h.BktrRelocation = ParseBktrHeader(data[0x100:0x120])
			h.BktrSubsection = ParseBktrHeader(data[0x120:0x140])
		}

		header.FsHeaders[i] = h
	}

	return &header, nil
}
