package fs

import (
	"encoding/binary"
	"io"

	"github.com/falk/nsz-go/pkg/crypto"
)

// BktrHeader represents the BKTR header info from FS header bytes 0x100-0x120 or 0x120-0x140
type BktrHeader struct {
	Offset     uint64 // Offset within section to bucket data
	Size       uint64 // Size of bucket data
	Magic      [4]byte
	Version    uint32
	EntryCount uint32
	Reserved   uint32
}

// BktrSubsectionEntry represents a single subsection with its counter value
type BktrSubsectionEntry struct {
	VirtualOffset uint64 // Offset within section
	Size          uint64 // Size of this subsection (calculated)
	Padding       uint32
	Ctr           uint32 // Counter value for this subsection
}

// BktrBucket contains subsection entries
type BktrBucket struct {
	Padding    uint32
	EntryCount uint32
	EndOffset  uint64
	Entries    []BktrSubsectionEntry
}

// ParseBktrHeader parses BKTR header from 32 bytes of FS header data
func ParseBktrHeader(data []byte) *BktrHeader {
	if len(data) < 32 {
		return nil
	}
	h := &BktrHeader{
		Offset:     binary.LittleEndian.Uint64(data[0:8]),
		Size:       binary.LittleEndian.Uint64(data[8:16]),
		Version:    binary.LittleEndian.Uint32(data[20:24]),
		EntryCount: binary.LittleEndian.Uint32(data[24:28]),
		Reserved:   binary.LittleEndian.Uint32(data[28:32]),
	}
	copy(h.Magic[:], data[16:20])
	return h
}

// ParseBktrSubsectionBuckets reads and decrypts subsection buckets from NCA data.
// The bucket data is encrypted with the section's base counter.
func ParseBktrSubsectionBuckets(r io.ReaderAt, sectionOffset int64, bktrHeader *BktrHeader, titleKey []byte, baseCounter []byte) ([]BktrBucket, error) {
	if bktrHeader == nil || bktrHeader.Size == 0 {
		return nil, nil
	}
	if titleKey == nil || len(baseCounter) < 16 {
		return nil, nil
	}

	// Read the entire BKTR data area (it's encrypted)
	bktrDataOffset := sectionOffset + int64(bktrHeader.Offset)
	bktrData := make([]byte, bktrHeader.Size)
	if _, err := r.ReadAt(bktrData, bktrDataOffset); err != nil {
		return nil, err
	}

	// Decrypt the BKTR data using CTR mode at the BKTR offset
	absoluteOffset := sectionOffset + int64(bktrHeader.Offset)
	stream, err := crypto.NewCTRStream(titleKey, baseCounter, absoluteOffset)
	if err != nil {
		return nil, err
	}
	stream.XORKeyStream(bktrData, bktrData)

	// Parse decrypted bucket header
	// Structure: padding(4) + bucketCount(4) + totalSize(8) + baseOffsets(0x3FF0)
	if len(bktrData) < 16 {
		return nil, nil
	}

	bucketCount := binary.LittleEndian.Uint32(bktrData[4:8])
	if bucketCount == 0 || bucketCount > 100 {
		return nil, nil
	}

	// Buckets start after header (16 bytes) + base offsets (0x3FF0 bytes)
	headerSize := 16 + 0x3FF0
	if len(bktrData) < headerSize {
		return nil, nil
	}

	buckets := make([]BktrBucket, 0, bucketCount)
	bucketPos := headerSize

	for i := uint32(0); i < bucketCount; i++ {
		if bucketPos+16 > len(bktrData) {
			break
		}

		bucket := BktrBucket{
			Padding:    binary.LittleEndian.Uint32(bktrData[bucketPos : bucketPos+4]),
			EntryCount: binary.LittleEndian.Uint32(bktrData[bucketPos+4 : bucketPos+8]),
			EndOffset:  binary.LittleEndian.Uint64(bktrData[bucketPos+8 : bucketPos+16]),
		}

		if bucket.EntryCount > 0xFFFF {
			break
		}

		entriesPos := bucketPos + 16
		for j := uint32(0); j < bucket.EntryCount; j++ {
			entryPos := entriesPos + int(j)*16
			if entryPos+16 > len(bktrData) {
				break
			}

			entry := BktrSubsectionEntry{
				VirtualOffset: binary.LittleEndian.Uint64(bktrData[entryPos : entryPos+8]),
				Padding:       binary.LittleEndian.Uint32(bktrData[entryPos+8 : entryPos+12]),
				Ctr:           binary.LittleEndian.Uint32(bktrData[entryPos+12 : entryPos+16]),
			}
			bucket.Entries = append(bucket.Entries, entry)
		}

		// Calculate sizes for entries
		for j := 0; j < len(bucket.Entries)-1; j++ {
			bucket.Entries[j].Size = bucket.Entries[j+1].VirtualOffset - bucket.Entries[j].VirtualOffset
		}
		if len(bucket.Entries) > 0 {
			lastIdx := len(bucket.Entries) - 1
			bucket.Entries[lastIdx].Size = bucket.EndOffset - bucket.Entries[lastIdx].VirtualOffset
		}

		buckets = append(buckets, bucket)
		bucketPos = entriesPos + int(bucket.EntryCount)*16
	}

	return buckets, nil
}

// SetBktrCounter creates a base counter for BKTR decryption.
// Sets bytes 4-7 to the subsection's CTR value. Bytes 8-15 (block number)
// are set later during actual decryption based on the offset.
func SetBktrCounter(baseCounter []byte, ctrVal uint32) []byte {
	counter := make([]byte, 16)
	copy(counter, baseCounter)

	// Set bytes 4-7 to ctrVal (big-endian)
	counter[4] = byte(ctrVal >> 24)
	counter[5] = byte(ctrVal >> 16)
	counter[6] = byte(ctrVal >> 8)
	counter[7] = byte(ctrVal)

	return counter
}
