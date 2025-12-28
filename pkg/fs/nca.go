package fs

import (
	"io"
	"sort"

	"github.com/falk/nsz-go/pkg/nsz"
)

type NCA struct {
	Header *NcaHeader
	Reader io.ReaderAt
}

func NewNCA(r io.ReaderAt) (*NCA, error) {
	h, err := ParseNcaHeader(r)
	if err != nil {
		return nil, err
	}
	return &NCA{Header: h, Reader: r}, nil
}

// GetEncryptionSections extracts the sections for NSZ compression.
// For BKTR sections, this parses subsection entries for proper decryption.
func (n *NCA) GetEncryptionSections() ([]nsz.NczSectionEntry, error) {
	var sections []nsz.NczSectionEntry

	for i, entry := range n.Header.SectionTables {
		if entry.MediaStartOffset == 0 && entry.MediaEndOffset == 0 {
			continue
		}

		sectionOffset := uint64(entry.MediaStartOffset) * MediaSize
		sectionEnd := uint64(entry.MediaEndOffset) * MediaSize
		sectionSize := sectionEnd - sectionOffset
		fsHeader := n.Header.FsHeaders[i]

		// Build base counter from FS header
		baseIV := buildBaseIV(fsHeader.CryptoCounter[:])

		// Handle BKTR sections with subsection info
		if fsHeader.CryptoType == CryptoTypeBKTR && fsHeader.BktrSubsection != nil && fsHeader.BktrSubsection.Size > 0 {
			bktrSections := n.parseBktrSections(sectionOffset, sectionEnd, fsHeader.BktrSubsection, baseIV)
			if len(bktrSections) > 0 {
				sections = append(sections, bktrSections...)
				continue
			}
		}

		// Default: single section
		sec := nsz.NczSectionEntry{
			Offset:     sectionOffset,
			Size:       sectionSize,
			CryptoType: uint64(fsHeader.CryptoType),
		}
		if n.Header.TitleKey != nil {
			copy(sec.CryptoKey[:], n.Header.TitleKey)
		}
		copy(sec.CryptoCounter[:], baseIV)
		sections = append(sections, sec)
	}

	// Sort by offset (required by NCZ format)
	sort.Slice(sections, func(i, j int) bool {
		return sections[i].Offset < sections[j].Offset
	})

	return sections, nil
}

// parseBktrSections parses BKTR subsection entries into encryption sections.
func (n *NCA) parseBktrSections(sectionOffset, sectionEnd uint64, bktrHeader *BktrHeader, baseIV []byte) []nsz.NczSectionEntry {
	buckets, err := ParseBktrSubsectionBuckets(n.Reader, int64(sectionOffset), bktrHeader, n.Header.TitleKey, baseIV)
	if err != nil || len(buckets) == 0 {
		return nil
	}

	var sections []nsz.NczSectionEntry
	var lastEntryEnd uint64

	for _, bucket := range buckets {
		for _, entry := range bucket.Entries {
			if entry.Size == 0 {
				continue
			}

			sec := nsz.NczSectionEntry{
				Offset:     sectionOffset + entry.VirtualOffset,
				Size:       entry.Size,
				CryptoType: CryptoTypeCTR, // BKTR uses CTR for decryption
			}

			if n.Header.TitleKey != nil {
				copy(sec.CryptoKey[:], n.Header.TitleKey)
			}

			counter := SetBktrCounter(baseIV, entry.Ctr)
			copy(sec.CryptoCounter[:], counter)
			sections = append(sections, sec)

			if end := sectionOffset + entry.VirtualOffset + entry.Size; end > lastEntryEnd {
				lastEntryEnd = end
			}
		}
	}

	// Add trailing section for gap between last BKTR entry and section end
	if lastEntryEnd < sectionEnd {
		tail := nsz.NczSectionEntry{
			Offset:     lastEntryEnd,
			Size:       sectionEnd - lastEntryEnd,
			CryptoType: CryptoTypeCTR,
		}
		if n.Header.TitleKey != nil {
			copy(tail.CryptoKey[:], n.Header.TitleKey)
		}
		copy(tail.CryptoCounter[:], baseIV)
		sections = append(sections, tail)
	}

	return sections
}

// buildBaseIV constructs the 16-byte base IV from the 8-byte FS header counter.
func buildBaseIV(counter []byte) []byte {
	iv := make([]byte, 16)
	// Copy counter to high bytes and reverse for proper format
	copy(iv[8:], counter)
	for i, j := 0, 15; i < j; i, j = i+1, j-1 {
		iv[i], iv[j] = iv[j], iv[i]
	}
	return iv
}
