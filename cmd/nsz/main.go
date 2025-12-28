package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/falk/nsz-go/pkg/fs"
	"github.com/falk/nsz-go/pkg/keys"
)

func main() {
	keysPath := flag.String("k", "", "Path to prod.keys")
	level := flag.Int("l", fs.DefaultCompressionLevel, "Compression level (1-22, higher = slower but smaller)")
	flag.Parse()

	compressionLevel := *level
	if compressionLevel < 1 || compressionLevel > 22 {
		compressionLevel = fs.DefaultCompressionLevel
	}

	fmt.Println("NSZ Go Port")

	var err error
	if *keysPath != "" {
		err = keys.Load(*keysPath)
	} else {
		err = keys.LoadDefault()
	}

	if err != nil {
		fmt.Printf("Warning: Could not load keys: %v\n", err)
		fmt.Println("Please provide keys file with -k or place in ~/.switch/prod.keys")
	} else {
		fmt.Println("Keys loaded successfully.")
		keys.DeriveKeys()
	}

	args := flag.Args()
	if len(args) == 0 {
		fmt.Println("Usage: nsz-go [options] <file>")
		return
	}

	inputFile := args[0]
	fmt.Printf("Processing %s...\n", inputFile)

	f, err := os.Open(inputFile)
	if err != nil {
		fmt.Printf("Error opening file: %v\n", err)
		return
	}
	defer f.Close()

	// Try parsing as PFS0 (NSP)
	pfsFiles, pfsHeaderSize, err := fs.OpenPfs0(f)
	if err == nil {
		processNsp(inputFile, f, pfsFiles, pfsHeaderSize, compressionLevel)
	} else {
		// Try parsing as NCA
		processSingleNca(inputFile, f, compressionLevel)
	}
}

func processNsp(inputPath string, f *os.File, files []fs.Pfs0File, headerSize int64, compressionLevel int) {
	fmt.Printf("Found Valid PFS0 (NSP) with %d files.\n", len(files))

	// 1. Find Title Key in Ticket (.tik)
	var titleKey []byte
	for _, file := range files {
		if strings.ToLower(filepath.Ext(file.Name)) == ".tik" {
			fmt.Printf("Found Ticket: %s\n", file.Name)
			// Read encrypted title key from ticket (offset 0x180, size 0x10)
			tikBuf := make([]byte, 0x190)
			offset := int64(file.Entry.DataOffset) + headerSize
			if _, err := f.ReadAt(tikBuf, offset); err != nil {
				fmt.Printf("Warning: Failed to read ticket: %v\n", err)
				break
			}
			encryptedKey := tikBuf[0x180 : 0x180+0x10]

			// We need Master Key Gen to decrypt.
			// We'll peek at the first NCA to find it.
			// (Simplification: assume all NCAs use same MK Gen)
			for _, ncaFile := range files {
				if strings.ToLower(filepath.Ext(ncaFile.Name)) == ".nca" {
					sr := io.NewSectionReader(f, int64(ncaFile.Entry.DataOffset)+headerSize, int64(ncaFile.Entry.DataSize))
					nca, err := fs.NewNCA(sr)
					if err == nil {
						keyGen := int(nca.Header.KeyGeneration)
						if nca.Header.KeyGeneration2 > nca.Header.KeyGeneration {
							keyGen = int(nca.Header.KeyGeneration2)
						}
						keyGen = keyGen - 1
						if keyGen < 0 {
							keyGen = 0
						}

						dec, err := keys.DecryptTitleKey(encryptedKey, keyGen)
						if err == nil {
							titleKey = dec
							fmt.Printf("Successfully decrypted Title Key: %x...\n", titleKey[:4])
						} else {
							fmt.Printf("Failed to decrypt title key: %v\n", err)
						}
						break
					}
				}
			}
			break
		}
	}

	outputPath := inputPath
	if strings.HasSuffix(outputPath, ".nsp") {
		outputPath = outputPath[:len(outputPath)-4] + ".nsz"
	} else {
		outputPath += ".nsz"
	}

	fmt.Printf("Creating %s...\n", outputPath)

	// Prepare output file list (names might change .nca -> .ncz)
	outputNames := make([]string, len(files))
	shouldCompress := make([]bool, len(files))

	for i, file := range files {
		ext := strings.ToLower(filepath.Ext(file.Name))
		if ext == ".nca" {
			// Check if compressible
			offset := int64(file.Entry.DataOffset) + headerSize
			sr := io.NewSectionReader(f, offset, int64(file.Entry.DataSize))

			nca, err := fs.NewNCA(sr)
			if err == nil {
				// Inject Title Key if we found one
				if titleKey != nil {
					nca.Header.TitleKey = titleKey
				}

				ct := nca.Header.ContentType
				// Compress Program (0) or PublicData (5)
				if (ct == 0 || ct == 5) && file.Entry.DataSize > 0x4000 {
					shouldCompress[i] = true
					outputNames[i] = strings.TrimSuffix(file.Name, ext) + ".ncz"
				} else {
					outputNames[i] = file.Name
				}
			} else {
				outputNames[i] = file.Name
			}
		} else {
			outputNames[i] = file.Name
		}
	}

	writer, err := fs.NewPfs0Writer(outputPath, outputNames)
	if err != nil {
		fmt.Printf("Error creating output: %v\n", err)
		return
	}
	defer writer.Close()

	// Processing Loop
	for i, file := range files {
		offset := int64(file.Entry.DataOffset) + headerSize
		size := int64(file.Entry.DataSize)
		sr := io.NewSectionReader(f, offset, size)

		fmt.Printf("[%d/%d] %s -> %s... ", i+1, len(files), file.Name, outputNames[i])

		if shouldCompress[i] {
			fmt.Printf("Compressing... ")

			if err := writer.AddCompressedFile(i, sr, size, titleKey, compressionLevel); err != nil {
				fmt.Printf("Error: %v\n", err)
				return
			}
			fmt.Println("Done.")
		} else {
			if err := writer.AddFile(i, sr, size); err != nil {
				fmt.Printf("Error: %v\n", err)
				return
			}
			fmt.Println("Added.")
		}
	}
	fmt.Println("Done!")
}

func processSingleNca(inputFile string, f *os.File, compressionLevel int) {
	nca, err := fs.NewNCA(f)
	if err != nil {
		fmt.Printf("Not a valid NCA: %v\n", err)
		return
	}

	fmt.Printf("Valid NCA3 found. Content Size: %d\n", nca.Header.ContentSize)
	outFile := inputFile + ".nsz"
	out, err := os.Create(outFile)
	if err != nil {
		fmt.Printf("Error creating output file: %v\n", err)
		return
	}
	defer out.Close()

	fileInfo, err := f.Stat()
	if err != nil {
		fmt.Printf("Error getting file info: %v\n", err)
		return
	}

	if _, err := fs.CompressNca(f, out, fileInfo.Size(), nil, compressionLevel); err != nil {
		fmt.Printf("Compression failed: %v\n", err)
		return
	}
	fmt.Println("Compression Complete.")
}
