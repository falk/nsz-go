package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"fmt"
	"sync"
)

// Cipher cache to avoid recreating AES ciphers for the same key
var (
	cipherCache   = make(map[[16]byte]cipher.Block)
	cipherCacheMu sync.RWMutex
)

func getCachedCipher(key []byte) (cipher.Block, error) {
	if len(key) != 16 {
		return nil, fmt.Errorf("key must be 16 bytes, got %d", len(key))
	}

	var keyArr [16]byte
	copy(keyArr[:], key)

	cipherCacheMu.RLock()
	block, ok := cipherCache[keyArr]
	cipherCacheMu.RUnlock()
	if ok {
		return block, nil
	}

	cipherCacheMu.Lock()
	defer cipherCacheMu.Unlock()

	// Double-check after acquiring write lock
	if block, ok = cipherCache[keyArr]; ok {
		return block, nil
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	cipherCache[keyArr] = block
	return block, nil
}

// ECBDecrypt decrypts data using AES-ECB.
// Note: ECB is not secure for general purpose, but used in Switch formats.
func ECBDecrypt(data, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	if len(data)%block.BlockSize() != 0 {
		return nil, fmt.Errorf("data length not multiple of block size")
	}

	out := make([]byte, len(data))
	for i := 0; i < len(data); i += block.BlockSize() {
		block.Decrypt(out[i:i+block.BlockSize()], data[i:i+block.BlockSize()])
	}
	return out, nil
}

// ECBEncrypt encrypts data using AES-ECB.
func ECBEncrypt(data, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	if len(data)%block.BlockSize() != 0 {
		return nil, fmt.Errorf("data length not multiple of block size")
	}

	out := make([]byte, len(data))
	for i := 0; i < len(data); i += block.BlockSize() {
		block.Encrypt(out[i:i+block.BlockSize()], data[i:i+block.BlockSize()])
	}
	return out, nil
}

// NewCTRStream creates an AES-CTR stream starting at a specific absolute offset.
// The iv contains the base counter (bytes 0-7 are section-specific).
// Bytes 8-15 are SET to the block number (offset / 16) in big-endian.
func NewCTRStream(key, iv []byte, absoluteOffset int64) (cipher.Stream, error) {
	block, err := getCachedCipher(key)
	if err != nil {
		return nil, err
	}

	counter := make([]byte, 16)
	copy(counter, iv)
	binary.BigEndian.PutUint64(counter[8:], uint64(absoluteOffset>>4))

	return cipher.NewCTR(block, counter), nil
}

// XTSDecrypt decrypts data using AES-XTS (Custom NSZ Tweak).
// key must be 32 bytes (16 bytes key1 + 16 bytes key2) for AES-128-XTS.
func XTSDecrypt(data, key []byte, sector uint64) ([]byte, error) {
	if len(key) != 32 {
		return nil, fmt.Errorf("XTS key must be 32 bytes (2x16) for AES-128")
	}

	c1, err := aes.NewCipher(key[:16]) // K1
	if err != nil {
		return nil, err
	}
	c2, err := aes.NewCipher(key[16:]) // K2
	if err != nil {
		return nil, err
	}

	// Initial Tweak: Big Endian Sector Number
	tweak := make([]byte, 16)
	binary.BigEndian.PutUint64(tweak[8:], sector)

	// Encrypt Tweak
	tweakEnc := make([]byte, 16)
	c2.Encrypt(tweakEnc, tweak)
	tweak = tweakEnc

	out := make([]byte, len(data))
	buf := make([]byte, 16)
	dec := make([]byte, 16)

	for i := 0; i < len(data); i += 16 {
		chunk := data[i : i+16]

		// C ^ T
		xor(buf, chunk, tweak)

		// D(K1, ...)
		c1.Decrypt(dec, buf)

		// ... ^ T
		xor(out[i:i+16], dec, tweak)

		// Update Tweak
		mul2(tweak)
	}
	return out, nil
}

func xor(dst, a, b []byte) {
	for i := 0; i < 16; i++ {
		dst[i] = a[i] ^ b[i]
	}
}

func mul2(tweak []byte) {
	var carry byte = 0
	for i := 0; i < 16; i++ {
		b := tweak[i]
		nextCarry := b >> 7
		tweak[i] = (b << 1) | carry
		carry = nextCarry
	}
	if carry != 0 {
		tweak[0] ^= 0x87
	}
}
