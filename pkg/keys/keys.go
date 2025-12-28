package keys

import (
	"bufio"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

var (
	keys = make(map[string][]byte)
	mu   sync.RWMutex
)

// Load reads keys from a file.
// Format expected: key_name = HEXVALUE
func Load(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			continue
		}

		name := strings.TrimSpace(parts[0])
		valHex := strings.TrimSpace(parts[1])

		val, err := hex.DecodeString(valHex)
		if err != nil {
			// Ignore invalid lines? Or log? For now ignore.
			continue
		}

		mu.Lock()
		keys[name] = val
		mu.Unlock()
	}

	return scanner.Err()
}

// Get retrieves a key by name. Returns nil if not found.
func Get(name string) []byte {
	mu.RLock()
	defer mu.RUnlock()
	if k, ok := keys[name]; ok {
		// Return a copy to prevent modification
		dest := make([]byte, len(k))
		copy(dest, k)
		return dest
	}
	return nil
}

// LoadDefault tries to load keys from standard locations.
func LoadDefault() error {
	home, err := os.UserHomeDir()
	if err != nil {
		return err
	}

	paths := []string{
		"prod.keys",
		"keys.txt",
		filepath.Join(home, ".switch", "prod.keys"),
		filepath.Join(home, ".switch", "keys.txt"),
	}

	for _, p := range paths {
		if _, err := os.Stat(p); err == nil {
			return Load(p)
		}
	}
	return fmt.Errorf("no keys file found")
}
