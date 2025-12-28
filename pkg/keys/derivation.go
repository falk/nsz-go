package keys

import (
	"fmt"
	"github.com/falk/nsz-go/pkg/crypto"
)

// Derived keys cache
var (
	keyAreaKeys [32][3][]byte
	titleKeks   [32][]byte
)

// DecryptTitleKey decrypts a title key using the specified master key generation.
func DecryptTitleKey(encryptedKey []byte, keyGen int) ([]byte, error) {
	mu.RLock()
	kek := titleKeks[keyGen]
	mu.RUnlock()

	if kek == nil {
		return nil, fmt.Errorf("title_kek_%02x not derived", keyGen)
	}

	return crypto.ECBDecrypt(encryptedKey, kek)
}

func GenerateKek(src, masterKey, kekSeed, keySeed []byte) ([]byte, error) {
	kek, err := crypto.ECBDecrypt(kekSeed, masterKey)
	if err != nil {
		return nil, err
	}

	srcKek, err := crypto.ECBDecrypt(src, kek)
	if err != nil {
		return nil, err
	}

	if keySeed != nil {
		return crypto.ECBDecrypt(keySeed, srcKek)
	}
	return srcKek, nil
}

// DeriveKeys generates the Key Area Keys and Title Keks for all available master keys.
// Should be called after loading keys.
func DeriveKeys() {
	mu.Lock()
	defer mu.Unlock()

	aesKekGen := keys["aes_kek_generation_source"]
	aesKeyGen := keys["aes_key_generation_source"]
	titleKekSource := keys["titlekek_source"]

	keyAreaSources := [3][]byte{
		keys["key_area_key_application_source"],
		keys["key_area_key_ocean_source"],
		keys["key_area_key_system_source"],
	}

	if aesKekGen == nil || aesKeyGen == nil {
		fmt.Println("Warning: Missing generation sources. Cannot derive keys.")
		return
	}

	for i := 0; i < 32; i++ {
		masterKeyName := fmt.Sprintf("master_key_%02x", i)
		masterKey := keys[masterKeyName]
		if masterKey == nil {
			continue
		}

		// Derive Title Kek
		if titleKekSource != nil {
			// TitleKek is Decrypt(titlekek_source, master_key)
			tk, err := crypto.ECBDecrypt(titleKekSource, masterKey)
			if err == nil {
				titleKeks[i] = tk
			}
		}

		// Derive Key Area Keys (Application, Ocean, System)
		for typeIdx := 0; typeIdx < 3; typeIdx++ {
			if keyAreaSources[typeIdx] == nil {
				continue
			}
			kak, err := GenerateKek(keyAreaSources[typeIdx], masterKey, aesKekGen, aesKeyGen)
			if err == nil {
				keyAreaKeys[i][typeIdx] = kak
			}
		}
	}
}

// UnwrapAesWrappedTitleKey unwraps the key from the NCA Key Area.
// usually it is wrapped with Key Area Key Application.
func UnwrapAesWrappedTitleKey(wrappedKey []byte, keyGen int) ([]byte, error) {
	mu.RLock()
	kak := keyAreaKeys[keyGen][0] // Application Key Area Key
	mu.RUnlock()

	if kak == nil {
		return nil, fmt.Errorf("key_area_key_application_%02x not derived", keyGen)
	}

	return crypto.ECBDecrypt(wrappedKey, kak)
}
