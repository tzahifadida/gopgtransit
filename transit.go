package gopgtransit

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"github.com/tzahifadida/go-pg-dek-manager"
	"io"
)

const (
	versionSize             = 4  // Size of the version number in bytes
	minimumKeySize          = 32 // Minimum key size in bytes (256 bits)
	defaultEncryptionMethod = "aes256-random"
)

// Transit provides high-level encryption and decryption operations using the DEK manager.
type Transit struct {
	dekManager *gopgdekmanager.DEKManager
}

// NewTransit creates a new Transit instance with the given DEK manager.
func NewTransit(dekManager *gopgdekmanager.DEKManager) *Transit {
	return &Transit{
		dekManager: dekManager,
	}
}

// Register registers a new key with the DEK manager using AES-256 encryption by default.
func (t *Transit) Register(ctx context.Context, keyName string) error {
	return t.dekManager.RegisterKeyWithFunction(ctx, keyName, defaultEncryptionMethod)
}

// RegisterWithEncryption registers a new key with the DEK manager using the specified encryption method.
func (t *Transit) RegisterWithEncryption(ctx context.Context, keyName, encryptionMethod string) error {
	return t.dekManager.RegisterKeyWithFunction(ctx, keyName, encryptionMethod)
}

// writeVersion writes the version number to a byte slice in a cross-platform manner.
func writeVersion(version int) []byte {
	versionBytes := make([]byte, versionSize)
	binary.BigEndian.PutUint32(versionBytes, uint32(version))
	return versionBytes
}

// readVersion reads the version number from a byte slice in a cross-platform manner.
func readVersion(data []byte) (int, error) {
	if len(data) < versionSize {
		return 0, errors.New("invalid data: too short to contain version")
	}
	return int(binary.BigEndian.Uint32(data[:versionSize])), nil
}

// Encrypt encrypts the plaintext using the DEK associated with the given key name.
func (t *Transit) Encrypt(ctx context.Context, keyName string, plaintext []byte) ([]byte, error) {
	dek, version, err := t.dekManager.GetDEK(ctx, keyName)
	if err != nil {
		return nil, fmt.Errorf("failed to get DEK: %w", err)
	}

	block, err := aes.NewCipher(dek)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("failed to generate nonce: %w", err)
	}

	ciphertext := gcm.Seal(nil, nonce, plaintext, nil)

	// Combine version, nonce, and ciphertext
	result := make([]byte, versionSize+len(nonce)+len(ciphertext))
	copy(result[:versionSize], writeVersion(version))
	copy(result[versionSize:], nonce)
	copy(result[versionSize+len(nonce):], ciphertext)

	return result, nil
}

// Decrypt decrypts the ciphertext using the DEK associated with the given key name and version.
func (t *Transit) Decrypt(ctx context.Context, keyName string, ciphertext []byte) ([]byte, error) {
	if len(ciphertext) < versionSize {
		return nil, errors.New("invalid ciphertext: too short")
	}

	version, err := readVersion(ciphertext[:versionSize])
	if err != nil {
		return nil, fmt.Errorf("failed to read version: %w", err)
	}

	dek, err := t.dekManager.GetDEKByVersion(ctx, keyName, version)
	if err != nil {
		return nil, fmt.Errorf("failed to get DEK: %w", err)
	}

	block, err := aes.NewCipher(dek)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	nonceSize := gcm.NonceSize()
	if len(ciphertext) < versionSize+nonceSize {
		return nil, errors.New("invalid ciphertext: too short")
	}

	nonce := ciphertext[versionSize : versionSize+nonceSize]
	encryptedData := ciphertext[versionSize+nonceSize:]

	plaintext, err := gcm.Open(nil, nonce, encryptedData, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt: %w", err)
	}

	return plaintext, nil
}

// EncryptWithAAD encrypts the plaintext with additional authenticated data (AAD).
func (t *Transit) EncryptWithAAD(ctx context.Context, keyName string, plaintext, aad []byte) ([]byte, error) {
	dek, version, err := t.dekManager.GetDEK(ctx, keyName)
	if err != nil {
		return nil, fmt.Errorf("failed to get DEK: %w", err)
	}

	if len(dek) < minimumKeySize {
		return nil, fmt.Errorf("DEK size (%d bytes) is less than minimum required size (%d bytes)", len(dek), minimumKeySize)
	}

	block, err := aes.NewCipher(dek)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("failed to generate nonce: %w", err)
	}

	ciphertext := gcm.Seal(nil, nonce, plaintext, aad)

	// Combine version, nonce, and ciphertext
	result := make([]byte, versionSize+len(nonce)+len(ciphertext))
	copy(result[:versionSize], writeVersion(version))
	copy(result[versionSize:], nonce)
	copy(result[versionSize+len(nonce):], ciphertext)

	return result, nil
}

// DecryptWithAAD decrypts the ciphertext with additional authenticated data (AAD).
func (t *Transit) DecryptWithAAD(ctx context.Context, keyName string, ciphertext, aad []byte) ([]byte, error) {
	if len(ciphertext) < versionSize {
		return nil, errors.New("invalid ciphertext: too short")
	}

	version, err := readVersion(ciphertext[:versionSize])
	if err != nil {
		return nil, fmt.Errorf("failed to read version: %w", err)
	}

	dek, err := t.dekManager.GetDEKByVersion(ctx, keyName, version)
	if err != nil {
		return nil, fmt.Errorf("failed to get DEK: %w", err)
	}

	if len(dek) < minimumKeySize {
		return nil, fmt.Errorf("DEK size (%d bytes) is less than minimum required size (%d bytes)", len(dek), minimumKeySize)
	}

	block, err := aes.NewCipher(dek)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	nonceSize := gcm.NonceSize()
	if len(ciphertext) < versionSize+nonceSize {
		return nil, errors.New("invalid ciphertext: too short")
	}

	nonce := ciphertext[versionSize : versionSize+nonceSize]
	encryptedData := ciphertext[versionSize+nonceSize:]

	plaintext, err := gcm.Open(nil, nonce, encryptedData, aad)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt: %w", err)
	}

	return plaintext, nil
}
