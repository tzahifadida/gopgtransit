package gopgtransit

import (
	"context"
	"database/sql"
	"fmt"
	"github.com/docker/go-connections/nat"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
	"github.com/tzahifadida/go-pg-dek-manager"

	_ "github.com/jackc/pgx/v5/stdlib"
)

const (
	testDBName     = "testdb"
	testDBUser     = "testuser"
	testDBPassword = "testpass"
)

func setupTestDatabase(t *testing.T) (*sql.DB, func()) {
	ctx := context.Background()

	// Create PostgreSQL container
	pgContainer, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: testcontainers.ContainerRequest{
			Image:        "postgres:13",
			ExposedPorts: []string{"5432/tcp"},
			Env: map[string]string{
				"POSTGRES_DB":       testDBName,
				"POSTGRES_USER":     testDBUser,
				"POSTGRES_PASSWORD": testDBPassword,
			},
			WaitingFor: wait.ForAll(
				wait.ForLog("database system is ready to accept connections"),
				wait.ForSQL("5432/tcp", "pgx", func(host string, port nat.Port) string {
					return fmt.Sprintf("host=%s port=%s user=%s password=%s dbname=%s sslmode=disable",
						host, port.Port(), testDBUser, testDBPassword, testDBName)
				}),
			).WithDeadline(1 * time.Minute),
		},
		Started: true,
	})
	require.NoError(t, err)

	// Get host and port
	host, err := pgContainer.Host(ctx)
	require.NoError(t, err)
	port, err := pgContainer.MappedPort(ctx, "5432")
	require.NoError(t, err)

	// Connect to the database
	dsn := fmt.Sprintf("host=%s port=%d user=%s password=%s dbname=%s sslmode=disable",
		host, port.Int(), testDBUser, testDBPassword, testDBName)
	db, err := sql.Open("pgx", dsn)
	require.NoError(t, err)

	// Ensure the database is ready
	err = waitForDB(db)
	require.NoError(t, err)

	// Return cleanup function
	cleanup := func() {
		db.Close()
		pgContainer.Terminate(ctx)
	}

	return db, cleanup
}

func waitForDB(db *sql.DB) error {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	for {
		select {
		case <-ctx.Done():
			return fmt.Errorf("timeout waiting for database to be ready")
		default:
			err := db.PingContext(ctx)
			if err == nil {
				return nil
			}
			time.Sleep(100 * time.Millisecond)
		}
	}
}

func TestTransitWithRealDatabase(t *testing.T) {
	db, cleanup := setupTestDatabase(t)
	defer cleanup()

	// Create a real DEK manager
	mek := []byte("12345678901234567890123456789012") // 32-byte MEK
	dekManager, err := gopgdekmanager.NewDEKManager(db, mek)
	require.NoError(t, err)

	transit := NewTransit(dekManager)
	ctx := context.Background()

	t.Run("RegisterAndEncryptDecrypt", func(t *testing.T) {
		plaintext := []byte("Hello, World!")
		keyName := "test_key"

		// Register the key first
		err := transit.Register(ctx, keyName)
		require.NoError(t, err)

		ciphertext, err := transit.Encrypt(ctx, keyName, plaintext)
		assert.NoError(t, err)
		assert.NotEqual(t, plaintext, ciphertext)

		decrypted, err := transit.Decrypt(ctx, keyName, ciphertext)
		assert.NoError(t, err)
		assert.Equal(t, plaintext, decrypted)
	})

	t.Run("RegisterWithEncryptionAndEncryptDecrypt", func(t *testing.T) {
		plaintext := []byte("Custom encryption method")
		keyName := "custom_key"

		// Register the key with a custom encryption method
		err := transit.RegisterWithEncryption(ctx, keyName, "aes192-random")
		require.NoError(t, err)

		ciphertext, err := transit.Encrypt(ctx, keyName, plaintext)
		assert.NoError(t, err)
		assert.NotEqual(t, plaintext, ciphertext)

		decrypted, err := transit.Decrypt(ctx, keyName, ciphertext)
		assert.NoError(t, err)
		assert.Equal(t, plaintext, decrypted)
	})

	t.Run("EncryptDecryptWithAAD", func(t *testing.T) {
		plaintext := []byte("Secret message")
		keyName := "aad_key"
		aad := []byte("UserID:123|SessionID:456")

		// Register the key first
		err := transit.Register(ctx, keyName)
		require.NoError(t, err)

		ciphertext, err := transit.EncryptWithAAD(ctx, keyName, plaintext, aad)
		assert.NoError(t, err)
		assert.NotEqual(t, plaintext, ciphertext)

		decrypted, err := transit.DecryptWithAAD(ctx, keyName, ciphertext, aad)
		assert.NoError(t, err)
		assert.Equal(t, plaintext, decrypted)

		// Try decrypting with wrong AAD
		_, err = transit.DecryptWithAAD(ctx, keyName, ciphertext, []byte("WrongAAD"))
		assert.Error(t, err)
	})

	t.Run("KeyRotation", func(t *testing.T) {
		keyName := "rotation_key"
		plaintext := []byte("Rotate me")

		// Register the key first
		err := transit.Register(ctx, keyName)
		require.NoError(t, err)

		// Encrypt with initial key
		ciphertext1, err := transit.Encrypt(ctx, keyName, plaintext)
		assert.NoError(t, err)

		// Rotate the key
		err = dekManager.RotateDEK(ctx, keyName)
		assert.NoError(t, err)

		// Encrypt with new key
		ciphertext2, err := transit.Encrypt(ctx, keyName, plaintext)
		assert.NoError(t, err)

		// Both ciphertexts should decrypt correctly
		decrypted1, err := transit.Decrypt(ctx, keyName, ciphertext1)
		assert.NoError(t, err)
		assert.Equal(t, plaintext, decrypted1)

		decrypted2, err := transit.Decrypt(ctx, keyName, ciphertext2)
		assert.NoError(t, err)
		assert.Equal(t, plaintext, decrypted2)
	})

	t.Run("MultipleKeys", func(t *testing.T) {
		key1 := "multi_key1"
		key2 := "multi_key2"
		plaintext := []byte("Multiple keys test")

		// Register both keys
		err := transit.Register(ctx, key1)
		require.NoError(t, err)
		err = transit.Register(ctx, key2)
		require.NoError(t, err)

		ciphertext1, err := transit.Encrypt(ctx, key1, plaintext)
		assert.NoError(t, err)

		ciphertext2, err := transit.Encrypt(ctx, key2, plaintext)
		assert.NoError(t, err)

		decrypted1, err := transit.Decrypt(ctx, key1, ciphertext1)
		assert.NoError(t, err)
		assert.Equal(t, plaintext, decrypted1)

		decrypted2, err := transit.Decrypt(ctx, key2, ciphertext2)
		assert.NoError(t, err)
		assert.Equal(t, plaintext, decrypted2)

		// Ensure keys are not interchangeable
		_, err = transit.Decrypt(ctx, key2, ciphertext1)
		assert.Error(t, err)
	})

	t.Run("ErrorCases", func(t *testing.T) {
		// Try to decrypt invalid ciphertext
		_, err := transit.Decrypt(ctx, "error_key", []byte("not valid ciphertext"))
		assert.Error(t, err)

		// Try to use a key that doesn't exist
		_, err = transit.Encrypt(ctx, "non_existent_key", []byte("test"))
		assert.Error(t, err)

		// Try to encrypt without registering the key first
		_, err = transit.Encrypt(ctx, "unregistered_key", []byte("test"))
		assert.Error(t, err)
	})
}
