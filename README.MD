# gopgtransit

⭐ If you find this project useful, please consider giving it a star on GitHub! Your support helps us improve and maintain this library. ⭐

gopgtransit is a Go library that provides a simple and secure way to encrypt and decrypt data using a Data Encryption Key (DEK) management system. It's designed to work seamlessly with the `go-pg-dek-manager` library for key management.

## Features

- Simple API for encryption and decryption
- Explicit key registration with support for custom encryption methods
- Automatic versioning of encryption keys
- Support for Additional Authenticated Data (AAD)
- Built on top of industry-standard AES-GCM encryption
- Context-aware operations for better control and cancellation

## Installation

To install gopgtransit, use `go get`:

```
go get github.com/tzahifadida/gopgtransit
```

## Quick Start

Here's a simple example of how to use gopgtransit:

```go
import (
"context"
"github.com/tzahifadida/gopgtransit"
"github.com/tzahifadida/go-pg-dek-manager"
)

// Initialize your DEK manager (refer to go-pg-dek-manager documentation)
dekManager, err := gopgdekmanager.NewDEKManager(/* ... */)
if err != nil {
// Handle error
}

// Create a new Transit instance
transit := gopgtransit.NewTransit(dekManager)

// Create a context
ctx := context.Background()

// Register a key (this can be done once at application startup)
keyName := "my-encryption-key"
err = transit.Register(ctx, keyName)
if err != nil {
// Handle error
}

// Encrypt some data
plaintext := []byte("Hello, World!")
ciphertext, err := transit.Encrypt(ctx, keyName, plaintext)
if err != nil {
// Handle error
}

// Decrypt the data
decrypted, err := transit.Decrypt(ctx, keyName, ciphertext)
if err != nil {
// Handle error
}

// decrypted should now be equal to plaintext
```

Note: The `Register` method only needs to be called once for each key, typically at application startup. After registration, you can use the key for encryption and decryption operations without registering it again.

## Understanding Encryption

For those new to encryption, here are some key concepts:

1. **Encryption**: The process of encoding information so that only authorized parties can access it.
2. **Decryption**: The reverse process of encryption, converting encrypted data back into its original form.
3. **Key**: A piece of information (usually a string of bits) that determines the output of a cryptographic algorithm.
4. **Data Encryption Key (DEK)**: A key used to encrypt and decrypt data.
5. **Key Rotation**: The practice of regularly changing encryption keys to limit the amount of data encrypted with a single key.

## Key Concepts in gopgtransit

### Key Names and Registration

In gopgtransit, each encryption key is associated with a `keyName`. Before using a key for encryption or decryption, you must register it using either `Register` or `RegisterWithEncryption` methods:

```go
// Register with default encryption method (AES-256)
err := transit.Register(ctx, "default-key")

// Register with a specific encryption method
err := transit.RegisterWithEncryption(ctx, "custom-key", "aes192-random")
```

Key registration only needs to be done once per key, typically at application startup. After registration, the key can be used for multiple encryption and decryption operations without needing to be registered again.

### Versioning

gopgtransit automatically handles key versioning. When you encrypt data, the version of the key used is stored along with the encrypted data. This allows the library to use the correct key version for decryption, even if the key has been rotated.

### Additional Authenticated Data (AAD)

AAD is a feature in modern encryption algorithms that allows you to include additional plaintext data in the encryption process without encrypting it. This data is used to ensure the integrity and authenticity of both the encrypted data (ciphertext) and the AAD itself.

Key points about AAD:
- It remains unencrypted but is protected against tampering.
- It binds the encrypted data to a specific context.
- It's used in the authentication process during decryption.

## Understanding Additional Authenticated Data (AAD)

AAD is a crucial feature in modern encryption that prevents the misuse of encrypted data across different users or sessions. Here's why AAD is important and how to use it effectively:

### Preventing Cross-User Data Misuse

Without AAD, encrypted data could potentially be used by any user who has access to the decryption key. AAD allows you to bind the encrypted data to a specific user or session.

**Example: User-Specific Encryption**

```go
userID := "user123"
plaintext := []byte("Sensitive user data")
aad := []byte("UserID:" + userID)

ciphertext, err := transit.EncryptWithAAD(ctx, keyName, plaintext, aad)
if err != nil {
    // Handle error
}

// Later, when decrypting:
decrypted, err := transit.DecryptWithAAD(ctx, keyName, ciphertext, aad)
if err != nil {
    // This will fail if the wrong user ID is provided
}
```

In this example, the encrypted data is bound to a specific user. Attempts to decrypt it with a different user ID will fail.

### Ensuring Session-Specific Data Integrity

AAD can also be used to tie encrypted data to a specific session, preventing replay attacks across different sessions.

**Example: Session-Bound Encryption**

```go
sessionID := "session456"
plaintext := []byte("Session-specific data")
aad := []byte("SessionID:" + sessionID)

ciphertext, err := transit.EncryptWithAAD(ctx, keyName, plaintext, aad)
if err != nil {
    // Handle error
}

// In a different session:
wrongSessionID := "session789"
wrongAAD := []byte("SessionID:" + wrongSessionID)
_, err = transit.DecryptWithAAD(ctx, keyName, ciphertext, wrongAAD)
if err != nil {
    // This will fail, preventing cross-session data misuse
}
```

### Storing Encrypted Data in Text-Based Systems

When storing encrypted data in text-based systems (like databases or JSON files), it's common to encode the binary ciphertext as base64. Here's how to do this with gopgtransit:

**Example: Encrypting, Encoding, and Storing**

```go
import "encoding/base64"

plaintext := []byte("Sensitive data")
aad := []byte("UserID:user123")

ciphertext, err := transit.EncryptWithAAD(ctx, keyName, plaintext, aad)
if err != nil {
    // Handle error
}

// Encode to base64 for storage
encodedCiphertext := base64.StdEncoding.EncodeToString(ciphertext)

// Store 'encodedCiphertext' in your database or file
```

**Example: Retrieving, Decoding, and Decrypting**

```go
// Retrieve 'encodedCiphertext' from your database or file

decodedCiphertext, err := base64.StdEncoding.DecodeString(encodedCiphertext)
if err != nil {
    // Handle error
}

aad := []byte("UserID:user123")
plaintext, err := transit.DecryptWithAAD(ctx, keyName, decodedCiphertext, aad)
if err != nil {
    // Handle error
}

// Use 'plaintext'
```

## Best Practices

1. **Key Management**: Use a secure method to generate and store your master encryption key (MEK) used by the DEK manager.
2. **Key Registration**: Register your keys once at application startup. You don't need to register a key before each encryption or decryption operation.
3. **Key Rotation**: Regularly rotate your DEKs using the DEK manager's rotation functionality.
4. **Error Handling**: Always check for and handle errors returned by the encryption and decryption functions.
5. **AAD Usage**: When using `EncryptWithAAD` and `DecryptWithAAD`, choose AAD that binds the encrypted data to its intended context.
6. **AAD Consistency**: Ensure that the same AAD is used during both encryption and decryption.
7. **Immutable AAD**: Use data that doesn't change over time as AAD (e.g., user IDs, timestamps at the moment of encryption).
8. **Always Include User or Session Information**: Incorporate unique identifiers like user IDs or session IDs in your AAD to prevent unauthorized cross-user or cross-session data access.
9. **Combine Multiple Identifiers**: For enhanced security, consider combining multiple pieces of contextual data in your AAD.

   Example:
   ```go
   aad := []byte(fmt.Sprintf("UserID:%s|SessionID:%s|Timestamp:%d", userID, sessionID, time.Now().Unix()))
   ```

10. **Avoid Sensitive Data in AAD**: Remember that AAD is not encrypted. Don't include sensitive information that shouldn't be exposed.
11. **Use Base64 Encoding for Storage**: Always encode your ciphertext to base64 when storing in text-based systems, and decode before decryption.
12. **Context Usage**: Always use appropriate contexts for your operations, especially in long-running or background tasks.

## Security Considerations

While gopgtransit provides a high-level interface for encryption, it's important to remember that the security of your encrypted data depends on the security of your key management system and your overall application design.

- Keep your MEK secure and never hard-code it in your application.
- Be cautious about logging or displaying encrypted data or keys.
- Remember that AAD is not encrypted; don't include sensitive data in AAD.
- Consider using gopgtransit as part of a broader security strategy that includes secure communications, access controls, and other relevant security measures.

## Contributing

Contributions to gopgtransit are welcome! Please submit pull requests with any enhancements, bug fixes, or documentation improvements.

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.