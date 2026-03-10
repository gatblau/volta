# Volta User Guide

This guide provides examples on how to use the Volta Vault Manager, covering core functionalities like secure encryption/decryption of PII, enterprise-grade secret management, and administrative operations.

---

## 1. Prerequisites & Secure Configuration

Before interacting with Volta, you must configure the `VaultManager` correctly.

### Secure Master Passphrase & Salt Management

The `VaultManager` requires a `DerivationPassphrase` and a `DerivationSalt` to manage vault keys securely.

**Security Warning:**
* **Never hardcode the `DerivationPassphrase` or `DerivationSalt` in your source code.**
* **Persistence is Mandatory:** You **MUST** persist the `DerivationSalt` across initialisations.
    *   **Automated Persistence:** Volta automatically handles `DerivationSalt` persistence across all built-in storage providers, including File-based and S3 stores. When using S3, the salt is stored as an object (vault.salt) in the configured S3 bucket. You should back up the vault contents (including the salt) along with your other vault data.
    *   **Custom Storage:** If you implement a custom `persist.Store`, you **MUST** ensure your implementation correctly handles salt persistence using the `SaveSalt` and `LoadSalt` methods, as this is critical for data recovery. 
    *   **Consequence:** If you regenerate the salt every time the system starts, all previously encrypted data will be rendered **PERMANENTLY UNRECOVERABLE**. 

#### Loading Secrets Securely
The only sensitive secret required for vault initialization is the `DerivationPassphrase`. For production environments, the recommended pattern is to retrieve this passphrase at runtime from a secure vault (e.g., AWS Secrets Manager, HashiCorp Vault) and inject it directly into the `volta.Options` struct.

```go
// Example: Fetching from an external secret manager
passphrase := secretManager.GetSecret("production/vault-master-passphrase")

options := volta.Options{
    DerivationPassphrase: passphrase, // Directly inject the secret
    EnableMemoryLock:     true,
}
```

*   **DerivationPassphrase**: You can inject it directly into `Options.DerivationPassphrase` as shown above, OR use `Options.EnvPassphraseVar` to specify an environment variable that already contains the passphrase.
*   **DerivationSalt**: Note that you do not need to manage the salt as a secret; Volta handles its persistence automatically across storage providers. You only need to ensure the underlying storage location remains accessible and is included in your backup procedures.

---

## 2. Initialisation & Development

### Development Initialisation
For local development, you can initialise the `VaultManager` by explicitly setting `DerivationPassphrase` and `DerivationSalt` in the `volta.Options` struct. Ensure you use stable, persistent values even in development to avoid repeatedly invalidating your data.

```go
options := volta.Options{
    DerivationPassphrase: "dev-secure-passphrase",
    DerivationSalt:       []byte("dev-stable-salt-value"), // MUST PERSIST
    EnableMemoryLock:     true, // Recommended for extra security
}

// Initialise with a simple file store
vaultManager := volta.NewVaultManagerFileStore(options, "/tmp/volta/vaults", auditLogger)
```

### Initialising VaultManager (Operational Modes)

Volta provides multiple ways to initialise the `VaultManager` based on your storage and audit needs.

#### A. File-based Storage
Ideal for simple deployments or when using a local filesystem.

```go
auditLogger := audit.NewLogger(&audit.Config{...}) // Initialise audit logger
basePath := "/var/lib/volta/vaults"

vaultManager := volta.NewVaultManagerFileStore(options, basePath, auditLogger)
```

#### B. S3 or Custom Storage (Factory Pattern)
For enterprise or cloud-native scenarios, you can define a `persist.StoreConfig` or a custom store factory function.

```go
// Using StoreConfig (S3 example)
storeConfig := persist.StoreConfig{
    Type: persist.StoreTypeS3,
    Config: map[string]interface{}{
        "bucket": "my-tenant-vaults",
        "region": "us-east-1",
    },
}

vaultManager := volta.NewVaultManagerWithStoreConfig(options, storeConfig, auditLogger)
```

---

## 3. Managing Tenant Vaults

Volta's `VaultManager` orchestrates multi-tenant vaults using lazy initialisation.

*   **Lazy Initialisation**: Calling `vaultManager.GetVault(tenantID)` checks if the vault exists. If not, it uses the configured `persist.Store` or factory to provision storage and create the vault instance on-demand.
*   **Isolation**: Each tenant receives an independent storage instance and vault service instance, ensuring complete data and cryptographic isolation.

```go
// Retrieve or create a tenant's vault
vault, err := vaultManager.GetVault("tenant-001")
```

---

## 4. Administrative Operations

The `VaultManager` provides robust tools for key rotation and audit log analysis.

### Key & Passphrase Rotation
Enterprise compliance often requires regular key and passphrase rotation.

*   **Key Rotation (Individual)**: `vault.RotateDataEncryptionKey(reason)` rotates the DEK for a specific tenant's vault.
*   **Key Rotation (Bulk)**: `vaultManager.RotateAllTenantKeys(tenantIDs, reason)` performs bulk rotation for multiple tenant vaults.
*   **Passphrase Rotation**: `RotateAllTenantPassphrases(tenantIDs, newPassphrase, reason)` updates the master passphrase for designated vaults.

### Auditing & Analysis
The `VaultManager` acts as a central hub for compliance monitoring.

*   **Audit Logging**: Configure `audit.Logger` during initialisation to maintain an immutable trail of all operations.
*   **Query Capabilities**:
    *   `QueryAuditLogs(...)`: General query for audit events across tenant boundaries.
    *   `QueryPassphraseAccessLogs(...)`: Specialized query for passphrase-related activities (authentication, rotation).
    *   `QueryFailedOperations(...)`: Focused query for identifying operational issues or security anomalies.
    *   `QuerySecretAccess(...)`: Investigation of interaction with specific secret resources.
    *   `QueryKeyOperations(...)`: Forensic analysis of activities performed with specific cryptographic keys.
    *   `GetAuditSummary(...)`: High-level metrics report (event frequency, success rates, etc.) for operational oversight.

---

## Scenario 1: PII Encryption & Decryption

The `encryption/main.go` example demonstrates how to perform PII lifecycle operations.

### Workflow:
1. **Initialize Audit Logger**: Records significant operations for compliance.
2. **Setup File Store**: Define the base path for vault storage.
3. **Obtain Vault**: Get an instance for a specific tenant (e.g., `pii-processor-service`).
4. **Encrypt PII**: `vault.Encrypt(data)` results in self-contained ciphertext (includes key metadata).
5. **Decrypt PII**: `vault.Decrypt(ciphertext)` automatically resolves the key and returns plaintext.

Example summary:
*   **Initialization**: `vaultManager.GetVault(tenantID)`
*   **Encryption**: `ciphertext, err := vault.Encrypt(data)`
*   **Decryption**: `decryptedData, err := vault.Decrypt(ciphertext)`

---

## Scenario 2: Secret Management

The `secrets/main.go` example demonstrates how to manage multiple tenant vaults and store/retrieve secrets.

### Workflow:
1. **Manage Multi-Tenant Vaults**: `VaultManager` orchestrates vaults separately by tenant ID.
2. **Store Secret**: `vault.StoreSecret(id, data, tags, contentType)`. The data is encrypted transparently.
3. **Use Secret**: `vault.UseSecret(id, callback)` is the recommended pattern to retrieve, decrypt, and use a secret. The plaintext data is available only within the callback and is cleared from memory afterward.

Example summary:
*   **Store**: `vault.StoreSecret(secretID, value, tags, volta.ContentTypeText)`
*   **Use**: `vault.UseSecret(id, func(plaintext []byte) error { ... })`

---

## Performance & Best Practices

1. **Resource Cleanup**: Always call `vault.Close()` to release file handles and scrub sensitive memory.
2. **Memory Protection**: Enable `EnableMemoryLock` to mitigate threats from memory dumps.
3. **Performance Monitoring**: As shown in the encryption example, cryptographic operations are very fast (often measured in microseconds), making it suitable for high-throughput services.
4. **Audit Logging**: Always configure an audit logger (e.g., file-based as shown in `createAuditLogger()`) to maintain a trail of all critical operations.
