# secenv

Secure, profile-based environment variable management with HOCON configuration, PGP decryption, and optional GCP Secret Manager integration for retrieving PGP private keys.

## Features

- 🔐 **PGP decryption**: Decrypt PGP-encrypted values using a private key provided via file, literal, GPG keyring (by fingerprint), or GCP Secret Manager
- ☁️ **GCP Secret Manager**: Fetch the PGP private key at runtime via `gcloud`
- 🗂️ **Profiles**: Organize variables by profile (dev, staging, prod, …)
- 🪪 **Profile gates**: Optionally require the current user's system biometrics or password, a dedicated profile password, or both before unlock and seal
- 📄 **Temporary files**: Create temporary files with plain or encrypted content that are automatically cleaned up after command execution
- **Sealed HOCON/JSON**: Decrypt marked scalar values in place or render them from templates for the command lifetime
- 🧪 **Docs & tooling**: Built-in manual and shell completion generators
- ⚡ **Fast & safe**: Rust-based CLI

## Installation

### From source

```bash
git clone https://github.com/cchexcode/secenv
cd secenv
cargo build --release
```

The binary will be at `target/release/secenv`.

## Quick start

### 1) Create `secenv.conf` (JSON or HOCON)

```hocon
version = "0.0.0"  # Must be semver and compatible with the CLI version

profiles.default {
  # Optional: decrypt marked values in HOCON/JSON files while the command runs.
  # Every file has its own PGP key or Argon2id passphrase from a configured source.
  sealed {
    # Replace these files in place, then restore their exact encrypted bytes.
    files {
      "./application.conf" {
        secret.pgp.gcp.secret = "projects/123456789/secrets/application-pgp-key"
      }
    }

    # Or render a temporary output from an encrypted template.
    # Map keys are output paths; source is the encrypted template path.
    templates {
      "./runtime-config.json" {
        source = "./runtime-config.json.sealed"
        secret.argon2id_xchacha20_poly1305.gcp.secret = "projects/123456789/secrets/runtime-passphrase"
      }
    }
  }

  # Optional: Define temporary files that will be created before command execution
  # and automatically cleaned up afterwards
  files {
    # Plain file example
    # "./config.json".plain.literal = '{"key": "value"}'
    
    # Secure file with PGP-encrypted content
    # "./credentials.key".secure {
    #   secret.pgp.gpg.fingerprint = "1E1BAC706C352094D490D5393F5167F1F3002043"
    #   value.base64 = "<base64-encoded ASCII-armored PGP message>"
    # }
  }

  env {
    # Optional regex patterns of variables to keep when executing a command.
    # If set, the child environment is cleared first, then only matching host vars are kept.
    # If omitted, the full host environment is kept.
    # keep = ["^PATH$", "^SHELL$", "^LC_.*"]

    vars {
      # Plain inline values
      APP_NAME.plain.literal = "myapp"
      # DB_HOST.plain.base64 = "bG9jYWxob3N0"  # "localhost"

      # Secure PGP-decrypted value using a GPG key from local keyring by fingerprint
      SECRET_TOKEN.secure {
        secret.pgp.gpg.fingerprint = "1E1BAC706C352094D490D5393F5167F1F3002043"
        value.base64 = "<base64-encoded ASCII-armored PGP message>"
      }

      # Secure PGP-decrypted value using a private key stored in GCP Secret Manager
      # secret.pgp.gcp.secret must be a fully qualified resource:
      #   projects/<project>/secrets/<name>[/versions/<version>]
      # version defaults to "latest" if omitted.
      SERVICE_TOKEN.secure {
        secret.pgp.gcp.secret = "projects/123456789/secrets/pgp-private-key"
        # secret.pgp.gcp.version = "latest"  # optional
        value.literal = """
        -----BEGIN PGP MESSAGE-----
        ...
        -----END PGP MESSAGE-----
        """
      }

      # Sealed marker using the same algorithms and key sources as sealed files
      DATABASE_PASSWORD.sealed {
        secret.argon2id_xchacha20_poly1305.gcp.secret = "projects/123456789/secrets/database-passphrase"
        value = "ENC[ARGON2ID-XCHACHA20-POLY1305,<base64-versioned-payload>]"
      }
    }
  }
}
```

Notes:
- The config file can be in JSON or HOCON format (HOCON is a superset of JSON).
- Relative file and sealed-template paths are resolved from the config file's directory.
- Use `secenv init` to generate a JSON example file, or write your own in HOCON format.
- The `version` field is validated against the CLI version. The config cannot be newer than the CLI, and major versions must match.
- PGP private keys for ordinary secure variables and temporary files support `literal`, `file`, `env`, `gpg`, `gcp`, and `aws` sources under `secret.pgp`.
- Sealed-file and inline profile-value PGP keys and Argon2id passphrases support the same `literal`, `file`, `env`, `gpg`, `gcp`, and `aws` source forms under the selected algorithm.

### 2) Unlock variables and manage temporary files

```bash
# Print key=value pairs for the default profile
secenv unlock

# Use a specific profile and config path
secenv unlock --config /path/to/secenv.conf --profile production

# Load into a POSIX shell (bash/zsh)
eval "$(secenv unlock --profile production)"
```

To run a command with the variables set:

```bash
# Run a program inheriting host environment (default behavior)
secenv unlock --profile production -- env | sort

# With keep configured in the profile, only matching host vars are preserved
secenv unlock --profile production -- printenv | sort

# Execute a command (temporary files defined in the profile will be created and cleaned up)
secenv unlock --profile production -- make deploy

# Stop a long-running command after five minutes, then clean up plaintext files
secenv unlock --profile production --timeout 300 -- make deploy

# Overwrite existing files if they already exist
secenv unlock --profile production --force -- make deploy
```

Output format when printing:
```
APP_NAME=myapp
SECRET_TOKEN=...
```

**Note**: When executing a command, files defined in `profiles.<profile>.files` are created before the command runs and deleted afterward. With `--force`, a pre-existing file is restored instead of deleted.

## Profile authentication

Each profile can require the current user's system biometrics or password, a dedicated profile password, or both. The checks are independent. Omit `auth` to keep the previous behavior. Both run before `unlock` or `seal` resolves any secret.

```hocon
profiles.production.auth {
  # Fresh operating-system prompt for the current user.
  # macOS: Touch ID when this process can use it, or that user's password.
  #        Enter Password remains available when Touch ID is shown. secenv never
  #        reads this password, and a previous biometric unlock is not reused.
  # Linux: the sudo PAM stack. Fingerprint if that stack is configured for it,
  #        otherwise the current user's password from the terminal, not stdin.
  system = true

  # Quoted Argon2id verifier from `secenv auth password`. The `$` characters are
  # literal only inside quotes.
  password = "$argon2id$v=19$m=19456,t=2,p=1$..."
}
```

Generate a verifier and paste it into the profile. secenv does not rewrite the config, because round-tripping HOCON would discard comments and substitutions:

```bash
secenv auth password
```

Supply that profile password with `--password`, or enter it at the prompt. The prompt reads the terminal, so it still works when `seal` is reading plaintext from stdin. `--password` can appear in shell history and process listings; prefer the prompt for interactive use.

```bash
secenv unlock --profile production
secenv seal --profile production --password "$PROFILE_PASSWORD" --env-var DATABASE_PASSWORD
```

`auth.system` is a human presence check for the current user. Piping a password into secenv cannot satisfy it, and another account is not accepted.

On macOS, the system dialog accepts Touch ID or that user's password, not Apple Watch. If Touch ID is unavailable, not enrolled, or not permitted for this process, macOS asks for the password instead of skipping the check. The dialog needs a local graphical session.

On Linux, glibc builds ask the `sudo` PAM stack. A fingerprint is offered only when that stack includes one. Otherwise the current user's password is read from the terminal. This needs `/dev/tty` and a PAM installation. It does not open a login session. Musl builds do not include this check.

On any other platform, or when the platform cannot show its prompt, the command fails.

These gates apply to the secenv binary you run. Editing the config or replacing the binary can remove them. They do not re-encrypt sealed values.

## Temporary files

The temporary files feature allows you to create files with sensitive content that are automatically managed by `secenv`. This is useful for:

- **Credential files**: Create temporary credential files (e.g., `.kubeconfig`, `.aws/credentials`, service account keys) that are needed by commands but should not persist on disk
- **Configuration files**: Generate temporary config files with decrypted secrets
- **SSH keys**: Provide temporary SSH keys for deployment scripts
- **Certificate files**: Supply temporary SSL/TLS certificates and keys

### How it works

1. **Definition**: Files are defined in the `profiles.<profile>.files` section of the config
2. **Content types**: Files can contain plain text or legacy PGP-encrypted `secure` content; inline `sealed` markers are reserved for profile environment variables
3. **Creation**: Before running a command (or printing env vars), all files are created with their decrypted content
4. **Directory creation**: Parent directories are automatically created if they don't exist
5. **Conflict handling**: If a file already exists, the operation fails unless `--force` is used
6. **Cleanup**: Created files are deleted; pre-existing files overwritten with `--force` are restored
7. **Error handling**: Cleanup failures are reported as command failures and retried when the file manager is dropped

### Example use case

```hocon
profiles.production {
  files {
    # Temporary kubeconfig for kubectl commands
    "./kubeconfig".secure {
      secret.pgp.gcp.secret = "projects/myproject/secrets/pgp-key"
      value.base64 = "<base64-encoded-pgp-message>"
    }
    
    # Temporary service account key
    "./service-account.json".secure {
      secret.pgp.gpg.fingerprint = "1E1BAC706C352094D490D5393F5167F1F3002043"
      value.base64 = "<base64-encoded-pgp-message>"
    }
  }
  
  env.vars {
    KUBECONFIG.plain.literal = "./kubeconfig"
    GOOGLE_APPLICATION_CREDENTIALS.plain.literal = "./service-account.json"
  }
}
```

Then run:
```bash
secenv unlock --profile production -- kubectl get pods
# The kubeconfig and service account files are created, kubectl runs, then files are deleted
```

## Sealed values

The `ENC[...]` marker format works both inside managed HOCON/JSON documents and directly in `profiles.<profile>.env.vars`.

### Inline profile environment values

Use `sealed` for profile variables that should store only ciphertext in `secenv.conf`:

```hocon
profiles.production.env.vars {
  API_TOKEN.sealed {
    secret.pgp.gcp.secret = "projects/myproject/secrets/profile-pgp-key"
    value = "ENC[PGP,<base64-encoded OpenPGP message>]"
  }

  DATABASE_PASSWORD.sealed {
    secret.argon2id_xchacha20_poly1305.aws.secret = "my-app/profile-passphrase"
    value = "ENC[ARGON2ID-XCHACHA20-POLY1305,<base64-versioned-payload>]"
  }
}
```

During `unlock`, each complete marker is decrypted and the plaintext becomes the variable's value. The configured algorithm must match the marker. Legacy `KEY.secure` values remain supported for raw PGP messages; use `KEY.sealed` for the shared marker format and Argon2id support.

Generate a marker for a configured profile variable and write it to stdout:

```bash
printf %s 'database-password' \
  | secenv seal --profile production --env-var DATABASE_PASSWORD
```

Paste the emitted marker into the variable's `value` field. Secenv does not rewrite `secenv.conf`, because round-tripping HOCON would discard comments, formatting, helper sections, and substitutions.

### Sealed HOCON and JSON documents

Profiles can decrypt individual string values inside existing HOCON or JSON documents. Each file or template selects PGP or Argon2id/XChaCha20-Poly1305 and loads its own key material from a literal, file, environment variable, GPG keyring, GCP Secret Manager, or AWS Secrets Manager. All required secrets are loaded and every document is decrypted and authenticated in zeroized in-memory buffers before any plaintext document is written.

Encrypted values use a single-line marker containing a base64-encoded OpenPGP message:

```hocon
database {
  host = "localhost"
  password = "ENC[PGP,<base64-encoded OpenPGP message>]"
}
```

Password-based values use a versioned Argon2id/XChaCha20-Poly1305 payload:

```hocon
database.password = "ENC[ARGON2ID-XCHACHA20-POLY1305,<base64-versioned-payload>]"
```

The same marker works in JSON:

```json
{
  "database": {
    "host": "localhost",
    "password": "ENC[PGP,<base64-encoded OpenPGP message>]"
  }
}
```

Configure in-place files and templates on each profile:

```hocon
profiles.production.sealed {
  # Decrypted atomically in place before the command and restored afterward.
  files {
    "./application.conf" {
      secret.pgp.gcp.secret = "projects/myproject/secrets/application-pgp-key"
      # secret.pgp.gcp.version = "latest"  # optional
    }
    "./settings.json" {
      secret.argon2id_xchacha20_poly1305.aws.secret = "my-app/settings-passphrase"
      # secret.argon2id_xchacha20_poly1305.aws.version = "AWSCURRENT"  # optional
      # secret.argon2id_xchacha20_poly1305.aws.region = "us-east-1"    # optional
    }
  }

  # Each map key is a temporary output path.
  templates {
    "./generated/runtime.conf" {
      source = "./templates/runtime.conf.sealed"
      secret.pgp.env = "SECENV_RUNTIME_PGP_KEY"
    }
    "./generated/credentials.json" {
      source = "./templates/credentials.json.sealed"
      secret.argon2id_xchacha20_poly1305.env = "SECENV_CREDENTIALS_PASSPHRASE"
    }
  }
}
```

### Generating sealed values

`secenv seal` selects a configured in-place path, template output path, or profile environment variable and uses that entry's configured algorithm. PGP entries encrypt with the public portion of the configured certificate. Argon2id/XChaCha20-Poly1305 entries derive an encryption key from the configured passphrase.

For an `env` source, the configured value is the environment variable name, not the secret itself. PGP sealing needs a public certificate and unlocking needs the corresponding private key; an environment variable containing the private certificate can serve both operations. Password values and multiline PGP key material are read verbatim without trimming. Missing or non-Unicode variables are rejected before plaintext files are written.

All sealed algorithms use the same source forms:

```hocon
# Inline UTF-8 or base64-encoded key material/password
secret.pgp.literal.literal = "<key material>"
secret.argon2id_xchacha20_poly1305.literal.base64 = "<base64 password>"

# File contents or a named environment variable
secret.pgp.file = "/path/to/private.key"
secret.argon2id_xchacha20_poly1305.env = "SECENV_SEALED_PASSWORD"

# Private key exported from the local GPG keyring
secret.pgp.gpg.fingerprint = "1E1BAC706C352094D490D5393F5167F1F3002043"

# Cloud secret managers
secret.pgp.gcp.secret = "projects/myproject/secrets/pgp-key"
secret.argon2id_xchacha20_poly1305.aws.secret = "my-app/passphrase"
```

`gpg` resolves to the exported private-key text and is primarily useful with the PGP algorithm. Other source forms return their exact string value and can be used with either algorithm.

Pass plaintext directly and write only the sealed marker to stdout:

```bash
secenv seal \
  --profile production \
  --for ./application.conf \
  'database-password'
```

Direct values can be visible in shell history and process listings. For sensitive values, pipe plaintext on stdin instead:

```bash
printf %s 'database-password' \
  | secenv seal --profile production --for ./application.conf
```

Read a string from a HOCON/JSON document and atomically replace it with the sealed marker:

```bash
secenv seal \
  --profile production \
  --for ./application.conf \
  --path /database/password
```

For templates, `--for` names the configured output path and the command updates its `source` document:

```bash
secenv seal \
  --profile production \
  --for ./generated/credentials.json \
  --path /service/token
```

Path mode uses RFC 6901 JSON Pointers, including `/database/password`, `/key.with.dots`, and `/items/0`. Escape `~` as `~0` and `/` inside a key as `~1`; an empty pointer selects the document root. The selected value must exist and be a plaintext string. Path mode materializes the updated document as canonical JSON, so HOCON comments and formatting are not preserved.

Path sealing rejects HOCON substitutions because they can alias the plaintext selected for encryption. For example:

```hocon
password = "plaintext"
password_copy = ${password}
```

HOCON resolves `password_copy` to `"plaintext"` before secenv traverses the document. Sealing only `/password` would otherwise replace that node while canonical output persisted `password_copy` in plaintext. Secenv therefore rejects path sealing whenever the source contains `${`. During `unlock`, in-document substitutions are allowed: if `password` already contains an `ENC[...]` marker, the parser resolves `password_copy` to the same marker and structure-aware traversal decrypts both string nodes. System-environment substitutions such as `${HOME}` remain disabled.

Behavior and constraints:

- A marker must occupy the complete string value. Decrypted values are emitted as strings.
- A marker's algorithm must match its file or profile variable's configured secret type; mixed algorithms within one file are rejected.
- `argon2id_xchacha20_poly1305` uses Argon2id with 19 MiB memory, 2 iterations, and 1 lane to derive a 256-bit key. Its versioned payload contains a random 16-byte salt, random 24-byte nonce, and authenticated XChaCha20-Poly1305 ciphertext. Use a high-entropy passphrase.
- Environment variables used as any secret source are removed from provider helper processes and child commands run by `secenv unlock`. Defining the same name explicitly in `profiles.<profile>.env.vars` reintroduces it only for the final child. The original value remains in secenv's parent process environment.
- Inside managed HOCON/JSON documents, unmarked strings and all numbers, booleans, arrays, objects, and null values are preserved. A profile variable configured with `sealed` must contain one complete marker.
- Documents are parsed strictly as HOCON and materialized as canonical JSON, which is valid HOCON. System-environment substitutions such as `${HOME}` are disabled; normal substitutions within the document still resolve.
- In-place source bytes, formatting, comments, and basic file permissions are restored after execution. Atomic replacement creates a new inode, so original ownership, hard-link identity, ACLs, extended attributes, and timestamps are not guaranteed to be preserved.
- In-place files and template sources must already exist and must be regular files inside the current project directory. Symbolic links, hard-linked files on Unix, and paths outside the project are rejected.
- Decrypted files use mode `0600` on Unix.
- Template outputs are removed after execution. With `--force`, a pre-existing output is restored instead of deleted.
- A template source may be configured for only one output because each output owns an independent key.
- Restoration runs after successful commands, command failures, startup errors after replacement, timeout, Ctrl-C, and SIGTERM. It cannot run after SIGKILL, a power loss, or an unrecoverable process crash, so in-place mode should only be used where that residual risk is acceptable.
- On timeout, Ctrl-C, or SIGTERM, `secenv` attempts to terminate and reap the immediate child process before restoring or removing secret files. Termination failures are reported; a successfully terminated timed-out command exits with status 124 after cleanup.
- Do not concurrently rename configured files or their parent directories while `secenv unlock` is active.
- Selecting a document with no valid marker is an error, as are malformed markers and failed decryptions.

## Configuration reference (JSON/HOCON)

### Top-level

```hocon
version = "<semver>"
profiles = { 
  <name> = { 
    sealed = {                     # optional inline HOCON/JSON decryption
      files = {                    # optional in-place files
        <path> = {
          secret = { pgp|argon2id_xchacha20_poly1305 = { literal|file|env|gpg|gcp|aws = ... } }
        }
      },
      templates = {                # optional temporary outputs
        <output> = {
          source = <source>,
          secret = { pgp|argon2id_xchacha20_poly1305 = { literal|file|env|gpg|gcp|aws = ... } }
        }
      }
    },
    auth = {                       # optional; either field may be used alone
      system = true              # current user's biometrics or password
      password = "<argon2id verifier>"
    }
    files = { ... }              # optional
    env = { 
      keep = [<regex>],          # optional
      vars = { ... }             # optional
    } 
  } 
}
```

### Profiles and temporary files

```hocon
profiles.<profile>.files {
  # Define temporary files that will be created before command execution
  # and automatically cleaned up afterwards
  
  # Plain file content
  "/path/to/file".plain.literal = "file content"
  "/path/to/file".plain.base64 = "<base64-encoded content>"
  
  # Secure file content (PGP-decrypted)
  "/path/to/secure.key".secure {
    # Use any of the same PGP secret sources as environment variables
    secret.pgp.file = "/path/to/private.key"
    # or secret.pgp.literal, secret.pgp.env, secret.pgp.gpg.fingerprint,
    # secret.pgp.gcp, or secret.pgp.aws
    
    value.literal = "-----BEGIN PGP MESSAGE-----..."
    # or value.base64 = "<base64-encoded-ASCII-armored-message>"
  }
}
```

### Profiles and environment

```hocon
profiles.<profile>.env.keep = ["^PATH$", "^LC_.*"]  # optional
profiles.<profile>.env.vars {                          # optional
  # Plain values (inline only)
  KEY.plain.literal = "value"
  KEY.plain.base64  = "<base64-encoded string>"

  # Secure values (PGP-decrypted)
  KEY.secure {
    # One of the following PGP private key sources:
    # Inline (EncodedValue): choose one encoding
    # secret.pgp.literal.literal = """
    # -----BEGIN PGP PRIVATE KEY BLOCK-----
    # ...
    # -----END PGP PRIVATE KEY BLOCK-----
    # """
    # or
    # secret.pgp.literal.base64 = "<base64-encoded ASCII-armored private key>"
    # OR
    # secret.pgp.file = "/path/to/private.key"
    # OR
    # secret.pgp.env = "SECENV_PGP_KEY"
    # OR
    # secret.pgp.gpg.fingerprint = "<fingerprint>"
    # OR
    # secret.pgp.gcp.secret = "projects/<project>/secrets/<name>"
    # secret.pgp.gcp.version = "latest"  # optional
    # OR
    # secret.pgp.aws.secret = "<secret-name-or-arn>"
    # secret.pgp.aws.version = "AWSCURRENT"  # optional
    # secret.pgp.aws.region = "us-east-1"    # optional

    # Encrypted value to decrypt (ASCII-armored PGP message)
    value.literal = "-----BEGIN PGP MESSAGE-----..."
    # or
    # value.base64 = "<base64-encoded-ASCII-armored-message>"
  }

  # Shared sealed-marker format: PGP or Argon2id, with any supported secret source
  DATABASE_PASSWORD.sealed {
    secret.argon2id_xchacha20_poly1305.gcp.secret = "projects/<project>/secrets/<passphrase>"
    value = "ENC[ARGON2ID-XCHACHA20-POLY1305,<base64-versioned-payload>]"
  }
}
```

### Providers

- **plain**: Inline string value via `literal` or `base64`
- **secure**: Decrypts a PGP message using a provided PGP private key (`secret.pgp.*`)
- **sealed**: Decrypts a complete PGP or Argon2id `ENC[...]` marker using any supported secret source

Important:
- Direct profile values can be loaded from `file`, `gcs`, or `aws`; inline plain values use `literal` or `base64`.
- Decryption via GPG keyring requires a `fingerprint`, and secenv verifies that GPG used that key.

## CLI reference

Commands:

### unlock
Unlock values, create temporary files, and optionally execute a command with the variables set.

```bash
secenv unlock [OPTIONS] [--] [COMMAND...]

Options:
  -c, --config <path>     Path to config (default: secenv.conf)
  -p, --profile <name>    Profile name (default: default)
  -f, --force             Overwrite existing files defined in the manifest
      --timeout <seconds> Maximum subcommand runtime; requires COMMAND
      --password <password> Profile password required by auth.password
```

Behavior:
- Without `COMMAND`, prints POSIX `export KEY=VALUE` lines to stdout. If the profile defines temporary files, they are created and immediately cleaned up.
- With `COMMAND`, executes it with variables set and temporary files created. Files are automatically cleaned up after the command completes.
- With `--timeout`, attempts to terminate and reap the immediate child after the given number of seconds, cleans up plaintext files, and exits 124 when termination and cleanup succeed.
- If `env.keep` is set in the profile, the child environment is cleared first and only host variables matching any regex in `keep` are preserved; otherwise, the full host environment is kept.
- Environment variables configured as secret sources are removed from provider helpers and the child environment unless explicitly reintroduced through `env.vars` for the final child.
- Temporary files defined in `profiles.<profile>.files` are created before command execution:
  - Parent directories are automatically created if they don't exist
  - If a file already exists, the command fails unless `--force` is specified
  - Files support both plain and secure (PGP-encrypted) content
  - Created files are removed; pre-existing files overwritten with `--force` are restored
- Sealed in-place files and template outputs exist in decrypted form only while `unlock` is active and are restored or removed before it exits.

### seal
Encrypt a value using the PGP key or Argon2id passphrase configured for a sealed document or profile environment variable.

```bash
secenv seal --for <configured-path> [VALUE] [OPTIONS]
secenv seal --for <configured-path> --path <json-pointer> [OPTIONS]
secenv seal --env-var <name> [VALUE] [OPTIONS]

Options:
  -c, --config <path>     Path to config (default: secenv.conf)
  -p, --profile <name>    Profile name (default: default)
      --for <path>        Configured in-place path or template output path
      --env-var <name>    Profile environment variable configured with sealed content
      --path <json-pointer> RFC 6901 pointer to one string in the configured source document
      --password <password> Profile password required by auth.password
```

Exactly one of `--for` or `--env-var` is required. Without `--path`, plaintext comes from positional `VALUE`, or exactly from piped stdin when `VALUE` is omitted, and the marker is written to stdout. Direct values may be exposed through shell history and process listings. With `--path`, `VALUE` is rejected, the selected source document is updated, and the resulting marker is also written to stdout. `--path` is valid only with `--for`; `--env-var` never rewrites the manifest.

### auth password
Print an Argon2id verifier for `profiles.<name>.auth.password`.

```bash
secenv auth password
```

The password is prompted twice on the terminal and is not accepted as an argument. Only the verifier is written to stdout.

### man
Render the manual pages or markdown help.

```bash
secenv man --out <directory> --format <manpages|markdown>
```

### autocomplete
Generate shell completion scripts.

```bash
secenv autocomplete --out <directory> --shell <bash|zsh|fish|elvish|powershell>
```

### init
Initialize a new config file.

```bash
secenv init [--path <path>] [--force]
```

Notes:
- Creates an example file at `--path` (default: `secenv.conf`) in JSON format.
- The config file can be in JSON or HOCON format (HOCON is a superset of JSON, so both work).
- Review and adapt the generated file to add your `version`, `profiles`, and `vars` as shown in the examples.

## GCP requirements

- Install and authenticate `gcloud` (`gcloud auth login` or service account with suitable permissions).
- Ensure the identity has access to the relevant secrets (e.g., Secret Manager Secret Accessor).
- Accepted secret identifier format: `projects/<project>/secrets/<name>` (optional `/versions/<version>`; defaults to `latest`).

## Troubleshooting

- "Profile '<name>' not found": Verify `profiles.<name>` exists in the config.
- "Failed to parse HOCON config": Validate HOCON syntax and file path.
- "File '<path>' already exists": A temporary file conflicts with an existing file. Use `--force` to replace it temporarily and restore it afterward.
- GCP access errors: Check `gcloud` authentication, project, permissions, and secret name.
- PGP decryption errors: Ensure the private key is valid ASCII‑armored and corresponds to the message.
- Sealed value errors: Ensure each marker uses `ENC[PGP,<base64>]` or `ENC[ARGON2ID-XCHACHA20-POLY1305,<base64>]` and matches its file or profile-variable configuration.
- System authentication errors: `auth.system` requires an interactive prompt for the current user. It cannot be skipped with a piped password. On macOS, enter that user's password in the system dialog when Touch ID is unavailable. On Linux, the `sudo` PAM stack must be installed and `/dev/tty` must be available.
- Profile password errors: Generate the verifier with `secenv auth password` and quote it in HOCON. Pass the same password with `--password` or at the prompt. A password passed to a profile that does not set `auth.password` is rejected.
- File cleanup errors: Cleanup failures are reported as command failures and retried when the file manager is dropped.

## Testing

```
cargo run -- unlock -- env
```

The password for all private keys for testing is `test`.

## Contributing

### Development

```bash
git clone https://github.com/cchexcode/secenv
cd secenv
cargo build
cargo test
```

## License

MIT – see [LICENSE](../LICENSE).

## Related projects

- [sops](https://github.com/mozilla/sops)
- [age](https://github.com/FiloSottile/age)
- [pass](https://www.passwordstore.org/)
