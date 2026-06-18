# Casa — Offline Password Vault

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org)
[![Platform: macOS](https://img.shields.io/badge/platform-macOS-lightgrey.svg)](#)

A minimal, fully offline password manager for macOS. Your credentials never leave
your machine and are stored on disk only as authenticated ciphertext, unlocked by a
single master password that is never saved anywhere.

## Features

- **Zero-knowledge design** — the master password is never stored; the encryption key
  is derived from it on the fly and discarded when the app closes or locks.
- **Strong cryptography** — Argon2id (256 MB) key derivation + AES-256-GCM authenticated encryption.
- **In-memory encryption** — after the vault is unlocked, individual passwords are
  re-encrypted with a random session key (AES-256-GCM); they never sit as plaintext
  Python strings in memory. Only account names and usernames are kept in plaintext for display.
- **Swap protection** — the disk key and the session key are held in `mlock`-pinned
  buffers (`SecureBuffer`) and zeroed out with `ctypes.memset` on lock/close.
- **Auto-lock** — the vault locks automatically after 5 minutes of inactivity.
  The session key and all decrypted data are wiped from memory on lock.
- **Brute-force protection** — wrong password attempts trigger an exponential
  back-off delay: 2 s, 4 s, 8 s … up to 60 s.
- **Password strength check** — new master passwords are evaluated with `zxcvbn`
  (pattern-matching, dictionary, keyboard-walk detection); weak passwords require confirmation.
- **Tamper detection** — any modification to the vault file is detected on open (GCM auth tag).
- **Clipboard auto-clear** — copied passwords are wiped from the clipboard after 15 seconds.
- **Vault format versioning** — a magic header + version byte allows safe format migrations.
- **Atomic writes** — vault is written to a `.tmp` file (created with `0o600` permissions
  from the start) then atomically renamed, preventing partial writes from corrupting data.
- **No network code** — genuinely offline; nothing is ever transmitted.

## Security architecture

| Layer | Choice | Why |
|-------|--------|-----|
| Key derivation | Argon2id (256 MB, 4 iterations, 4 threads) | Memory-hard; resistant to GPU/ASIC brute force |
| Disk encryption | AES-256-GCM | Industry-standard confidentiality **and** integrity |
| In-memory encryption | AES-256-GCM (random session key) | Passwords never in plaintext RAM outside of brief copy/edit operations |
| Session key storage | `SecureBuffer` (`mlock` + `ctypes.memset`) | Prevents key from being swapped to disk; zeroed on lock/close |
| Per-vault salt | 16 random bytes | Defeats precomputed (rainbow table) attacks |
| Per-write nonce | 12 random bytes | New nonce on every save (GCM requirement) |
| File permissions | `0o600` from creation | Readable/writable only by the owner; no race window |
| Vault format | `MAGIC(4) \| VERSION(1) \| salt \| nonce \| ciphertext` | Version byte enables future migrations; magic prevents misidentification |

On disk the vault file contains only a magic header, version byte, salt, nonce, and ciphertext.
None of these are useful without the master password. **If the master password is lost, the vault
cannot be recovered — this is intentional; there is no backdoor.**

## Installation

```bash
git clone https://github.com/heissenberg06/casa.git
cd casa

python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

## Usage

```bash
source venv/bin/activate   # if not already active
python3 casa.py
```

On first launch you set a master password and a new vault is created. On later launches the
same password unlocks it. The vault is stored at `~/.sifre_kasasi.dat`.

## Dependencies

| Package | Purpose |
|---------|---------|
| `argon2-cffi` | Argon2id key derivation |
| `cryptography` | AES-256-GCM encryption |
| `zxcvbn` | Realistic master-password strength estimation |

## Security note

This is a personal project, not a professionally audited product. The cryptographic building
blocks (Argon2id, AES-256-GCM) are standard and used via the well-maintained `argon2-cffi` and
`cryptography` libraries — no custom crypto is implemented. Still, for protecting
high-value secrets at scale, prefer an audited tool such as Bitwarden, 1Password or KeePassXC.

## License

Released under the [MIT License](LICENSE).
