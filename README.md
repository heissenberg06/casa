# Casa — Offline Password Vault

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org)
[![Platform: macOS](https://img.shields.io/badge/platform-macOS-lightgrey.svg)](#)

A minimal, fully offline password manager for macOS. Your credentials never leave
your machine and are stored on disk only as authenticated ciphertext, unlocked by a
single master password that is never saved anywhere.

## Features

- **Zero-knowledge design** — the master password is never stored; the encryption key
  is derived from it on the fly and discarded when the app closes.
- **Strong cryptography** — Argon2id key derivation + AES-256-GCM authenticated encryption.
- **Tamper detection** — any modification to the vault file is detected on open (GCM auth tag).
- **Simple table UI** — accounts, usernames and passwords in columns; passwords masked by default.
- **Clipboard auto-clear** — copied passwords are wiped from the clipboard after 20 seconds.
- **No network code** — genuinely offline; nothing is ever transmitted.

## Security architecture

| Layer | Choice | Why |
|-------|--------|-----|
| Key derivation | Argon2id (128 MB, 4 iterations) | Memory-hard; resistant to GPU/ASIC brute force |
| Encryption | AES-256-GCM | Industry-standard confidentiality **and** integrity |
| Per-vault salt | 16 random bytes | Defeats precomputed (rainbow table) attacks |
| Per-write nonce | 12 random bytes | New nonce on every save (GCM requirement) |
| File permissions | `0600` | Readable/writable only by the owner |

On disk the vault file contains only `salt | nonce | ciphertext | auth tag`. None of these
are useful without the master password. **If the master password is lost, the vault cannot
be recovered — this is intentional; there is no backdoor.**

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
python3 sifre_kasasi.py
```

On first launch you set a master password and a new vault is created. On later launches the
same password unlocks it. The vault is stored at `~/.sifre_kasasi.dat`.

## Security note

This is a personal project, not a professionally audited product. The cryptographic building
blocks (Argon2id, AES-256-GCM) are standard and used via the well-maintained `argon2-cffi` and
`cryptography` libraries — no custom crypto is implemented. Still, for protecting
high-value secrets at scale, prefer an audited tool such as Bitwarden, 1Password or KeePassXC.

## License

Released under the [MIT License](LICENSE).
