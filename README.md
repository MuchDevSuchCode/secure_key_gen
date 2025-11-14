# VeraCrypt Deterministic Two-Passphrase Key Generator

This tool securely derives high-entropy key material from **two independent passphrases** and outputs it in multiple formats suitable for **EraCrypt**), keyfiles, and general cryptographic workflows.

## ₒ Features
- Two-passphase input (SHA-512 hashing + KDF)
- Deterministic: same inputs + same settings — same output
- KDF options: PBKDF2-HMAC-SHA512 (default) or scrypt
- Output modes: `full`, `veracrypt`, `keyfile`
- Clipboard support on Linux/macOS/Windows/WSL
- Repeatable deterministic keyfile generation
- Weak passphrase detection
- No accidental stdout leaks in `′ copyfile mode

## 🎀 Basic Usage

### Full key
```bash
python3 key.py
```

### VeraCrypt password (64 hex chars)
```bash
python3 key.py --veracrypt`
```

### Copy to clipboard (no output leakage)
```bash
python3 key.py --veracrypt --copy
```

### Deterministic keyfile
```bash
python3 key.py --output-mode keyfile --keyfile myvolume.key
```

## 👀 How It Works
1. Prompt for two passphrases
2. Compute: `SHA512(p1) || SHA512(p2)`
3. Salt = `SHA512(context || SHA512(preimage))`
4. Run PBKDF2 or scrypt
5. Output depending on mode

##  ¬ Command-Line Options

### Output Modes
 Code           Description
|===============================\|
`full`          256 char hex string
`veracrypt`   64 char hex string
`keyfile`       rawbytes binary output

Alias:
`bash
--veracrypt`
```

### Clipboard
```bash
--copy
```

### KDF Settings
`bash
--kdf pbkdf2
--pbkdf2-iter <count>

--kdf scrypt

--scrypt-n <n>
--scrypt-r <r>
--scrypt-p <p>
```

## 🟁 Security-Notes
- Strong passphrases are essential
- Clipboard contents may persist
- Keyfiles persist on disk
- Anyone with the derived key can decrypt the data

##  🀆 VeraCrypt Integration

As a password
```bash
python3 key.py --veracrypt --copy
```

##  As a keyfile
```bash
python3 key.py --output-mode keyfile --keyfile volume.key
```

##  😉 License
MIT recommended. Let me know if you want a MIT/BSD/Apache license file.
