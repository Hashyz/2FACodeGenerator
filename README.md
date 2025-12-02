# 2FA Code Generator

A comprehensive Two-Factor Authentication (2FA) code generator built with Streamlit. Generate TOTP codes instantly, manage multiple accounts, and check password security.

## Features

### Quick 2FA (Default Page)
- Instant code generation - paste a secret key and see your live TOTP code
- No Enter key required - updates as you type
- Real-time countdown timer with progress bar

### Account Management
- Add, edit, and delete 2FA accounts
- Organize accounts by category (Work, Personal, Finance, Social, Gaming, etc.)
- Search and filter accounts
- QR code generation for easy sharing

### Password Breach Checker
- Check if passwords have been exposed in data breaches
- Uses Have I Been Pwned API with k-anonymity (your password never leaves your device)

### Backup & Export
- Export accounts to JSON for backup
- Import accounts from backup files
- Merge or replace existing accounts

### How It Works
- Educational section explaining TOTP algorithms
- Live demo showing code generation process

## Tech Stack

- **Framework**: Streamlit
- **TOTP Library**: pyotp
- **QR Codes**: qrcode, Pillow
- **Password Checking**: Have I Been Pwned API
- **Live 2FA**: JavaScript (jsSHA for HMAC-SHA1)

## Installation

```bash
pip install streamlit pyotp qrcode Pillow requests pandas streamlit-autorefresh
```

## Usage

```bash
streamlit run app.py --server.port=5000 --server.address=0.0.0.0 --server.headless=true
```

## Security Notes

- Secrets are stored only in browser session (not on any server)
- Password checking uses k-anonymity model
- Quick 2FA runs entirely in your browser using JavaScript
- Exported backups contain sensitive secret keys - store securely!

## Credits

- Original concept inspired by [Hashyz](https://github.com/Hashyz)
- Uses [jsSHA](https://github.com/Caligatio/jsSHA) for HMAC-SHA1 in browser
- Password breach checking via [Have I Been Pwned](https://haveibeenpwned.com/)

## License

MIT License
