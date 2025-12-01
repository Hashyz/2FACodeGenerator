# 2FA Code Generator

## Overview
A comprehensive Two-Factor Authentication (2FA) code generator built with Streamlit. This app generates TOTP (Time-based One-Time Password) codes, manages multiple accounts, and includes innovative security features.

## Features
- **TOTP Code Generation**: Generate 6-digit codes that refresh every 30 seconds
- **Account Management**: Add, delete, and organize multiple 2FA accounts
- **QR Code Generation**: Create QR codes for easy account setup on other devices
- **Category Organization**: Group accounts by Work, Personal, Finance, Social, Gaming, etc.
- **Password Breach Checker**: Check if passwords have been exposed in data breaches using Have I Been Pwned API (k-anonymity model)
- **Backup & Export**: Export and import accounts as JSON for backup purposes
- **Educational Section**: Learn how TOTP algorithms work with live demos

## Tech Stack
- **Framework**: Streamlit
- **TOTP Library**: pyotp
- **QR Codes**: qrcode, Pillow
- **HTTP Requests**: requests (for breach checking)
- **Data Handling**: pandas

## Project Structure
```
/
├── app.py              # Main Streamlit application
├── pyproject.toml      # Python dependencies
├── .gitignore          # Git ignore rules
└── replit.md           # This file
```

## Running the App
The app runs on port 5000 with the command:
```bash
streamlit run app.py --server.port=5000 --server.address=0.0.0.0 --server.headless=true
```

## Security Notes
- Secrets are stored only in session state (browser memory)
- Password checking uses k-anonymity (password is never sent over the network)
- Exported backups contain sensitive secret keys - store securely!

## Recent Changes
- Initial build with all core features
- Added password breach checker integration
- Implemented backup/export functionality
- Created educational "How It Works" section
