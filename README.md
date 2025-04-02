# File Locker Application

A secure GUI application for file encryption/decryption using Fernet symmetric encryption.

![image](https://github.com/user-attachments/assets/c1557c02-e019-47cd-98b5-34953f2ae7d9)

## Features

- **File Encryption**
  - Generate secure 256-bit encryption keys
  - Automatic base64 URL-safe key encoding
  - Copy keys to clipboard with one click
  - 50MB maximum file size limit for encryption

- **File Decryption**
  - Paste keys from clipboard (CTRL+V supported)
  - Detailed error messages for:
    - Invalid key formats
    - Decryption failures
    - File size limits (15MB max for decryption)
  - Secure temporary file handling during operations

- **User Interface**
  - Modern dark/light theme (system dependent)
  - Context-aware controls:
    - Right-click context menu in text fields
    - Keyboard shortcuts (CTRL+A/C/V/X)
  - Responsive error feedback
  - File size validation before processing

## Requirements

- Python 3.7+
- Tkinter (usually included with Python)
- [CustomTkinter](https://github.com/TomSchimansky/CustomTkinter)
- [Cryptography](https://cryptography.io/) library

## Installation

1. Install required packages:
```bash
pip install cryptography customtkinter
