<div align="center">

```
███████╗███╗   ██╗ ██████╗██████╗ ██╗   ██╗██████╗ ████████╗
██╔════╝████╗  ██║██╔════╝██╔══██╗╚██╗ ██╔╝██╔══██╗╚══██╔══╝
█████╗  ██╔██╗ ██║██║     ██████╔╝ ╚████╔╝ ██████╔╝   ██║
██╔══╝  ██║╚██╗██║██║     ██╔══██╗  ╚██╔╝  ██╔═══╝    ██║
███████╗██║ ╚████║╚██████╗██║  ██║   ██║   ██║        ██║
╚══════╝╚═╝  ╚═══╝ ╚═════╝╚═╝  ╚═╝   ╚═╝   ╚═╝        ╚═╝
```

**A simple text encryption and decryption tool written in Python**  
*AES Encryption · Terminal · Romanian Coding Community*

![Python](https://img.shields.io/badge/Python-3.x-blue?style=flat-square&logo=python)
![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20Linux%20%7C%20macOS-lightgrey?style=flat-square)
![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)
![pyaes](https://img.shields.io/badge/Library-pyaes-orange?style=flat-square)
![Author](https://img.shields.io/badge/Author-flandreiii-cyan?style=flat-square)
![Community](https://img.shields.io/badge/Community-Romanian%20Coding-blue?style=flat-square)

</div>

---

## 🔐 What is Encrypt?

**Encrypt** is a lightweight Python tool that lets you **encrypt and decrypt text** straight from your terminal using AES encryption. Whether you want to protect a message, a password, or any sensitive piece of text — Encrypt makes it fast and simple.

> 🇷🇴 This tool was made for the **Romanian coding community**.

---

## ✨ Features

- 🔒 **Text encryption** — secure any string with AES
- 🔓 **Text decryption** — recover original text from encrypted data
- ⚡ **Fast and lightweight** — minimal dependencies, runs instantly
- 🖥️ **Terminal based** — simple, clean command line interface
- 🐍 **Pure Python** — easy to read, modify and extend

---

## 📋 Requirements

| Requirement | Details |
|---|---|
| **Python** | 3.x |
| **Library** | `pyaes` |

---

## 🚀 Installation

### Step 1 — Clone the repository
```bash
git clone https://github.com/flandreiii/Encrypt.git
cd Encrypt
```

### Step 2 — Install the required library
```bash
pip install pyaes
```

### Step 3 — Run the tool
```bash
python encrypt.py
```

---

## 🛠️ Usage

```bash
# Run the tool
python encrypt.py
```

Follow the on-screen menu to:
- **Encrypt** a piece of text
- **Decrypt** previously encrypted text

---

## 🔧 Troubleshooting

| Problem | Fix |
|---|---|
| `ModuleNotFoundError: No module named 'pyaes'` | Run `pip install pyaes` |
| `python: command not found` | Make sure Python 3 is installed — try `python3 encrypt.py` |
| Decryption gives wrong output | Make sure you are using the exact same key used during encryption |
| Permission error on Linux/macOS | Try `chmod +x encrypt.py` then run again |

---

## 📁 Project Structure

```
Encrypt/
├── encrypt.py     # Main tool — encryption & decryption logic
├── .gitignore     # Git ignore rules
└── README.md      # This file
```

---

## 🔑 How AES Encryption Works

AES (Advanced Encryption Standard) is one of the most widely used encryption algorithms in the world. It works by taking your plain text and a secret key, and transforming the text into unreadable encrypted data. Only someone with the correct key can reverse the process and recover the original text.

```
Plain text  +  Secret Key  ──►  [ AES ]  ──►  Encrypted text
Encrypted text  +  Secret Key  ──►  [ AES ]  ──►  Plain text
```

---

## 🤝 Contributing

Contributions are welcome, especially from the Romanian coding community!  
Feel free to open an issue or submit a pull request.

Ideas for future features:
- [ ] File encryption support
- [ ] GUI interface
- [ ] Multiple encryption algorithms (RSA, Fernet, etc.)
- [ ] Save encrypted output to a file
- [ ] Password-based key generation

---

## ⚠️ Disclaimer

This tool is intended for **educational purposes**. Always use encryption responsibly. Do not use it to protect highly sensitive or classified data without proper security review.

---

## 📜 License

```
MIT License

Copyright (c) 2026 flandreiii

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
```

---

<div align="center">

**Made by [flandreiii](https://github.com/flandreiii) 🇷🇴**

*Encrypt — keep your text safe, one key at a time 🔐*

</div>
