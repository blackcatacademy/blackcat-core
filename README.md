# BlackCat Core — BlackCat\\Store

<p align="left">
  <img src="https://github.com/blackcatacademy/blackcat-core/blob/master/.github/logo.png" alt="BlackCat Core Logo" width="160" />
</p>

**Status:** 🔧 *In Development*

A proprietary set of PHP libraries (libs) built on `libsodium` (`ext-sodium`), serving as the foundational framework (library set) for the e-commerce platform developed by **Black Cat Academy s. r. o.**.

---

## 🧩 Requirements
```json
"require": {
  "php": "^8.1",
  "ext-sodium": "*",
  "psr/simple-cache": "^1.0",
  "psr/log": "^1.1"
}
```

---

## 🚀 Installation
This package is **proprietary** and **not distributed via Packagist**. Installation should be done manually or from the internal Git repository.

```bash
composer install
```

---

## ⚙️ Development Status
This project is currently **under active development**. APIs, internal structure, and interfaces are subject to change without prior notice. Production use is not yet recommended until a stable release is announced.

---

## 🔐 Security Notes
- Uses `ext-sodium`, the standard PHP extension providing access to `libsodium` for secure cryptography.
- Using high-level APIs such as `crypto_aead_*`, `crypto_kdf_*`, etc.
- Never commit production keys or secrets to the repository.
- To report security issues, contact **backcatacademy@protonmail.com**.

---

## 📜 License
This software is **proprietary**. See the [`LICENSE`](./LICENSE) file for full license terms.  
Use, redistribution, or modification is permitted only under the conditions defined by Black Cat Academy s. r. o.

---

© 2025 Black Cat Academy s. r. o.

