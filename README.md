<div align="center">

# 🚀 GPU Ed25519 Vanity Generator

### CUDA accelerated Ed25519 public key and fingerprint vanity search

Search custom prefixes and suffixes in:

🔑 Ed25519 Public Keys
🔍 SHA256 SSH Fingerprints

Multi-GPU support.

</div>

---

## ✨ Features

* ⚡ CUDA accelerated
* 🖥 Multi-GPU support
* 🎯 Public key prefix matching
* 🎯 Public key suffix matching
* 🔍 SSH fingerprint matching
* 🔐 OpenSSH key export
* 📡 MeshCore compatible export

---

## 📖 Usage

### Fingerprint Search

```bash
ed25519brute_cuda.exe --fingerprint-prefix dead

ed25519brute_cuda.exe --fingerprint-suffix cafe
```

### Public Key Search

```bash
ed25519brute_cuda.exe --pubkey-prefix dead

ed25519brute_cuda.exe --pubkey-suffix beef
```

### Multi-GPU Example

```bash
ed25519brute_cuda.exe ^
  --pubkey-prefix dead ^
  --pubkey-suffix beef ^
  --blocks 256 ^
  --gpu 0,1,2
```

---

## ⚙ Parameters

| Option                 | Description         |
| ---------------------- | ------------------- |
| `--fingerprint-prefix` | Fingerprint prefix  |
| `--fingerprint-suffix` | Fingerprint suffix  |
| `--pubkey-prefix`      | Public key prefix   |
| `--pubkey-suffix`      | Public key suffix   |
| `--blocks`             | CUDA blocks per GPU |
| `--gpu`                | GPU IDs             |

> ⚠ Fingerprint and Public Key modes cannot be combined.

---

## 📸 Example Search

<p align="center">
  <img src="images/example.png" width="100%">
</p>

---

## 📁 Generated Files

```text
found_key.txt
id_ed25519
id_ed25519.pub
```

### found_key.txt contains

* Seed
* Public Key
* SSH Fingerprint
* MeshCore Private Key
* OpenSSH Private Key

---

## 🙏 Credits

Math inspiration:

https://github.com/4equest

CUDA implementation and full project:

https://github.com/c0baca

---

## ☕ Donation

### Bitcoin

```text
1LGsYVdf4uEQn6qvuC145Nu1AgZ3via6wE
```

---

<div align="center">

⭐ If you find this project useful, consider giving it a star ⭐

</div>
