# 🛡️ Fl4gC4pt - CTF Crypto Solver & Decoder Tool

```
            ███████╗██╗      █████╗   ██████╗         ██████╗  █████    ██████╗ ████████╗
            ██╔════╝██║     ██╔══██╗ ██╔════╝        ██╔════╝ ██╔══██╗  ██╔══██╗╚══██╔══╝
            █████╗  ██║     ███████║ ██║  ███╗       ██║      ███████║  ██████╔╝   ██║
            ██╔══╝  ██║     ██╔══██║ ██║   ██║       ██║      ██╔══██║  ██╔═══╝    ██║   
            ██║     ███████╗██║  ██║ ╚██████╔╝       ╚██████╗ ██║  ██╔  ██║        ██║  
            ╚═╝     ══════╝╚═╝  ╚═╝   ╚═════╝         ╚═════╝  ═╝  ╚═╝  ╚═╝        ╚═╝     
            ・┆✦ʚ♡ɞ✦ ┆・ Fl4gC4pt by 1DH4M ・┆✦ʚ♡ɞ✦ ┆・
```

**Fl4gC4pt** is a powerful command-line tool written in Python to help you **decrypt, decode, and solve** various cryptographic challenges often encountered in **Capture The Flag (CTF)** competitions.

---

## ✨ Features

- RSA decryption (manual or automatic factorization via FactorDB)
- AES decryption (CBC/ECB modes)
- XOR bruteforce and known key decryption
- Classical Ciphers: Caesar, ROT13, Vigenère
- Base64 decoding
- Binary, Hex, ASCII conversions
- Reverse strings
- Wiener Attack & Low Exponent RSA Attack

---

## ⚙️ Installation from GitHub Repository

Clone the repository:

```
git clone https://github.com/El-Mehdi-Dridi/Flag-Capt.git
```

Navigate to the flagcapt directory:

```
cd FlagCapt
```

Install the required Python packages:

```
pip install -r requirements.txt
```

> ⚠️ Python 3.6+ is required.

---

## Usage

Run the tool via CLI:

```bash
python flagcapt.py <method> -[options]
```

```
python flagcapt.py --help                         

            ███████╗██╗      █████╗   ██████╗         ██████╗  █████    ██████╗ ████████╗
            ██╔════╝██║     ██╔══██╗ ██╔════╝        ██╔════╝ ██╔══██╗  ██╔══██╗╚══██╔══╝
            █████╗  ██║     ███████║ ██║  ███╗       ██║      ███████║  ██████╔╝   ██║
            ██╔══╝  ██║     ██╔══██║ ██║   ██║       ██║      ██╔══██║  ██╔═══╝    ██║   
            ██║     ███████╗██║  ██║ ╚██████╔╝       ╚██████╗ ██║  ██╔  ██║        ██║  
            ╚═╝     ══════╝╚═╝  ╚═╝   ╚═════╝         ╚═════╝  ═╝  ╚═╝  ╚═╝        ╚═╝     
            ・┆✦ʚ♡ɞ✦ ┆・ Fl4gC4pt by 1DH4M ・┆✦ʚ♡ɞ✦ ┆・

[*] Just Wait H4CK3R ☆.𓋼𓍊 𓆏 𓍊𓋼𓍊.☆ : 100%|██████████████████████████████████ 100%
usage: flagcapt.py [-h] [-n NUMBER] [-e EXPONENT] [-c CIPHER] [-f FILE] [-p PRIME1] [-q PRIME2] [-s SHIFT] [-k KEY] [-i IV] [-m MODE] [--low-exponent-attack] [--wiener-attack] [--bruteforce] [--prefix PREFIX] method

positional arguments:
  method                Decryption method to use. Supported methods:
                          - rsa: RSA decryption
                          - factor: Factorize a number
                          - xor: XOR decryption
                          - cesar: Caesar cipher decryption
                          - rot13: ROT13 cipher decryption
                          - aes: AES decryption
                          - base64: Base64 decoding
                          - binary: Binary to string conversion
                          - hex: Hexadecimal to string conversion
                          - ascii: ASCII to string conversion
                          - vigenere: Vigenere cipher decryption
                          - reverse: Reverse string decryption

options:
  -h, --help            show this help message and exit
  -n, --number NUMBER   Modulus (n) for RSA decryption or factorization
  -e, --exponent EXPONENT
                        Exponent for RSA decryption
  -c, --cipher CIPHER   Cipher text to decrypt
  -f, --file FILE       File containing the cipher text or RSA parameters
  -p, --prime1 PRIME1   First prime for RSA decryption
  -q, --prime2 PRIME2   Second prime for RSA decryption
  -s, --shift SHIFT     Shift value for Caesar cipher
  -k, --key KEY         Key for AES or XOR decryption
  -i, --iv IV           Initialization vector for AES decryption
  -m, --mode MODE       Mode for AES decryption (e.g., CBC, ECB)
  --low-exponent-attack
                        Perform low exponent attack on RSA
  --wiener-attack       Perform Wiener's Attack on RSA
  --bruteforce          Perform XOR brute force decryption
  --prefix PREFIX       Known prefix of the flag for XOR decryption

```

### Common Arguments

| Option            | Description                          |
|-------------------|--------------------------------------|
| `-c`, `--cipher`  | Cipher text or encoded input         |
| `-k`, `--key`     | Key for AES, XOR, or Vigenère        |
| `-s`, `--shift`   | Shift for Caesar cipher              |
| `-n`, `--number`  | RSA modulus `n`                      |
| `-e`, `--exponent`| RSA exponent `e`                     |
| `-p`, `--prime1`  | Prime `p` (for RSA)                  |
| `-q`, `--prime2`  | Prime `q` (for RSA)                  |
| `-i`, `--iv`      | Initialization vector for AES        |
| `-f`, `--file`    | Read cipher text from file           |
| `--low-exponent-attack`| Low exponent RSA attack (e = 3) |
|`--wiener-attack`  | Wiener attack on RSA                 |

---

## Available Methods

| Method       | Description                             |
|--------------|-----------------------------------------|
| `rsa`        | Decrypt RSA using p, q, e, and cipher   |
| `factor`     | Get p & q from n via FactorDB           |
| `xor`        | XOR decryption (with key or bruteforce) |
| `cesar`      | Caesar cipher decryption                |
| `rot13`      | ROT13 decoder                           |
| `aes`        | AES CBC/ECB decryption                  |
| `base64`     | Decode base64 strings                   |
| `binary`     | Binary to string                        |
| `hex`        | Hex to string                           |
| `ascii`      | ASCII values to string                  |
| `vigenere`   | Vigenère decryption                     |
| `reverse`    | Reverse the string                      |

---

## 📌 Examples

## RSA Decryption

### Typical RSA
```bash
python flagcapt.py rsa -e 65537 -c 15752613524540611205355101441647970957140019284625297899850 -n 37400945029259002357443060764390969896841289525047883637759
[*] Just Wait H4CK3R ☆.𓋼𓍊 𓆏 𓍊𓋼𓍊.☆ : 100%|██████████████████████████████████ 100%
[CALCULING P] 82350732498477128986705241687
[CALCULING q] 454166513090222231786915976857
[*] Flag Found [*]: Flag{Fl4g_C4pT_by_1DH4M} [*]
```

### Wiener Attack
```bash
python flagcapt.py rsa -n < modulus > -e <exponent> -c <cipher> --wiener-attack
```
### Low Exponent Attack
```
python flagcapt.py rsa -f rsa.txt --low-exponent-attack                                             
```
## XOR Decryption
### with known key

```bash
python flagcapt.py xor -c "ciphertext_here" -k "key"
```
### with known perfix
```
python flagcapt.py xor -f flag.txt --prefix "prefix"
```
### BruteForce
```
python flagcapt.py  xor -f flag.txt --bruteforce 
```

## AES Decryption 

### CBC mode

```bash
python flagcapt.py  aes -c "cipher" -k "key" -i "iv" --mode CBC
```
### ECB mode

```bash
python flagcapt.py  aes -c "cipher" -k "key" -i "iv" --mode CBC
```


# 👨‍💻 Author

Created by **1DH4M**  on 04/2025
