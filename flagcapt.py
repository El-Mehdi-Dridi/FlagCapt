import sys
import base64
import requests
from Crypto.Util.number import *
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
from tqdm import tqdm
import time
import argparse
import gmpy2
from libnum import n2s
import owiener
from bs4 import BeautifulSoup
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from concurrent.futures import ThreadPoolExecutor, as_completed


def show_loading_bar():
    ascii_art ="""
            ███████╗██╗      █████╗   ██████╗         ██████╗  █████    ██████╗ ████████╗
            ██╔════╝██║     ██╔══██╗ ██╔════╝        ██╔════╝ ██╔══██╗  ██╔══██╗╚══██╔══╝
            █████╗  ██║     ███████║ ██║  ███╗       ██║      ███████║  ██████╔╝   ██║
            ██╔══╝  ██║     ██╔══██║ ██║   ██║       ██║      ██╔══██║  ██╔═══╝    ██║   
            ██║     ███████╗██║  ██║ ╚██████╔╝       ╚██████╗ ██║  ██╔  ██║        ██║  
            ╚═╝     ══════╝╚═╝  ╚═╝   ╚═════╝         ╚═════╝  ═╝  ╚═╝  ╚═╝        ╚═╝     
            ・┆✦ʚ♡ɞ✦ ┆・ Fl4gC4pt by 1DH4M ・┆✦ʚ♡ɞ✦ ┆・
"""


    print(ascii_art)
    for i in tqdm(range(10), desc="[*] Just Wait H4CK3R ☆.𓋼𓍊 𓆏 𓍊𓋼𓍊.☆ ", ncols=80,  bar_format="{l_bar}{bar} {percentage:3.0f}%"):
        time.sleep(0.05)

def rsa_decrypt(e, p, q, c):
    n = p * q
    phi = (p - 1) * (q - 1)
    d = pow(e, -1, phi)
    flag = pow(c, d, n)
    return long_to_bytes(flag)


def factorize(n, poll_attempts=40, poll_interval=0.5, http_retries=2, 
             backoff_factor=0.2, max_workers=2, verbose=False):
    API_URL = "http://factordb.com/api"
    session = requests.Session()
    retry = Retry(
        total=http_retries,
        backoff_factor=backoff_factor,
        status_forcelist=[429, 500, 502, 503, 504]
    )
    adapter = HTTPAdapter(max_retries=retry, pool_connections=5, pool_maxsize=5)
    session.mount("http://", adapter)

    def query(x):
        r = session.get(API_URL, params={"query": x}, timeout=5)
        r.raise_for_status()
        return r.json()

    raw = None
    for i in range(poll_attempts):
        try:
            data = query(n)
            if data and "factors" in data and len(data["factors"]) >= 2:
                first_two = data["factors"][:2]
                if all(f[0].isdigit() for f in first_two):
                    raw = [int(f[0]) for f in first_two]
                    break
        except Exception:
            pass
        
        if verbose:
            print(f"[poll {i+1}/{poll_attempts}] Waiting...")
        time.sleep(poll_interval)
    else:
        return None, None

    final = []
    with ThreadPoolExecutor(max_workers=max_workers) as ex:
        futures = {ex.submit(query, f): f for f in raw}
        for fut in as_completed(futures):
            base = futures[fut]
            try:
                sub = fut.result()
                fr = sub.get("factors", [])
                if len(fr) > 1 and all(x[0].isdigit() for x in fr):
                    final.extend(int(x[0]) for x in fr)
                else:
                    final.append(base)
            except Exception:
                final.append(base)

    return tuple(sorted(final)) if len(final) == 2 else (None, None)




def low_exponent_attack(n, e, c):
    
    orig = c
    while True:
        m = gmpy2.iroot(c, e)[0]  
        if pow(m, e, n) == orig:  
            return n2s(int(m))    
        c += n

def wiener_attack(e, n, c):
    d = owiener.attack(e, n)
    if d:
        m = pow(c, d, n)
        return long_to_bytes(m).decode()
    else:
        return "Wiener's Attack failed."


def caesar_cipher_decrypt(encrypted_text, shift):
    decrypted_text = ""
    for char in encrypted_text:
        if char.isalpha():
            if char.islower():
                decrypted_text += chr((ord(char) - shift - ord('a')) % 26 + ord('a'))
            elif char.isupper():
                decrypted_text += chr((ord(char) - shift - ord('A')) % 26 + ord('A'))
        else:
            decrypted_text += char
    return decrypted_text

def aes_decrypt(key, iv, ciphertext_hex, mode='CBC'):
    try:
        key_bytes = bytes.fromhex(key) if all(c in '0123456789abcdefABCDEF' for c in key) else key.encode()
        iv_bytes = bytes.fromhex(iv) if all(c in '0123456789abcdefABCDEF' for c in iv) else iv.encode()
        ciphertext = bytes.fromhex(ciphertext_hex)

        if mode == 'CBC':
            cipher = AES.new(key_bytes, AES.MODE_CBC, iv_bytes)
        elif mode == 'ECB':
            cipher = AES.new(key_bytes, AES.MODE_ECB)
        else:
            return f"Unsupported AES mode: {mode}"

        decrypted = cipher.decrypt(ciphertext)

        try:
            decrypted = unpad(decrypted, AES.block_size)
            return f"AES Decrypted: {decrypted.decode()}"
        except:
            return f"AES Decrypted (no padding): {decrypted}"

    except Exception as e:
        return f"AES Decryption Error: {e}"

def xor_cipher(key, encrypted_text, part=None, bruteforce=False):
   
    if bruteforce:
       
        encrypted_bytes = bytes.fromhex(encrypted_text) if all(c in '0123456789abcdefABCDEF' for c in encrypted_text) else encrypted_text.encode()

       
        results = []
        for i in range(0x00, 0x100):  
            key_bytes = bytes([i]) * len(encrypted_bytes)
            flag = b''
            for q, w in zip(encrypted_bytes, key_bytes):
                flag += bytes([q ^ w])
            if part and part.encode() in flag:  
                results.append(f"Key: {i:02x}, Result (with part): {flag.decode(errors='ignore')}")
            elif not part:  
                results.append(f"Key: {i:02x}, Result: {flag.decode(errors='ignore')}")

        
        for result in results:
            print(result)

        return "Brute force completed."

    elif key:
        if len(key) == 1:
            key = f"0{key}"

        key_bytes = bytes.fromhex(key) if all(c in '0123456789abcdefABCDEF' for c in key) else key.encode()
        decrypted_text = ""
        for i in range(len(encrypted_text)):
            decrypted_text += chr(ord(encrypted_text[i]) ^ key_bytes[i % len(key_bytes)])
        return f"XOR Cipher Decrypted: {decrypted_text}"

    elif part:

        enc_bytes = encrypted_text.encode()
        part_bytes = part.encode()
        key = enc_bytes[0] ^ part_bytes[0]
        flag = b''
        for byte in enc_bytes:
            flag += bytes([byte ^ key])
        return f"Recovered Flag: {flag.decode()}"

    else:
        return "Error: Provide either a key (-k), a known part (--part), or use --bruteforce."


def rot13_cipher(text):
    result = ""
    for char in text:
        if char.isalpha():
            shift = 13
            if char.islower():
                result += chr((ord(char) - ord('a') + shift) % 26 + ord('a'))
            else:
                result += chr((ord(char) - ord('A') + shift) % 26 + ord('A'))
        else:
            result += char
    return result

def decode_base64(encoded):
    try:
        return base64.b64decode(encoded).decode()
    except Exception as e:
        return f"Base64 Decode Error: {e}"
def vigenere_cipher_decrypt(encrypted_text, key):
    decrypted_text = ""
    key_length = len(key)
    key_index = 0
    
    for char in encrypted_text:
        if char.isalpha():
            shift = ord(key[key_index % key_length].lower()) - ord('a')
            if char.islower():
                decrypted_text += chr((ord(char) - shift - ord('a')) % 26 + ord('a'))
            elif char.isupper():
                decrypted_text += chr((ord(char) - shift - ord('A')) % 26 + ord('A'))
            key_index += 1
        else:
            decrypted_text += char
    
    return decrypted_text
    
def reverse_decrypt(text):
    return text[::-1]

def binary_to_string(binary_string):
    try:
        chars = binary_string.split()
        return ''.join([chr(int(b, 2)) for b in chars])
    except:
        return "Invalid binary input (use space between each byte)."

def hex_to_string(hex_string):
    try:
        return bytes.fromhex(hex_string).decode()
    except:
        return "Invalid hex input."


def ascii_to_string(ascii_input):
    try:
        numbers = ascii_input.split()
        return ''.join([chr(int(n)) for n in numbers])
    except:
        return "Invalid ASCII input (use space between codes)."



def main():
    show_loading_bar()
    parser = argparse.ArgumentParser(formatter_class=argparse.RawTextHelpFormatter)
    parser.add_argument("method", help=(
        "Decryption method to use. Supported methods:\n"
        "  - rsa: RSA decryption\n"
        "  - factor: Factorize a number\n"
        "  - xor: XOR decryption\n"
        "  - cesar: Caesar cipher decryption\n"
        "  - rot13: ROT13 cipher decryption\n"
        "  - aes: AES decryption\n"
        "  - base64: Base64 decoding\n"
        "  - binary: Binary to string conversion\n"
        "  - hex: Hexadecimal to string conversion\n"
        "  - ascii: ASCII to string conversion\n"
        "  - vigenere: Vigenere cipher decryption\n"
        "  - reverse: Reverse string decryption\n"
    ))
    parser.add_argument("-n", "--number", help="Modulus (n) for RSA decryption or factorization")
    parser.add_argument("-e", "--exponent", help="Exponent for RSA decryption")  # Ensure this is added only once
    parser.add_argument("-c", "--cipher", help="Cipher text to decrypt")
    parser.add_argument("-f", "--file", help="File containing the cipher text or RSA parameters")
    parser.add_argument("-p", "--prime1", type=int, help="First prime for RSA decryption")
    parser.add_argument("-q", "--prime2", type=int, help="Second prime for RSA decryption")
    parser.add_argument("-s", "--shift", type=int, help="Shift value for Caesar cipher")
    parser.add_argument("-k", "--key", help="Key for AES or XOR decryption")
    parser.add_argument("-i", "--iv", help="Initialization vector for AES decryption")
    parser.add_argument("-m", "--mode", help="Mode for AES decryption (e.g., CBC, ECB)")
    parser.add_argument("--low-exponent-attack", action="store_true", help="Perform low exponent attack on RSA")
    parser.add_argument("--wiener-attack", action="store_true", help="Perform Wiener's Attack on RSA")
    parser.add_argument("--bruteforce", action="store_true", help="Perform XOR brute force decryption")
    parser.add_argument("--prefix", help="Known prefix of the flag for XOR decryption")
    args = parser.parse_args()

    def parse_input(value):
        if value.startswith("0x"):
            return int(value, 16)
        return int(value)

    if args.file:
        try:
            with open(args.file, "r") as file:
                for line in file:
                    line = line.strip()
                    if line.startswith("n ="):
                        args.number = int(line.split("=", 1)[1].strip(), 0)
                    elif line.startswith("e ="):
                        args.exponent = int(line.split("=", 1)[1].strip(), 0)
                    elif line.startswith("c ="):
                        args.cipher = int(line.split("=", 1)[1].strip(), 0)
                    elif line.startswith("p ="):
                        args.prime1 = int(line.split("=", 1)[1].strip(), 0)
                    elif line.startswith("q ="):
                        args.prime2 = int(line.split("=", 1)[1].strip(), 0)
                    else:
                        args.cipher = line.strip()
        except Exception as ex:
            print(f"Error reading file: {ex}")
            return

    try:

        if args.method == "factor":
            if args.number is None:
                print("Usage: python tool.py factor -n <number>")
                return
            args.number = parse_input(str(args.number))
            p, q = factorize(args.number)
            if p and q:
                print(f"[*] Factors Found: p = {p}, q = {q} [*]")
            else:
                print("Error: Unable to factorize the number.")
        if args.method == "rsa":
            if args.number:
                args.number = parse_input(str(args.number))
            if args.exponent:
                args.exponent = parse_input(str(args.exponent))
            if args.cipher:
                args.cipher = parse_input(str(args.cipher))

            if args.wiener_attack:
                if args.number is None or args.exponent is None or args.cipher is None:
                    print("Usage: python tool.py rsa -n <modulus> -e <exponent> -c <cipher_text> --wiener-attack")
                    return
                decrypted = wiener_attack(args.exponent, args.number, args.cipher)
                print(f"[*] Flag Found: {decrypted} [*]")

            elif args.low_exponent_attack:
                if args.number is None or args.exponent is None or args.cipher is None:
                    print("Usage: python tool.py rsa -n <modulus> -e <exponent> -c <cipher_text> --low-exponent-attack")
                    return
                decrypted = low_exponent_attack(args.number, args.exponent, args.cipher)
                print(f"[*] Flag Found: {decrypted} [*]")

            elif args.prime1 is not None and args.prime2 is not None:
                if args.exponent is None or args.cipher is None:
                    print("Usage: python tool.py rsa -e <exponent> -p <prime1> -q <prime2> -c <cipher_text>")
                    return
                args.number = args.prime1 * args.prime2
                decrypted = rsa_decrypt(args.exponent, args.prime1, args.prime2, args.cipher)
                print(f"[*] Flag Found: {decrypted.decode()} [*]")

            elif args.number is not None and args.exponent is not None and args.cipher is not None:
                p, q = factorize(args.number)
                if p is None or q is None:
                    print("Error: Unable to factorize n into two prime factors.")
                    return
                
                print(f"[CALCULATING P] {p}")
                print(f"[CALCULATING q] {q}")
                decrypted = rsa_decrypt(args.exponent, p, q, args.cipher)
                print(f"[*] Flag Found: {decrypted.decode()} [*]")

            else:
                print("Usage: python tool.py rsa -n <modulus> -e <exponent> -c <cipher_text>")
                return

        # Handle other decryption methods
        elif args.method == "xor":
            if args.cipher is None:
                print("Usage: python tool.py xor -c <cipher_text> [-k <key>] [--part <known_part>] [--bruteforce]")
                return
            result = xor_cipher(args.key, args.cipher, args.prefix, args.bruteforce)
            print(f"[*] Flag Found: {result} [*]")

        elif args.method == "cesar":
            if args.shift is None or args.cipher is None:
                print("Usage: python tool.py cesar -s <shift> -c <cipher_text>")
                return
            decrypted = caesar_cipher_decrypt(args.cipher, args.shift)
            print(f"[*] Flag Found: {decrypted} [*]")

        elif args.method == "rot13":
            if args.cipher is None:
                print("Usage: python tool.py rot13 -c <cipher_text>")
                return
            decrypted = rot13_cipher(args.cipher)
            print(f"[*] Flag Found: {decrypted} [*]")

        elif args.method == "aes":
            if args.key is None or args.iv is None or args.cipher is None or args.mode is None:
                print("Usage: python tool.py aes -k <key> -i <iv> -c <ciphertext_hex> -m <mode>")
                return
            decrypted = aes_decrypt(args.key, args.iv, args.cipher, args.mode.upper())
            print(f"[*] Flag Found: {decrypted} [*]")

        elif args.method == "base64":
            if args.cipher is None:
                print("Usage: python tool.py base64 -c <encoded_text>")
                return
            decrypted = decode_base64(args.cipher)
            print(f"[*] Flag Found: {decrypted} [*]")

        elif args.method == "binary":
            if args.cipher is None:
                print("Usage: python tool.py binary -c <binary_sequence>")
                return
            decrypted = binary_to_string(args.cipher)
            print(f"[*] Flag Found: {decrypted} [*]")

        elif args.method == "hex":
            if args.cipher is None:
                print("Usage: python tool.py hex -c <hex_string>")
                return
            decrypted = hex_to_string(args.cipher)
            print(f"[*] Flag Found: {decrypted} [*]")

        elif args.method == "ascii":
            if args.cipher is None:
                print("Usage: python tool.py ascii -c <ascii_codes>")
                return
            decrypted = ascii_to_string(args.cipher)
            print(f"[*] Flag Found: {decrypted} [*]")

        elif args.method == "vigenere":
            if args.key is None or args.cipher is None:
                print("Usage: python tool.py vigenere -k <key> -c <cipher_text>")
                return
            decrypted = vigenere_cipher_decrypt(args.cipher, args.key)
            print(f"[*] Flag Found: {decrypted} [*]")

        elif args.method == "reverse":
            if args.cipher is None:
                print("Usage: python tool.py reverse -c <cipher_text>")
                return
            decrypted = reverse_decrypt(args.cipher)
            print(f"[*] Flag Found: {decrypted} [*]")

        else:
            print("Invalid method. Use one of the supported methods.")
    except Exception as ex:
        print(f"Error: {ex}")


if __name__ == "__main__":
    main()
