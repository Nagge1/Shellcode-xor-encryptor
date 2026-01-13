#!/usr/bin/env python3
"""
Shellcode XOR Encryptor

Detta verktyg krypterar shellcode med XOR-nyckel för obfuskering.
Används i pentesting för att undvika enkel detektion.

Användning:
    python xorcrypt.py --in raw.bin --out encrypted.bin --key 0x42 --format c
"""

import argparse
import sys

def xor_encrypt(data: bytes, key: bytes) -> bytes:
    """
    Krypterar data med XOR och en nyckel.

    Args:
        data (bytes): Rå shellcode-data.
        key (bytes): XOR-nyckel (kan vara flera bytes).

    Returns:
        bytes: Krypterad data.
    """
    key_len = len(key)
    encrypted = bytearray()
    for i, byte in enumerate(data):
        encrypted.append(byte ^ key[i % key_len])
    return bytes(encrypted)

def format_output(encrypted: bytes, format_type: str) -> str:
    """
    Formaterar krypterad data för output.

    Args:
        encrypted (bytes): Krypterad data.
        format_type (str): 'raw', 'python', eller 'c'.

    Returns:
        str: Formaterad sträng.
    """
    if format_type == 'raw':
        return encrypted.hex()  # För visning, men sparas som binär
    elif format_type == 'python':
        hex_values = [f'0x{b:02x}' for b in encrypted]
        return f'[{", ".join(hex_values)}]'
    elif format_type == 'c':
        hex_values = [f'0x{b:02x}' for b in encrypted]
        return f'unsigned char buf[] = {{ {", ".join(hex_values)} }};'
    else:
        raise ValueError(f"Okänt format: {format_type}")

def main():
    """
    Huvudfunktion som hanterar argument, kryptering och output.
    """
    parser = argparse.ArgumentParser(description='XOR-kryptera shellcode för obfuskering.')
    parser.add_argument('--in', dest='input_file', required=True,
                        help='Inputfil med rå shellcode (binär).')
    parser.add_argument('--out', dest='output_file', required=True,
                        help='Outputfil för krypterad shellcode.')
    parser.add_argument('--key', required=True,
                        help='XOR-nyckel (hex som 0x42 eller sträng).')
    parser.add_argument('--format', choices=['raw', 'python', 'c'], default='raw',
                        help='Output-format (standard: raw).')

    args = parser.parse_args()

    # Läs input-fil
    try:
        with open(args.input_file, 'rb') as f:
            data = f.read()
    except FileNotFoundError:
        print(f"Fel: Inputfil '{args.input_file}' hittades inte.", file=sys.stderr)
        sys.exit(1)

    # Hantera nyckel: Om det börjar med 0x, behandla som hex, annars som sträng
    if args.key.startswith('0x'):
        try:
            key = bytes.fromhex(args.key[2:])
        except ValueError:
            print(f"Fel: Ogiltig hex-nyckel '{args.key}'.", file=sys.stderr)
            sys.exit(1)
    else:
        key = args.key.encode('utf-8')

    if not key:
        print("Fel: Nyckel kan inte vara tom.", file=sys.stderr)
        sys.exit(1)

    # Kryptera
    encrypted = xor_encrypt(data, key)

    # Spara till output-fil (alltid som binär för raw, men för andra format skriv ut till stdout)
    with open(args.output_file, 'wb') as f:
        f.write(encrypted)

    # Formatera och skriv ut
    formatted = format_output(encrypted, args.format)
    print(formatted)

if __name__ == '__main__':
    main()
