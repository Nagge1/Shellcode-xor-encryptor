#!/usr/bin/env python3
"""
Shellcode XOR Encryptor

This tool encrypts shellcode with an XOR key for obfuscation.
Used in penetration testing to avoid simple detection.

Usage:
    python xorcrypt.py --in raw.bin --out encrypted.bin --key 0x42 --format c
"""

import argparse
import sys

def xor_encrypt(data: bytes, key: bytes) -> bytes:
    """
    Encrypts data with XOR and a key.

    Args:
        data (bytes): Raw shellcode data.
        key (bytes): XOR key (can be multiple bytes).

    Returns:
        bytes: Encrypted data.
    """
    key_len = len(key)
    encrypted = bytearray()
    for i, byte in enumerate(data):
        encrypted.append(byte ^ key[i % key_len])
    return bytes(encrypted)

def format_output(encrypted: bytes, format_type: str) -> str:
    """
    Formats encrypted data for output.

    Args:
        encrypted (bytes): Encrypted data.
        format_type (str): 'raw', 'python', or 'c'.

    Returns:
        str: Formatted string.
    """
    if format_type == 'raw':
        return encrypted.hex()  # For display, but saved as binary
    elif format_type == 'python':
        hex_values = [f'0x{b:02x}' for b in encrypted]
        return f'[{", ".join(hex_values)}]'
    elif format_type == 'c':
        hex_values = [f'0x{b:02x}' for b in encrypted]
        return f'unsigned char buf[] = {{ {", ".join(hex_values)} }};'
    else:
        raise ValueError(f"Unknown format: {format_type}")

def main():
    """
    Main function that handles arguments, encryption, and output.
    """
    parser = argparse.ArgumentParser(description='XOR-encrypt shellcode for obfuscation.')
    parser.add_argument('--in', dest='input_file', required=True,
                        help='Input file with raw shellcode (binary).')
    parser.add_argument('--out', dest='output_file', required=True,
                        help='Output file for encrypted shellcode.')
    parser.add_argument('--key', required=True,
                        help='XOR key (hex like 0x42 or string).')
    parser.add_argument('--format', choices=['raw', 'python', 'c'], default='raw',
                        help='Output format (default: raw).')

    args = parser.parse_args()

    # Read input file
    try:
        with open(args.input_file, 'rb') as f:
            data = f.read()
    except FileNotFoundError:
        print(f"Error: Input file '{args.input_file}' not found.", file=sys.stderr)
        sys.exit(1)

    # Handle key: If it starts with 0x, treat as hex, otherwise as string
    if args.key.startswith('0x'):
        try:
            key = bytes.fromhex(args.key[2:])
        except ValueError:
            print(f"Error: Invalid hex key '{args.key}'.", file=sys.stderr)
            sys.exit(1)
    else:
        key = args.key.encode('utf-8')

    if not key:
        print("Error: Key cannot be empty.", file=sys.stderr)
        sys.exit(1)

    # Encrypt
    encrypted = xor_encrypt(data, key)

    # Save to output file (always as binary for raw, but print formatted for others)
    with open(args.output_file, 'wb') as f:
        f.write(encrypted)

    # Format and print
    formatted = format_output(encrypted, args.format)
    print(formatted)

if __name__ == '__main__':
    main()
