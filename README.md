# Shellcode XOR Encryptor

This is a CLI tool written in Python that XOR-encrypts shellcode for obfuscation. It is used in penetration testing to avoid simple detection by antivirus or other security tools. The tool encrypts raw shellcode with an XOR key and produces output in various formats.

## Installation and Requirements

- Python 3.x is required.
- No external libraries are needed (uses only standard libraries like `argparse`).

Clone or download the `xorcrypt.py` file and place it in your working directory.

## How to Run It

Run the tool from the command line:

```
python xorcrypt.py --in <inputfile> --out <outputfile> --key <key> [--format <format>]
```

### Arguments

- `--in`: Path to the input file with raw shellcode (binary file).
- `--out`: Path to the output file where encrypted shellcode is saved (binary).
- `--key`: XOR key. Can be hex (e.g., `0x42`) or a string (e.g., `"secret"`).
- `--format`: Output format for display on screen. Options: `raw` (hex string), `python` (list), `c` (C array). Default is `raw`.

## Example Commands

### Example 1: Encrypt with hex key and C format
```
python xorcrypt.py --in raw.bin --out encrypted.bin --key 0x42 --format c
```

Output on screen:
```
unsigned char xored_shellcode[] = { 0x12, 0xa1, 0x4f, ... };
```

### Example 2: Encrypt with string key and Python format
```
python xorcrypt.py --in shellcode.bin --out output.bin --key "mykey" --format python
```

Output on screen:
```
[0x5a, 0x3b, 0x8f, ...]
```

### Example 3: Encrypt and save as raw binary (default format)
```
python xorcrypt.py --in input.bin --out encrypted.bin --key 0xAB
```

Output on screen: Hex string of encrypted data.

## How to Create Test Shellcode

To test the tool, create a simple binary file with raw shellcode:

- **Use Python to create a file:**
  ```
  python -c "with open('test.bin', 'wb') as f: f.write(bytes([0x90, 0x90, 0xC3]))"
  ```
  This creates `test.bin` with bytes `0x90` (NOP), `0x90`, `0xC3` (RET).

- **Verify the file:** `python -c "with open('test.bin', 'rb') as f: print(f.read().hex())"`

## Verification and Troubleshooting

- **Reversibility:** XOR is symmetric. Encrypt a file, then encrypt the result again with the same key – you should get back the original.
  Example:
  ```
  python xorcrypt.py --in original.bin --out enc.bin --key 0x42
  python xorcrypt.py --in enc.bin --out dec.bin --key 0x42
  # dec.bin should be identical to original.bin
  ```

- **Common errors:**
  - "Error: Input file not found" – Check the path.
  - Invalid hex key – Use format like `0x42` (not `42`).
  - Empty key – Provide a valid key.

## Security and Ethics

- This tool is for **obfuscation**, not secure encryption. Used in pentesting to avoid simple detection.
- Use only for educational and ethical testing. Follow laws and obtain permission before testing on real systems.
- Recommended: Test in an isolated VM environment.

## License

This is an educational project. Use ethically and in accordance with the law.
