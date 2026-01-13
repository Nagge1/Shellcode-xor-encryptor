# Shellcode XOR Encryptor

Detta är ett CLI-verktyg skrivet i Python som XOR-krypterar shellcode för obfuskering. Det används i pentesting för att undvika enkel detektion av antivirus eller andra säkerhetsverktyg. Verktyget krypterar rå shellcode med en XOR-nyckel och producerar output i olika format.

## Installation och krav

- Python 3.x krävs.
- Inga externa bibliotek behövs (använder endast standardbibliotek som `argparse`).

Klona eller ladda ner filen `xorcrypt.py` och placera den i din arbetskatalog.

## Hur man kör det

Kör verktyget från kommandoraden:

```
python xorcrypt.py --in <inputfil> --out <outputfil> --key <nyckel> [--format <format>]
```

### Argument

- `--in`: Sökväg till inputfilen med rå shellcode (binär fil).
- `--out`: Sökväg till outputfilen där krypterad shellcode sparas (binär).
- `--key`: XOR-nyckel. Kan vara hex (t.ex. `0x42`) eller en sträng (t.ex. `"secret"`).
- `--format`: Output-format för visning på skärmen. Alternativ: `raw` (hex-sträng), `python` (lista), `c` (C-array). Standard är `raw`.

## Exempelkommandon

### Exempel 1: Kryptera med hex-nyckel och C-format
```
python xorcrypt.py --in raw.bin --out encrypted.bin --key 0x42 --format c
```

Output på skärmen:
```
unsigned char buf[] = { 0x12, 0xa1, 0x4f, ... };
```

### Exempel 2: Kryptera med strängnyckel och Python-format
```
python xorcrypt.py --in shellcode.bin --out output.bin --key "mykey" --format python
```

Output på skärmen:
```
[0x5a, 0x3b, 0x8f, ...]
```

### Exempel 3: Kryptera och spara som rå binär (standardformat)
```
python xorcrypt.py --in input.bin --out encrypted.bin --key 0xAB
```

Output på skärmen: Hex-sträng av krypterad data.

## Hur man skapar test-shellcode

För att testa verktyget, skapa en enkel binär fil med rå shellcode:

- **Använd Python för att skapa en fil:**
  ```
  python -c "with open('test.bin', 'wb') as f: f.write(bytes([0x90, 0x90, 0xCC]))"
  ```
  Detta skapar `test.bin` med bytes `0x90` (NOP), `0x90`, `0xCC` (INT3).

- **Verifiera filen:** `python -c "with open('test.bin', 'rb') as f: print(f.read().hex())"`

## Verifiering och felsökning

- **Reversibilitet:** XOR är symmetriskt. Kryptera en fil, kryptera resultatet igen med samma nyckel – du bör få tillbaka originalet.
  Exempel:
  ```
  python xorcrypt.py --in original.bin --out enc.bin --key 0x42
  python xorcrypt.py --in enc.bin --out dec.bin --key 0x42
  # dec.bin bör vara identisk med original.bin
  ```

- **Vanliga fel:**
  - "Fel: Inputfil hittades inte" – Kontrollera sökvägen.
  - Ogiltig hex-nyckel – Använd format som `0x42` (inte `42`).
  - Tom nyckel – Ange en giltig nyckel.

## Säkerhet och etik

- Detta verktyg är för **obfuskering**, inte säker kryptering. Används i pentesting för att undvika enkel detektion.
- Använd endast för utbildning och etiska tester. Följ lagar och få tillstånd innan du testar på riktiga system.
- Rekommenderas: Testa i en isolerad VM-miljö.

## Licens

Detta är ett utbildningsprojekt. Använd etiskt och enligt lag.