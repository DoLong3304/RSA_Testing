# RSA Cryptography Tool

A simple (academic) RSA key generation, file encryption/decryption, and testing toolkit written in C using GMP.

> IMPORTANT: This project is for academic / instructional purposes only. It omits critical production-security features (e.g. padding schemes like OAEP, side‑channel mitigations, secure randomness quality control, hardened prime generation, constant-time operations, key storage protections). Do NOT use it for real-world protection of sensitive data.

## Table of Contents
1. Overview & Disclaimer
2. How the Algorithm Works
3. Key & Cipher File Formats
4. Features Summary
5. Building the Project
6. Platform Setup (macOS, Linux, Windows / WSL / MSYS2 / Cygwin)
7. IDE Setup (VS Code & CLion)
8. Usage Examples (Basic, Advanced, Testing)
9. Troubleshooting & FAQs
10. Academic Limitations & Possible Extensions
11. License

---
## 1. Overview & Disclaimer
This tool implements core RSA operations: key generation, raw (unpadded) modular exponentiation for encryption/decryption, and several test utilities (speed, integrity, naive brute force). The design intentionally keeps the code approachable for study. The implementation trades completeness and security for clarity.

---
## 2. How the Algorithm Works
### 2.1 Key Generation
1. Choose a target modulus bit length B (e.g. 2048). Split approximately in half for each prime: p_bits ≈ B/2, q_bits ≈ B/2.
2. Generate prime p:
   - Produce a random number of p_bits using `mpz_urandomb`.
   - Force the high bit to ensure size (`mpz_setbit`).
   - Call `mpz_nextprime` to advance to the next prime.
3. Generate prime q the same way, retrying if q == p.
4. Compute modulus: n = p * q.
5. Compute Euler's totient: φ(n) = (p - 1) * (q - 1).
6. Public exponent e selection:
   - Randomly sample candidates in (2, φ - 1).
   - Require gcd(e, φ) = 1.
   - Compute modular inverse d = e⁻¹ mod φ.
   - Accept the first invertible e (no bit-length constraint between e and d).
7. Output public key (n, e) and private key (n, d) as hex values.

### 2.2 Encryption (Raw / Unpadded)
For a file:
1. Determine key byte length: `key_bytes = ceil(bitlen(n)/8)`.
2. Use chunk size = key_bytes - 1 (very naive; ensures message < n).
3. For each chunk:
   - Import bytes into big integer m (`mpz_import`).
   - Compute c = m^e mod n.
   - Write ciphertext block as lowercase hexadecimal followed by newline.

### 2.3 Decryption
1. Read each hex line into big integer c.
2. Compute m = c^d mod n.
3. Export m back to raw bytes (`mpz_export`) and append to plaintext output.

### 2.4 Integrity Test
Encrypt then decrypt a target file with a given key size (or the latest). A byte-by-byte compare plus optional SHA-256 hashing confirms round-trip fidelity.

### 2.5 Speed Benchmark
Generates temporary keys for each power-of-two bit size in a range; measures encryption and decryption wall-clock time plus the size of the produced ciphertext.

### 2.6 Naive Brute Force Demo
Attempts factoring of n using selectable algorithms:
- `auto` (default): tries Pollard’s p−1 (small bounds), then Pollard’s Rho (Floyd), then falls back to trial division.
- `rho`: Pollard’s Rho with Floyd cycle detection.
- `p1`: Pollard’s p−1 with small smoothness bound (fast if p−1 is B-smooth).
- `trial`: naive trial division (slow, worst case).
Each key size attempt is time-limited.
- Default per-key time limit: `LIMIT_SECONDS` (defined in `test_module.h`, default 600 seconds).
- You can override via CLI or interactive mode (details below).
- On success, reconstruct φ and d, then verify by decrypting a test sample; otherwise prints a timeout result.

### 2.7 Security Notes
- No padding: Vulnerable to textbook RSA attacks (deterministic, malleable, structure leaks). 
- Randomness: Uses time-seeded default GMP RNG — insufficient for secure cryptography.
- Prime generation: Relies solely on `mpz_nextprime` (not a provable or hardened process against adversarial manipulation).
- Side channels: Timing and memory access patterns are not protected.

---
## 3. Key & Cipher File Formats
### 3.1 Public / Private Key Files
Each key file contains two lines (hexadecimal, lowercase):
```
<n in hex>
<e in hex>   # for public_X.key
```
```
<n in hex>
<d in hex>   # for private_X.key
```
### 3.2 Ciphertext Files
Each line is one encrypted block: hex representation of `m^e mod n`. No headers, no versioning, no salt.

### 3.3 Plaintext Output Naming
- Encryption: `original.ext` → `original.ext.dat`
- Decryption: `original.ext.dat` → `original_decrypted.ext`

---
## 4. Features Summary
- Arbitrary bit-length key generation (no enforced minimum beyond >0).
- Automatic key storage under `keys/` using `public_<bits>.key`, `private_<bits>.key`.
- Automatic output name derivation for encryption/decryption.
- Bulk key generation (powers of two range).
- Integrity checking (byte compare + optional SHA-256 hashes displayed).
- Speed benchmark table (times + encrypted size).
- Naive brute force demonstration with configurable timeout (default `LIMIT_SECONDS`, overridable in CLI/interactive).
- Interactive TUI and CLI modes.

---
## 5. Building the Project
You can build via the provided `Makefile` or with CMake.

### 5.1 Using Make
```
make
./rsa_tool
```
### 5.2 Using CMake (Optional)
```
mkdir build
cd build
cmake ..
cmake --build .
./rsa_tool
```
Ensure GMP development headers and library are installed first.

---
## 6. Platform Setup
### 6.1 macOS (Homebrew)
```
brew install gmp
make
```
If Homebrew installs to `/opt/homebrew`, the Makefile auto-detects includes and libs.

### 6.2 Linux (Debian/Ubuntu)
```
sudo apt update
sudo apt install build-essential libgmp-dev
make
```

### 6.3 Linux (Fedora/RHEL/CentOS)
```
sudo dnf install gcc gmp-devel make
make
```

### 6.4 Windows (Recommended: WSL)
1. Install WSL (Ubuntu) via Microsoft Store.
2. Inside WSL:
```
sudo apt update
sudo apt install build-essential libgmp-dev
make
```
3. Run `./rsa_tool` within WSL.

### 6.5 Windows (MSYS2)
1. Install MSYS2.
2. In MSYS2 shell:
```
pacman -Syu
pacman -S git make gcc mingw-w64-x86_64-gmp
make
```
3. Use the `mingw64` environment for 64-bit build.

### 6.6 Windows (Cygwin)
Install packages: `gcc-core`, `make`, `libgmp-devel` then run `make`.

### 6.7 Verifying GMP Presence
If build fails with missing `gmp.h`, locate install path and adjust `Makefile` or set:
```
export CFLAGS="-I/path/to/gmp/include" 
export LDFLAGS="-L/path/to/gmp/lib"
make
```

---
## 7. IDE Setup
### 7.1 VS Code
Recommended extensions:
- C/C++ (Microsoft)
- CMake Tools (optional if using CMake)
- Code Runner (optional)

Example `.vscode/tasks.json` (Make):
```json
{
  "version": "2.0.0",
  "tasks": [
    {"label": "build", "type": "shell", "command": "make", "group": "build"},
    {"label": "run", "type": "shell", "command": "./rsa_tool", "group": "test"}
  ]
}
```
Launch config `.vscode/launch.json`:
```json
{
  "version": "0.2.0",
  "configurations": [
    {
      "name": "Run rsa_tool",
      "type": "cppdbg",
      "request": "launch",
      "program": "${workspaceFolder}/rsa_tool",
      "cwd": "${workspaceFolder}",
      "MIMode": "lldb"
    }
  ]
}
```

### 7.2 CLion
Open the folder; CLion detects the `CMakeLists.txt`. Use the predefined Run/Debug. For Make-only workflow, you can add an External Tool or rely on CMake build.

### 7.3 Other Editors
Any editor supporting a terminal can run `make` and invoke `./rsa_tool`.

---
## 8. Usage Examples
### 8.1 Basic Key Generation
```
./rsa_tool generate 1024
```
Creates `keys/public_1024.key` & `keys/private_1024.key`.

### 8.2 Encrypt With Latest Key Automatically
```
./rsa_tool encrypt docs/report.txt
# -> docs/report.txt.dat
```

### 8.3 Encrypt With Specific Bits & Custom Output
```
./rsa_tool encrypt docs/report.txt 2048 encrypted.dat
```

### 8.4 Decrypt Automatically
```
./rsa_tool decrypt docs/report.txt.dat
# -> docs/report_decrypted.txt
```

### 8.5 Bulk Key Generation (512 → 4096)
```
./rsa_tool test bulk 512 4096
```
Generates keys: 512, 1024, 2048, 4096.

### 8.6 Integrity Test
```
./rsa_tool test integrity docs/report.txt 2048
```
Outputs PASS/FAIL and prints SHA-256 of original & decrypted.

### 8.7 Speed Benchmark
```
./rsa_tool test speed docs/report.txt 512 4096
```
Produces a timing table.

### 8.8 Brute Force Demonstration (ONLY Tiny Keys)
Default (uses `LIMIT_SECONDS` from `test_module.h`, 600s by default) and automatic algorithm selection (p-1, then rho, then trial):
```
./rsa_tool test bruteforce docs/small.txt 64 128
```
Custom time limit per key (e.g., 30 seconds) and explicit algorithm:
```
# Use Pollard's Rho
./rsa_tool test bruteforce docs/small.txt 64 128 30 rho

# Use Pollard's p-1
./rsa_tool test bruteforce docs/small.txt 64 128 30 p1

# Force naive trial division (for comparison)
./rsa_tool test bruteforce docs/small.txt 64 128 30 trial
```
In interactive mode, you can also pick the algorithm (auto|trial|rho|p1) and time limit when prompted.

### 8.9 Interactive Mode
Run:
```
./rsa_tool
```
Use menu options for all operations. The brute force test also prompts for an optional time limit (press Enter to use the default shown).

### 8.10 Embedding (Academic Library Use)
You could directly include `rsa.h` and call:
- `init_public_key`, `init_private_key`
- `generate_keys`
- `encrypt_file`, `decrypt_file`
for experiments within another C program. (Not packaged as a library here.)

---
## 9. Troubleshooting & FAQs
| Issue | Cause | Fix |
|-------|-------|-----|
| `gmp.h` not found | GMP not installed / include path missing | Install GMP, export CFLAGS/LDFLAGS, or adjust Makefile paths |
| Segfault on tiny bit length | Extremely small n reduces chunk logic | Use >= 64 bits for demonstrations |
| Brute force never finishes | Key size too large for trial division | Restrict to ≤128 bits; feature is illustrative only |
| Decrypted file larger/smaller | Chunk boundary vs raw export alignment | Expected with raw RSA; integrity test ensures correctness |
| Different timing each run | Natural variability (CPU frequency, cache) | Run multiple iterations; take mean |

### Common Questions
- Why no padding? Simplicity for study. Add OAEP/PSS for any serious use.
- Why are e and d forced to same bit length? Academic exercise – not a standard RSA requirement.
- Why hex lines for ciphertext? Simplifies parsing; binary framing omitted.

---
## 10. Academic Limitations & Possible Extensions
Potential enhancements (exercise ideas):
- Implement OAEP padding for semantic security.
- Replace trial division with Pollard's Rho / Quadratic Sieve demonstration.
- Multi-thread the brute force attempt (divide candidate ranges).
- Add CRT optimization for faster decryption (use p, q directly).
- Introduce a secure RNG seeding strategy (e.g. `/dev/urandom`, `getrandom`).
- Integrate timing-resistant modular exponentiation.
- Provide benchmarking for larger files and memory mapping.
- Add JSON output mode for scripting.
- Convert chunk logic to PKCS#1 type 2 or OAEP for safe usage patterns.

---
## 11. License
This project is released under the MIT License (see `LICENSE`).

---
## Reminder
Again: This repository is for **academic exploration**, not production cryptography. Use modern, vetted libraries for real security needs.
