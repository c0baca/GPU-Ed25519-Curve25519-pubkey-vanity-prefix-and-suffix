# ed25519brute-cuda — Build & Usage Instructions

> **Warning:** This is a research/educational project. Do not use found keys in production. Use `ssh-keygen` for real SSH keys.

---

## Repository Structure

```
ed25519brute-cuda/
├── src/
│   ├── main.cu                  # Entry point, CUDA kernel, multi-GPU logic
│   ├── config.h                 # Compile-time kernel parameters
│   ├── ed25519.cuh              # CUDA Ed25519 (PTX-optimized field arithmetic)
│   ├── sha256.cuh               # CUDA SHA-256 for fingerprint computation
│   ├── sha512.cuh               # CUDA SHA-512 for key derivation
│   ├── fingerprint_match.cuh    # Prefix/suffix matching logic
│   ├── openssh_format.h         # OpenSSH PEM key writer
│   ├── precomp_5bit.h           # Precomputed point table (5-bit window)
│   ├── precomp_7bit.h           # Precomputed point table (7-bit window)
│   ├── precomp_8bit.h           # Precomputed point table (8-bit window, active)
│   ├── generate_precomp.py      # Script to regenerate precomp tables
│   └── test_kernels.cu          # CUDA kernel tests
├── tests/
│   └── test_vectors.py          # Python correctness tests (pytest)
├── testdata/                    # Binary test vectors
│   ├── test_vectors.bin
│   ├── sha256_test_vectors.bin
│   ├── match_test_vectors.bin
│   ├── prefix_test_vectors.bin
│   └── suffix_test_vectors.bin
├── py/
│   ├── main.py                  # CPU brute-force (Python, multiprocessing)
│   ├── verify_seed.py           # Verify a found seed
│   ├── generate_match_tests.py  # Test vector generator
│   ├── debug_sha256_input.py    # SHA-256 input debugger
│   ├── debug_wireformat.py      # SSH wire format debugger
│   └── debug_suffix.py          # Suffix match analyzer
├── build.bat                    # Primary build script (Windows)
├── buildold.bat                 # Legacy script (sm_89 only)
├── CMakeLists.txt               # Alternative CMake build
├── pyproject.toml               # Python dependencies
└── .gitignore
```

---

## Requirements

### Mandatory

| Component | Version | Notes |
|-----------|---------|-------|
| **NVIDIA GPU** | Compute Capability 7.5+ | RTX 20xx / 30xx / 40xx |
| **CUDA Toolkit** | 12.x recommended | Provides `nvcc` |
| **MSVC** (Windows) | Visual Studio 2019 / 2022 | C++ Build Tools are sufficient |

### Supported GPU Architectures

| Architecture | `sm_` code | Example GPUs |
|--------------|------------|--------------|
| Turing | `sm_75` | RTX 2080, T4 |
| Ampere | `sm_86` | RTX 3080, A100 |
| Ada Lovelace | `sm_89` | RTX 4090, RTX 4080 |

---

## Building on Windows (Recommended)

### Step 1 — Install Dependencies

1. **Visual Studio 2022** (or Build Tools only): install the **"Desktop development with C++"** workload.
2. **CUDA Toolkit**: download from [developer.nvidia.com/cuda-downloads](https://developer.nvidia.com/cuda-downloads).

Verify `nvcc` is available:
```powershell
nvcc --version
```

### Step 2 — Set the Target GPU Architecture

Open `build.bat` and locate the `-gencode` flags:

```bat
nvcc -O3 --use_fast_math --extra-device-vectorization ^
  -gencode arch=compute_75,code=sm_75 ^
  -gencode arch=compute_86,code=sm_86 ^
  -gencode arch=compute_89,code=sm_89 ^
  ...
```

For faster compilation, keep only the entry matching your GPU. For example, for an RTX 4090:

```bat
nvcc -O3 --use_fast_math --extra-device-vectorization ^
  -gencode arch=compute_89,code=sm_89 ^
  ...
```

To find your compute capability:
```powershell
nvidia-smi --query-gpu=compute_cap --format=csv
```

### Step 3 — Compile

```powershell
# Build the main executable
.\build.bat

# Equivalent explicit call:
.\build.bat main

# Build CUDA kernel tests:
.\build.bat test
```

Output files:
- `build\ed25519brute_cuda.exe` — main program
- `build\test_kernels.exe` — CUDA kernel tests
- `build_log.txt` — detailed compile log (ptxas register/stack info)

> **Note:** `build.bat` automatically searches for `vcvars64.bat` under all Visual Studio installation paths and initializes the MSVC environment. If `cl.exe` is already in PATH (e.g. inside a Developer Command Prompt), this step is skipped automatically.

---

## Alternative: CMake Build

The `CMakeLists.txt` targets `sm_89` only and does not enable `-rdc=true`. Suitable for simple setups.

```powershell
mkdir build_cmake && cd build_cmake
cmake .. -G "Visual Studio 17 2022" -A x64
cmake --build . --config Release
```

---

## Performance Tuning

The defaults in `src/config.h` are optimized for the author's GPU. You may need to adjust them for your hardware:

```c
#define THREADS_PER_BLOCK      256   // Power of 2, typically 128–512
#define ITERATIONS_PER_THREAD  256   // Higher = less launch overhead, slower response
#define BATCH_SIZE             32    // Montgomery batch inversion size
#define DEFAULT_BLOCKS         256   // Grid blocks per GPU (overridable via --blocks)
#define MAX_BLOCKS             4096
```

A full rebuild is required after any change to `config.h`.

---

## Usage

```powershell
# Search by fingerprint suffix
.\build\ed25519brute_cuda.exe --fingerprint-suffix AAAAAA

# Search by fingerprint prefix
.\build\ed25519brute_cuda.exe --fingerprint-prefix abc123

# Both prefix and suffix simultaneously
.\build\ed25519brute_cuda.exe --fingerprint-prefix abc --fingerprint-suffix XYZ

# Search by raw public key hex prefix
.\build\ed25519brute_cuda.exe --pubkey-prefix deadbeef

# Use multiple GPUs (e.g. GPU 0 and 1)
.\build\ed25519brute_cuda.exe --fingerprint-suffix AAAAAA --gpu 0,1

# Override block count
.\build\ed25519brute_cuda.exe --fingerprint-suffix AAAAAA --blocks 512
```

> **Constraint:** the last character of `--fingerprint-suffix` must be one of `AEIMQUYcgkosw048` due to Base64 bit-alignment.

### Example Output

```
Ed25519 SSH Key CUDA Brute Force
=================================
Fingerprint suffix: AAAAAA
GPUs: [0] NVIDIA GeForce RTX 4090 (SM 8.9)
Blocks per GPU: 256  |  Threads per block: 256
Starting search...

[  1.1s] Total:    100 M  |  Speed:   44.34 MKeys/s  |  GPUs: GPU0: 100M

============================================
Match found in 1.1s after ~100 M keys!
============================================

Seed (32 bytes):       f7af4ff1...
Public Key (32 bytes): 5c9e490b...
Fingerprint:           SHA256:h3O4gF...AAAAAA

Saving results:
  Info:        found_key_20260615_120000_001.txt
  Private key: id_ed25519_20260615_120000_001
  Public key:  id_ed25519_20260615_120000_001.pub
```

Output files use unique names (timestamp + serial number) — no accidental overwrites.

---

## Testing

### CUDA Kernel Tests

```powershell
.\build\test_kernels.exe
```

Requires binary files in `testdata/`. Validates SHA-512, Ed25519 key generation, SHA-256 fingerprint, and prefix/suffix matching against reference vectors.

### Python Tests (pytest)

Install dependencies (requires Python 3.14+):

```powershell
pip install uv
uv sync
```

Or directly:
```powershell
pip install cryptography pynacl pytest
```

Run tests:
```powershell
pytest tests/test_vectors.py -v
```

These tests compare CUDA kernel outputs (via binary vectors) against the reference `cryptography` / `hashlib` implementations.

### Generating Test Vectors Manually

```powershell
cd py
python generate_match_tests.py
# Creates match_test_vectors.bin (100 vectors)
```

---

## CPU Version (Python)

For debugging or systems without a GPU:

```powershell
cd py
python main.py --fingerprint-suffix AAAAAA
python main.py --fingerprint-prefix abc123
```

Significantly slower than the GPU version (~KKeys/s vs ~MKeys/s).

---

## Troubleshooting

| Problem | Solution |
|---------|----------|
| `vcvars64.bat not found` | Install Visual Studio C++ Build Tools |
| `nvcc: command not found` | Add CUDA bin to PATH: `C:\Program Files\NVIDIA GPU Computing Toolkit\CUDA\vX.X\bin` |
| Build failed | Check `build_log.txt` for details |
| Warning: `pattern_bits` was declared but never referenced | Harmless, can be ignored |
| Slow compilation | Keep only one `-gencode` entry matching your GPU in `build.bat` |
| GPU not found at runtime | Run `nvidia-smi` to verify driver, check CUDA Runtime installation |

---

## Security Notes

- **Never** reuse the same `base_seed` for multiple keys — they will be cryptographically correlated.
- Found keys are intended for GitHub commit verification (Vanity SSH fingerprint) only.
- Output files use unique timestamped names to prevent accidental overwriting of previously found keys.
