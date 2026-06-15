# ed25519brute-cuda — Инструкция по сборке и использованию

> **Предупреждение:** Это учебный/исследовательский проект. Не используйте найденные ключи в продакшене. Для реальных SSH-ключей используйте `ssh-keygen`.

---

## Структура репозитория

```
ed25519brute-cuda/
├── src/
│   ├── main.cu                  # Точка входа, CUDA-ядро, мульти-GPU логика
│   ├── config.h                 # Compile-time параметры ядра
│   ├── ed25519.cuh              # CUDA Ed25519 (PTX-оптимизированная арифметика)
│   ├── sha256.cuh               # CUDA SHA-256 для fingerprint
│   ├── sha512.cuh               # CUDA SHA-512 для key derivation
│   ├── fingerprint_match.cuh    # Логика сопоставления prefix/suffix
│   ├── openssh_format.h         # Запись ключей в OpenSSH PEM-формат
│   ├── precomp_5bit.h           # Таблица предвычисленных точек (5-bit окно)
│   ├── precomp_7bit.h           # Таблица предвычисленных точек (7-bit окно)
│   ├── precomp_8bit.h           # Таблица предвычисленных точек (8-bit окно, используется)
│   ├── generate_precomp.py      # Скрипт генерации precomp-таблиц
│   └── test_kernels.cu          # CUDA-тесты ядер
├── tests/
│   └── test_vectors.py          # Python-тесты корректности (pytest)
├── testdata/                    # Бинарные тестовые векторы
│   ├── test_vectors.bin
│   ├── sha256_test_vectors.bin
│   ├── match_test_vectors.bin
│   ├── prefix_test_vectors.bin
│   └── suffix_test_vectors.bin
├── py/
│   ├── main.py                  # CPU-версия брутфорса (Python, multiprocessing)
│   ├── verify_seed.py           # Верификация найденного seed
│   ├── generate_match_tests.py  # Генератор тестовых векторов
│   ├── debug_sha256_input.py    # Отладка SHA-256
│   ├── debug_wireformat.py      # Отладка SSH wire format
│   └── debug_suffix.py          # Анализ суффиксного совпадения
├── build.bat                    # Основной скрипт сборки (Windows)
├── buildold.bat                 # Устаревший скрипт (только sm_89)
├── CMakeLists.txt               # Альтернативная сборка через CMake
├── pyproject.toml               # Python-зависимости
└── .gitignore
```

---

## Требования

### Обязательные

| Компонент | Версия | Примечание |
|-----------|--------|------------|
| **NVIDIA GPU** | Compute Capability 7.5+ | RTX 20xx / 30xx / 40xx |
| **CUDA Toolkit** | 12.x рекомендуется | Включает `nvcc` |
| **MSVC** (Windows) | Visual Studio 2019 / 2022 | Нужен только C++ build tools |

### Поддерживаемые архитектуры GPU

| Архитектура | `sm_` код | Примеры GPU |
|-------------|-----------|-------------|
| Turing | `sm_75` | RTX 2080, T4 |
| Ampere | `sm_86` | RTX 3080, A100 |
| Ada Lovelace | `sm_89` | RTX 4090, RTX 4080 |

---

## Сборка на Windows (рекомендуется)

### Шаг 1 — Установить зависимости

1. **Visual Studio 2022** (или Build Tools): установить компонент **«Desktop development with C++»**
2. **CUDA Toolkit**: скачать с [developer.nvidia.com/cuda-downloads](https://developer.nvidia.com/cuda-downloads)

После установки убедитесь, что `nvcc` доступен:
```powershell
nvcc --version
```

### Шаг 2 — Настроить целевую архитектуру GPU

Откройте `build.bat` и найдите строку с `-gencode`:

```bat
nvcc -O3 --use_fast_math --extra-device-vectorization ^
  -gencode arch=compute_75,code=sm_75 ^
  -gencode arch=compute_86,code=sm_86 ^
  -gencode arch=compute_89,code=sm_89 ^
  ...
```

Оставьте только архитектуру своего GPU (для ускорения компиляции). Например, для RTX 4090:

```bat
nvcc -O3 --use_fast_math --extra-device-vectorization ^
  -gencode arch=compute_89,code=sm_89 ^
  ...
```

Узнать свой `compute capability` можно командой:
```powershell
nvidia-smi --query-gpu=compute_cap --format=csv
```

### Шаг 3 — Скомпилировать

```powershell
# Основной исполняемый файл
.\build.bat

# Или явно указать цель:
.\build.bat main

# Тестовые ядра:
.\build.bat test
```

Результат:
- `build\ed25519brute_cuda.exe` — основная программа
- `build\test_kernels.exe` — тесты CUDA-ядер
- `build_log.txt` — подробный лог компиляции (ptxas info)

> **Примечание:** `build.bat` автоматически ищет `vcvars64.bat` в директориях Visual Studio и инициализирует окружение MSVC. Если `cl.exe` уже в PATH (например, в Developer Command Prompt), этот шаг пропускается.

---

## Альтернативная сборка через CMake

CMake-конфиг (`CMakeLists.txt`) поддерживает только `sm_89` и не включает `-rdc=true`. Подходит для простых случаев.

```powershell
mkdir build_cmake && cd build_cmake
cmake .. -G "Visual Studio 17 2022" -A x64
cmake --build . --config Release
```

---

## Тюнинг производительности

Параметры в `src/config.h` оптимизированы под конкретное железо автора. Для других GPU может потребоваться подстройка:

```c
#define THREADS_PER_BLOCK      256   // 128–512, степень двойки
#define ITERATIONS_PER_THREAD  256   // больше → меньше overhead, но дольше отклик
#define BATCH_SIZE             32    // размер батча Montgomery inversion
#define DEFAULT_BLOCKS         256   // блоков на GPU (переопределяется через --blocks)
#define MAX_BLOCKS             4096
```

После изменения `config.h` необходима пересборка.

---

## Использование

```powershell
# Поиск по суффиксу fingerprint
.\build\ed25519brute_cuda.exe --fingerprint-suffix AAAAAA

# Поиск по префиксу fingerprint
.\build\ed25519brute_cuda.exe --fingerprint-prefix abc123

# Одновременно prefix и suffix
.\build\ed25519brute_cuda.exe --fingerprint-prefix abc --fingerprint-suffix XYZ

# Поиск по hex-префиксу сырого публичного ключа
.\build\ed25519brute_cuda.exe --pubkey-prefix deadbeef

# Использовать несколько GPU (например, GPU 0 и 1)
.\build\ed25519brute_cuda.exe --fingerprint-suffix AAAAAA --gpu 0,1

# Указать количество блоков вручную
.\build\ed25519brute_cuda.exe --fingerprint-suffix AAAAAA --blocks 512
```

> **Ограничение:** последний символ `--fingerprint-suffix` должен быть одним из `AEIMQUYcgkosw048` (ограничение Base64-выравнивания).

### Пример вывода

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

Файлы сохраняются с уникальным именем (timestamp + серийный номер) — перезапись невозможна.

---

## Тесты

### CUDA-тесты ядер

```powershell
.\build\test_kernels.exe
```

Требует наличия файлов в `testdata/`. Проверяет SHA-512, Ed25519, SHA-256 fingerprint, prefix/suffix matching.

### Python-тесты (pytest)

Установка зависимостей (требует Python 3.14+):

```powershell
pip install uv
uv sync
```

Или напрямую:
```powershell
pip install cryptography pynacl pytest
```

Запуск тестов:
```powershell
pytest tests/test_vectors.py -v
```

Тесты сверяют результаты CUDA-ядер (через бинарные векторы) с эталонной реализацией `cryptography` / `hashlib`.

### Генерация тестовых векторов вручную

```powershell
cd py
python generate_match_tests.py
# Создаёт match_test_vectors.bin (100 векторов)
```

---

## CPU-версия (Python)

Для отладки или систем без GPU:

```powershell
cd py
python main.py --fingerprint-suffix AAAAAA
python main.py --fingerprint-prefix abc123
```

Значительно медленнее GPU-версии (~KKeys/s против ~MKeys/s).

---

## Диагностика

| Проблема | Решение |
|----------|---------|
| `vcvars64.bat not found` | Установить Visual Studio C++ Build Tools |
| `nvcc: command not found` | Добавить CUDA bin в PATH: `C:\Program Files\NVIDIA GPU Computing Toolkit\CUDA\vX.X\bin` |
| `Build failed` | Смотреть `build_log.txt` |
| Предупреждение `pattern_bits` was declared but never referenced | Безвредно, можно игнорировать |
| Медленная компиляция | Оставить только одну `-gencode` для своего GPU в `build.bat` |
| GPU не найден | Проверить `nvidia-smi`, убедиться в установке CUDA Runtime |

---

## Безопасность

- **Никогда** не используйте один `base_seed` для нескольких ключей — они будут криптографически связаны.
- Найденные ключи предназначены только для тестирования GitHub commit verification (Vanity SSH fingerprint).
- Результаты сохраняются в файлы с уникальными именами, чтобы случайно не перезаписать предыдущий найденный ключ.
