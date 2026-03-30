# mbrecon

Modbus TCP reconnaissance and security assessment tool for OT/ICS environments.

Enumerates exposed Function Codes, maps writable coils, discovers holding registers, and generates a structured security report, all without prior knowledge of the target device's register map.

## Why

Modbus TCP has no native authentication. Any host on the same network can read sensor data and send write commands without credentials. `mbrecon` makes this exposure visible and measurable, producing actionable findings for security assessments of industrial control systems.

## Disclaimer

> [!CAUTION]
> `mbrecon` is intended for **authorized security assessments only**.
>
> Use of this tool against systems you do not own or have explicit written permission to test may be illegal under applicable law, including but not limited to the Computer Fraud and Abuse Act (CFAA), the UK Computer Misuse Act, and equivalent legislation in other jurisdictions.
>
> The authors assume no liability for misuse or damage caused by this tool. You are solely responsible for ensuring your use complies with all applicable laws and regulations.
>
> **Always obtain proper authorization before running any assessment.**

## Features

- **Connectivity check** — confirms Modbus service is active before proceeding
- **Function Code enumeration** — tests FC01–FC16 and reports what is allowed or denied, including exception codes
- **Coil mapping** — identifies writable digital outputs via FC05
- **Register discovery** — brute-forces addresses 0–999 in blocks of 125, with automatic per-address fallback when a block read fails
- **Value inference** — classifies discovered registers by value range (Celsius, Kelvin, ratio, or raw)
- **Security findings** — structured report with severity levels (Critical / High / Medium) and remediation recommendations
- **Interactive flow** — each phase is opt-in, allowing targeted runs

## Installation

```bash
curl -sSL https://raw.githubusercontent.com/h0ru/mbrecon/refs/heads/main/install.sh | bash
```

The installer will:
1. Check Python >= 3.8
2. Install `pymodbus` via pip
3. Download and validate `mbrecon.py` to the current directory

### Manual installation

```bash
pip install pymodbus --break-system-packages
curl -sSL https://raw.githubusercontent.com/h0ru/mbrecon/refs/heads/main/mbrecon.py -o mbrecon.py
python3 mbrecon.py <host>
```

## Requirements

- Python 3.8+
- [pymodbus](https://github.com/pymodbus-dev/pymodbus)

## Usage

```bash
python3 mbrecon.py <host> [options]
```

### Arguments

| Argument | Short | Default | Description |
|---|---|---|---|
| `host` | — | required | Target IP or hostname |
| `--port` | `-p` | `502` | Modbus TCP port |
| `--device-id` | `-d` | `1` | Unit ID / Device ID |
| `--probe` | — | `74` | Register address used for connectivity probe |
| `--scan-range` | — | `1000` | Upper bound for register discovery (0 to N-1) |

### Examples

```bash
# Basic scan
python3 mbrecon.py x.x.x.x

# Custom port and device ID
python3 mbrecon.py x.x.x.x --port 502 --device-id 2

# Expand discovery range
python3 mbrecon.py x.x.x.x --scan-range 2000
```

## Output

```
════════════════════════════════════════════════════════════
                          MBRECON
                OT Security Assessment Tool
════════════════════════════════════════════════════════════
  Target    : x.x.x.x:502
  Device ID : 1

  [STEP 1/4] Checking Modbus connectivity...
  [✓] Modbus service is ACTIVE at x.x.x.x:502

  [STEP 2/4] Function Code Enumeration
  [✗]  FC01 — Read Coils                   DENIED (exception code: 2)
  [✓]  FC03 — Read Holding Registers       ALLOWED
  [✓]  FC05 — Write Single Coil            ALLOWED
  ...

  [STEP 3/4] Coil Mapping
  [✓] Coil 000: exists and accepts write

  [ SUMMARY ]
  Allowed FCs    : 2/8 — FC03, FC05
  Writable Coils : [0]
  Authentication : NONE

  ADDR     INFERRED LABEL          VALUE        RAW
  [0074]   Temp_C_01 (C)          27.61        0x41dc 0xdd2e
  [0142]   Temp_K_01 (Kelvin)    390.42 K      (117.27C)
  ...

  [ SECURITY FINDINGS ]
  [CRITICAL] No authentication mechanism
  [CRITICAL] Unauthenticated write to digital output (FC05 / Coil 0)
  [HIGH]     Full sensor data exposed without access control
  ...
```

## Scan Flow

```
mbrecon.py <host>
├── Step 1  Connectivity check           → confirm Modbus is responding
├── Step 2  Function Code enumeration    → FC01 through FC16
├── Step 3  Coil mapping                 → writable outputs via FC05 (range 0–31)
├── Step 4  Summary
├── [opt]   Register discovery scan      → brute-force 0 to scan-range
└── [opt]   Security findings & report
```
