#!/usr/bin/env python3
# ─────────────────────────────────────────────────────────────
#  mbrecon — tool
#  https://github.com/h0ru/mbrecon
# ─────────────────────────────────────────────────────────────

"""
mbrecon.py — Modbus TCP Reconnaissance & Security Assessment Tool
Usage: python3 mbrecon.py <host> [--port PORT] [--device-id ID] [--probe ADDR]
"""

import sys
import time
import struct
import argparse
import threading
import itertools
from datetime import datetime

# ── COLOR CODES ──────────────────────────────────────────────
class C:
    RESET   = '\033[0m'
    BOLD    = '\033[1m'
    RED     = '\033[91m'
    GREEN   = '\033[92m'
    YELLOW  = '\033[93m'
    CYAN    = '\033[96m'
    WHITE   = '\033[97m'
    GRAY    = '\033[90m'
    ORANGE  = '\033[38;5;208m'

def critical(text): return f"{C.BOLD}{C.RED}{text}{C.RESET}"
def high(text):     return f"{C.BOLD}{C.ORANGE}{text}{C.RESET}"
def medium(text):   return f"{C.BOLD}{C.YELLOW}{text}{C.RESET}"
def ok(text):       return f"{C.BOLD}{C.GREEN}{text}{C.RESET}"
def info(text):     return f"{C.CYAN}{text}{C.RESET}"
def dim(text):      return f"{C.GRAY}{text}{C.RESET}"
def bold(text):     return f"{C.BOLD}{C.WHITE}{text}{C.RESET}"

def ask(question):
    ans = input(f"  {bold('>')} {C.YELLOW}{question} [Y/n]{C.RESET} ").strip().lower()
    return ans not in ('n', 'no')

# ── SPINNER ──────────────────────────────────────────────────
class Spinner:
    FRAMES = ['⠋','⠙','⠹','⠸','⠼','⠴','⠦','⠧','⠇','⠏']

    def __init__(self, msg):
        self.msg        = msg
        self._stop      = threading.Event()
        self._thread    = threading.Thread(target=self._spin, daemon=True)

    def _spin(self):
        for f in itertools.cycle(self.FRAMES):
            if self._stop.is_set():
                break
            print(f"\r  {C.CYAN}{f}{C.RESET}  {self.msg}", end='', flush=True)
            time.sleep(0.08)

    def start(self):
        self._thread.start()
        return self

    def stop(self, final_msg=None):
        self._stop.set()
        self._thread.join()
        label = final_msg or self.msg
        print(f"\r  {ok('[✓]')}  {label}{' '*30}")

    def update(self, msg):
        self.msg = msg

# ── ARGUMENT PARSING ─────────────────────────────────────────
parser = argparse.ArgumentParser(
    description='mbrecon — Modbus TCP Reconnaissance & Security Assessment Tool'
)
parser.add_argument('host',               help='Target IP or hostname')
parser.add_argument('--port',      '-p',  type=int, default=502,  help='Modbus port (default: 502)')
parser.add_argument('--device-id', '-d',  type=int, default=1,    help='Device ID / Unit ID (default: 1)')
parser.add_argument('--probe',            type=int, default=74,   help='Probe register address (default: 74)')
parser.add_argument('--scan-range',       type=int, default=1000, help='Discovery scan range (default: 1000)')
args = parser.parse_args()

HOST       = args.host
PORT       = args.port
DEVICE_ID  = args.device_id
PROBE_ADDR = args.probe
SCAN_RANGE = args.scan_range

# ── BANNER ───────────────────────────────────────────────────
print(f"\n{C.BOLD}{C.CYAN}{'═'*60}{C.RESET}")
print(f"{C.BOLD}{C.CYAN}  {'MBRECON'.center(56)}  {C.RESET}")
print(f"{C.GRAY}  {'OT Security Assessment Tool'.center(56)}  {C.RESET}")
print(f"{C.BOLD}{C.CYAN}{'═'*60}{C.RESET}")
print(f"  {dim('Target    :')} {bold(HOST)}:{bold(str(PORT))}")
print(f"  {dim('Device ID :')} {bold(str(DEVICE_ID))}")
print(f"  {dim('Time      :')} {dim(datetime.now().strftime('%Y-%m-%d %H:%M:%S'))}")
print(f"{C.CYAN}{'─'*60}{C.RESET}\n")

# ── DEPENDENCY CHECK ─────────────────────────────────────────
try:
    from pymodbus.client import ModbusTcpClient
    from pymodbus import ModbusException
except ImportError:
    print(critical("  [!] pymodbus not found. Run: pip install pymodbus"))
    sys.exit(1)

# ── HELPERS ──────────────────────────────────────────────────
def regs_to_float_be(r1, r2):
    return struct.unpack('>f', struct.pack('>HH', r1, r2))[0]

def infer_label(addr, val, counters):
    if 200.0 < val < 500.0:
        counters['temp_k'] += 1
        return f"Temp_K_{counters['temp_k']:02d} (Kelvin)", 'kelvin'
    elif 5.0 <= val <= 100.0:
        counters['temp_c'] += 1
        return f"Temp_C_{counters['temp_c']:02d} (C)", 'celsius'
    elif 0.0 <= val <= 1.0:
        counters['ratio'] += 1
        return f"Ratio_{counters['ratio']:02d} (0-1)", 'ratio'
    else:
        counters['unknown'] += 1
        return f"Register_{addr:04d}", 'unknown'

def test_fc(fn):
    try:
        r = fn()
        if hasattr(r, 'isError') and r.isError():
            code = getattr(r, 'exception_code', '?')
            return 'DENIED', code
        return 'ALLOWED', None
    except ModbusException as e:
        return 'ERROR', str(e)

def try_block(base, count):
    """Read a block of registers. Returns list of (addr, r1, r2, val) or []."""
    results = []
    try:
        rr = client.read_holding_registers(address=base, count=count, device_id=DEVICE_ID)
        if not rr.isError():
            regs = rr.registers
            for i in range(0, len(regs) - 1, 2):
                addr = base + i
                r1, r2 = regs[i], regs[i+1]
                try:
                    v = regs_to_float_be(r1, r2)
                    if v == v and abs(v) < 1e6 and abs(v) > 1e-9:
                        results.append((addr, r1, r2, v))
                except Exception:
                    pass
            return results, False
        else:
            return None, True
    except ModbusException:
        return None, True

def try_individual(base, count):
    """Fallback: read address by address when block read fails.
    Always starts on an even address to keep float32 BE pairs aligned."""
    results = []
    start = base if base % 2 == 0 else base + 1
    for addr in range(start, base + count, 2):
        try:
            rr = client.read_holding_registers(address=addr, count=2, device_id=DEVICE_ID)
            if not rr.isError():
                r1, r2 = rr.registers[0], rr.registers[1]
                try:
                    v = regs_to_float_be(r1, r2)
                    if v == v and abs(v) < 1e6 and abs(v) > 1e-9:
                        results.append((addr, r1, r2, v))
                except Exception:
                    pass
            time.sleep(0.05)
        except ModbusException:
            pass
    return results

# ── STEP 1: CONNECTIVITY CHECK ───────────────────────────────
print(f"  {bold('[STEP 1/4]')} {info('Checking Modbus connectivity...')}\n")

client = ModbusTcpClient(HOST, port=PORT, timeout=3)
connected = client.connect()

if not connected:
    print(f"  {critical('[✗] Cannot reach')} {bold(HOST)}:{bold(str(PORT))}")
    print(f"  {dim('The host may be offline, port closed, or firewalled.')}\n")
    sys.exit(1)

probe        = client.read_holding_registers(address=PROBE_ADDR, count=2, device_id=DEVICE_ID)
modbus_alive = not probe.isError()

if modbus_alive:
    print(f"  {ok('[✓] Modbus service is ACTIVE')} at {bold(HOST)}:{bold(str(PORT))}")
else:
    print(f"  {medium('[~] TCP connection OK but Modbus probe returned error')}")
    print(f"      {dim('Device may be online but probe register unavailable.')}")

print()
if not ask("Modbus host is reachable. Proceed with full scan?"):
    print(f"\n  {dim('Scan aborted by user.')}\n")
    client.close()
    sys.exit(0)

print()

# ── STEP 2: FUNCTION CODE ENUMERATION ───────────────────────
print(f"{C.CYAN}{'─'*60}{C.RESET}")
print(f"  {bold('[STEP 2/4]')} {info('Function Code Enumeration')}\n")

fcs = [
    ("FC01", "Read Coils",
        lambda: client.read_coils(address=0, count=8, device_id=DEVICE_ID)),
    ("FC02", "Read Discrete Inputs",
        lambda: client.read_discrete_inputs(address=0, count=8, device_id=DEVICE_ID)),
    ("FC03", "Read Holding Registers",
        lambda: client.read_holding_registers(address=PROBE_ADDR, count=2, device_id=DEVICE_ID)),
    ("FC04", "Read Input Registers",
        lambda: client.read_input_registers(address=PROBE_ADDR, count=2, device_id=DEVICE_ID)),
    ("FC05", "Write Single Coil",
        lambda: client.write_coil(address=0, value=False, device_id=DEVICE_ID)),
    ("FC06", "Write Single Register",
        lambda: client.write_register(address=PROBE_ADDR, value=0x0000, device_id=DEVICE_ID)),
    ("FC15", "Write Multiple Coils",
        lambda: client.write_coils(address=0, values=[False]*8, device_id=DEVICE_ID)),
    ("FC16", "Write Multiple Registers",
        lambda: client.write_registers(address=PROBE_ADDR, values=[0x0000, 0x0000], device_id=DEVICE_ID)),
]

allowed_fcs = []
fc_results  = {}

for fc_code, fc_label, fn in fcs:
    status, detail = test_fc(fn)
    fc_results[fc_code] = (status, detail)

    if status == 'ALLOWED':
        allowed_fcs.append(fc_code)
        icon    = ok('[✓]')
        s_label = ok('ALLOWED')
        d_text  = ''
    else:
        icon    = f"{C.RED}[✗]{C.RESET}"
        s_label = medium('DENIED') if status == 'DENIED' else dim('ERROR')
        d_text  = f" {dim(f'(exception code: {detail})')}" if detail else ''

    print(f"  {icon}  {C.BOLD}{fc_code}{C.RESET} {dim('—')} {fc_label:<28} {s_label}{d_text}")
    time.sleep(0.15)

# ── STEP 3: COIL MAPPING ─────────────────────────────────────
print(f"\n{C.CYAN}{'─'*60}{C.RESET}")
print(f"  {bold('[STEP 3/4]')} {info('Coil Mapping (FC05 write probe, range 0-31)')}\n")

coils_found = []
for addr in range(0, 32):
    try:
        r = client.write_coil(address=addr, value=False, device_id=DEVICE_ID)
        if not r.isError():
            coils_found.append(addr)
            print(f"  {ok('[✓]')} Coil {C.BOLD}{addr:03d}{C.RESET}: exists and {C.GREEN}accepts write{C.RESET}")
        time.sleep(0.1)
    except ModbusException:
        pass

if not coils_found:
    print(f"  {dim('No writable coils found in range 0-31')}")
else:
    print(f"\n  {bold('Coils mapped:')} {C.YELLOW}{coils_found}{C.RESET}")

# ── STEP 4: SUMMARY ──────────────────────────────────────────
val = None
rr  = client.read_holding_registers(address=PROBE_ADDR, count=2, device_id=DEVICE_ID)
if not rr.isError():
    val = regs_to_float_be(rr.registers[0], rr.registers[1])

print(f"\n{C.BOLD}{C.CYAN}{'═'*60}{C.RESET}")
print(f"{C.BOLD}{C.WHITE}{'[ SUMMARY ]'.center(60)}{C.RESET}")
print(f"{C.BOLD}{C.CYAN}{'═'*60}{C.RESET}")
print(f"  {dim('Host              :')} {bold(HOST)}:{bold(str(PORT))}")
print(f"  {dim('Device ID         :')} {bold(str(DEVICE_ID))}")
print(f"  {dim('Modbus Active     :')} {ok('YES') if modbus_alive else medium('PARTIAL')}")
print(f"  {dim('FC03 Read         :')} {ok(f'{val:.4f} C') if val else medium('FAILED')}")
print(f"  {dim('Allowed FCs       :')} {C.YELLOW}{len(allowed_fcs)}/{len(fcs)}{C.RESET} {dim('—')} {C.YELLOW}{', '.join(allowed_fcs) if allowed_fcs else 'none'}{C.RESET}")
print(f"  {dim('Writable Coils    :')} {C.YELLOW}{coils_found if coils_found else 'none'}{C.RESET}")
print(f"  {dim('Authentication    :')} {critical('NONE')}")

# ── OPTIONAL: REGISTER DISCOVERY SCAN ────────────────────────
print(f"\n{C.CYAN}{'─'*60}{C.RESET}")
print()
if ask(f"Run register discovery scan? (addresses 0-{SCAN_RANGE-1})"):

    discovered   = {}
    fallbacks    = 0
    counters     = {'temp_c': 0, 'temp_k': 0, 'ratio': 0, 'unknown': 0}
    total_blocks = (SCAN_RANGE + 124) // 125

    print()
    spin = Spinner(f"Scanning block 1/{total_blocks}...").start()

    for block_idx, base in enumerate(range(0, SCAN_RANGE, 125), start=1):
        count = min(125, SCAN_RANGE - base)
        spin.update(f"Block {block_idx}/{total_blocks}  "
                    f"{dim(f'[{base}-{base+count-1}]')}  "
                    f"{C.GREEN}{len(discovered)} found{C.RESET}")

        results, use_fallback = try_block(base, count)

        if use_fallback:
            fallbacks += 1
            spin.update(f"Block {block_idx}/{total_blocks}  "
                        f"{dim(f'[{base}-{base+count-1}]')}  "
                        f"{C.YELLOW}fallback mode{C.RESET}")
            results = try_individual(base, count)

        if results:
            for addr, r1, r2, v in results:
                discovered[addr] = (r1, r2, v)

        time.sleep(0.05)

    spin.stop(f"Scan complete — {len(discovered)} registers found"
              + (f"  {dim(f'({fallbacks} blocks used fallback)')}" if fallbacks else ""))

    if not discovered:
        print(f"\n  {medium('[~] No readable registers found in range 0-{SCAN_RANGE-1}')}")
    else:
        print()
        print(f"  {C.BOLD}{'ADDR':<8} {'INFERRED LABEL':<30} {'VALUE':>12}  RAW{C.RESET}")
        print(f"  {dim('─'*68)}")

        temp_vals = []
        for addr, (r1, r2, v) in sorted(discovered.items()):
            label, kind = infer_label(addr, v, counters)

            if kind == 'kelvin':
                celsius = v - 273.15
                val_str = (f"{C.YELLOW}{v:>8.2f} K{C.RESET}  "
                           f"{dim(f'({celsius:.2f}C)')}")
            elif kind == 'celsius':
                color = C.RED if v > 60 else C.ORANGE if v > 45 else C.GREEN
                val_str = f"{color}{C.BOLD}{v:>10.4f}{C.RESET}"
                temp_vals.append(v)
            elif kind == 'ratio':
                val_str = f"{C.CYAN}{v:>10.4f}{C.RESET}"
            else:
                val_str = f"{C.WHITE}{v:>10.4f}{C.RESET}"

            raw_str = dim(f"0x{r1:04x} 0x{r2:04x}")
            print(f"  {C.BOLD}[{addr:04d}]{C.RESET}  {label:<30} {val_str}  {raw_str}")

        print(f"\n  {dim('─'*68)}")
        print(f"  {dim('Registers found :')} {bold(str(len(discovered)))}")
        if fallbacks:
            print(f"  {dim('Fallback blocks :')} {medium(str(fallbacks))}")
        if temp_vals:
            print(f"  {dim('Value range     :')} "
                  f"{C.GREEN}{min(temp_vals):.2f}{C.RESET} "
                  f"{dim('to')} "
                  f"{C.RED}{max(temp_vals):.2f}{C.RESET}")
else:
    print(f"\n  {dim('Register scan skipped.')}")

client.close()

# ── OPTIONAL: SECURITY FINDINGS ──────────────────────────────
print(f"\n{C.CYAN}{'─'*60}{C.RESET}")
print()
if not ask("Display security findings and recommendations?"):
    print(f"\n  {dim('Security report skipped. Exiting.')}\n")
    sys.exit(0)

print(f"\n{C.BOLD}{C.CYAN}{'═'*60}{C.RESET}")
print(f"{C.BOLD}{C.WHITE}{'[ SECURITY FINDINGS ]'.center(60)}{C.RESET}")
print(f"{C.BOLD}{C.CYAN}{'═'*60}{C.RESET}\n")

findings = [
    (
        critical, "CRITICAL",
        "No authentication mechanism",
        "Modbus TCP has no native authentication. Any host on\n"
        "   the network can read all registers and send write\n"
        "   commands without credentials, tokens, or identity\n"
        "   verification of any kind."
    ),
    (
        critical, "CRITICAL",
        "Unauthenticated write to digital output (FC05 / Coil 0)",
        "Coil 0 accepts write commands with zero restriction.\n"
        "   Depending on what this coil drives (relay, valve,\n"
        "   actuator), an attacker can trigger physical changes\n"
        "   in the process with a single unauthenticated packet."
    ),
    (
        high, "HIGH",
        "Full sensor data exposed without access control (FC03)",
        "All mapped temperature registers are readable by anyone\n"
        "   on the network. This leaks real-time operational data\n"
        "   which can be used to profile the environment before\n"
        "   a targeted or destructive attack."
    ),
    (
        high, "HIGH",
        "No network-level segmentation observed",
        "Device responds directly on port 502 with no evidence\n"
        "   of a Modbus-aware firewall or industrial gateway\n"
        "   filtering Function Codes. A firewall (e.g. Tofino,\n"
        "   Moxa) should restrict FCs and address ranges per zone."
    ),
    (
        medium, "MEDIUM",
        "FC16 blocked by firmware, not by network controls",
        "Write Multiple Registers returns exception code 4\n"
        "   (device failure), not code 1 (function not supported).\n"
        "   The firmware processes the command before rejecting --\n"
        "   protection could be bypassed on other addresses or\n"
        "   firmware versions."
    ),
]

for color_fn, severity, title, detail in findings:
    print(f"  {color_fn(f'[{severity}]')}")
    print(f"  {C.BOLD}{C.WHITE}{title}{C.RESET}")
    print(f"   {C.GRAY}{detail}{C.RESET}")
    print()

print(f"{C.CYAN}{'─'*60}{C.RESET}")
print(f"  {ok('[RECOMMENDATIONS]')}\n")

recs = [
    "Deploy a Modbus-aware firewall to whitelist allowed FCs\n     per source IP and address range.",
    "If FC05 is not required remotely, block it at network level\n     to eliminate unauthenticated coil write access.",
    "Migrate to a protocol with native authentication (e.g.\n     OPC-UA) where the process and hardware allow.",
    "Implement OT network monitoring (e.g. Claroty, Dragos)\n     to alert on anomalous Modbus write commands.",
    "Isolate the OT network from IT and restrict port 502\n     to known engineering workstations only.",
    "Enable logging of all Modbus transactions at the gateway\n     level for incident response and audit trail.",
]

for i, rec in enumerate(recs, 1):
    print(f"  {C.CYAN}{i}.{C.RESET} {rec}\n")

print(f"{C.BOLD}{C.CYAN}{'═'*60}{C.RESET}")
print(f"{C.GRAY}{('Assessment complete — ' + datetime.now().strftime('%Y-%m-%d %H:%M:%S')).center(60)}{C.RESET}")
print(f"{C.BOLD}{C.CYAN}{'═'*60}{C.RESET}\n")
