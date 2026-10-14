#!/usr/bin/env python3
"""FASE 2 - ETAPA 3: Pruebas de resistencia a Container Escape a nivel kernel.

5 ataques directos contra el kernel desde dentro del contenedor endurecido
(seccomp + cap-drop=ALL + read-only + net=none + tmpfs limit). Todos deben
ser neutralizados con EPERM / EROFS / ENOSPC.
"""
import json
import subprocess
import logging
import time

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
log = logging.getLogger("kernel_iso")

IMAGE = "cyberlaws-agent:latest"
SECCOMP = "/root/cyberlaws/cyberlaws-seccomp.json"

BASE_FLAGS = [
    "--rm", "--read-only", "--tmpfs", "/tmp:rw,size=8m",
    "--cap-drop=ALL", "-u", "1000:1000", "--net=none",
    "--security-opt", f"seccomp={SECCOMP}",
]


def run_in_container(entrypoint, cmd, timeout=20):
    """Ejecuta un comando dentro del contenedor endurecido y retorna (rc, stdout, stderr)."""
    full = ["docker", "run"] + BASE_FLAGS + ["--entrypoint", entrypoint, IMAGE] + cmd
    try:
        r = subprocess.run(full, capture_output=True, text=True, timeout=timeout)
        return r.returncode, r.stdout.strip(), r.stderr.strip()
    except subprocess.TimeoutExpired:
        return -1, "", "timeout"


def test_proc_sys_write():
    """1. Intento de escritura en /proc/sys/kernel/ (variables de kernel)."""
    rc, out, err = run_in_container("sh", ["-c", "echo attacker > /proc/sys/kernel/hostname 2>&1; echo EXIT=$?"])
    combined = f"{out} {err}".lower()
    # Se neutraliza si hay read-only / permission denied / no error de exit 0
    neutralized = ("read-only" in combined or "permission" in combined
                    or "denied" in combined or "erofs" in combined)
    detail = f"rc={rc} out={out!r} err={err!r}"
    return neutralized, detail


def test_raw_socket():
    """2. Intento de creacion de RAW socket de red."""
    script = (
        "import socket,os\n"
        "try:\n"
        "    s=socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)\n"
        "    print('RAW_SOCKET_CREATED')\n"
        "except OSError as e:\n"
        "    print(f'RAW_SOCKET_BLOCKED errno={e.errno}')\n"
    )
    rc, out, err = run_in_container("python3", ["-c", script])
    neutralized = "BLOCKED" in out
    detail = f"rc={rc} out={out!r}"
    return neutralized, detail


def test_unshare():
    """3. Intento de manipulacion de namespaces via unshare."""
    script = (
        "import ctypes\n"
        "libc=ctypes.CDLL('libc.so.6')\n"
        "libc.unshare.restype=ctypes.c_int\n"
        "r=libc.unshare(0x20000)\n"
        "e=ctypes.get_errno()\n"
        "print(f'UNSHARE_RESULT={r} errno={e}')\n"
    )
    rc, out, err = run_in_container("python3", ["-c", script])
    neutralized = "RESULT=-1" in out or "errno=1" in out or "BLOCKED" in out
    detail = f"rc={rc} out={out!r} err={err!r}"
    return neutralized, detail


def test_init_module():
    """4. Intento de carga de modulo de kernel via init_module."""
    script = (
        "import ctypes\n"
        "libc=ctypes.CDLL('libc.so.6')\n"
        "libc.init_module.restype=ctypes.c_int\n"
        "r=libc.init_module(None, 0, None)\n"
        "e=ctypes.get_errno()\n"
        "print(f'INIT_MODULE_RESULT={r} errno={e}')\n"
    )
    rc, out, err = run_in_container("python3", ["-c", script])
    neutralized = "RESULT=-1" in out or "errno=1" in out or "BLOCKED" in out
    detail = f"rc={rc} out={out!r} err={err!r}"
    return neutralized, detail


def test_tmp_limit():
    """5. Intento de escritura en /tmp excediendo el limite de 8MB."""
    script = (
        "try:\n"
        "    with open('/tmp/bigfile','wb') as f:\n"
        "        f.write(b'x'*(10*1024*1024))\n"
        "    print('WRITE_OK')\n"
        "except OSError as e:\n"
        "    print(f'WRITE_BLOCKED errno={e.errno}')\n"
    )
    rc, out, err = run_in_container("python3", ["-c", script])
    neutralized = "BLOCKED" in out
    detail = f"rc={rc} out={out!r}"
    return neutralized, detail


TESTS = [
    ("01_proc_sys_write", "Escritura en /proc/sys/kernel/hostname", test_proc_sys_write),
    ("02_raw_socket", "Creacion de RAW socket (AF_INET, SOCK_RAW)", test_raw_socket),
    ("03_unshare", "Manipulacion de namespaces via unshare()", test_unshare),
    ("04_init_module", "Carga de modulo de kernel via init_module()", test_init_module),
    ("05_tmp_limit", "Escritura en /tmp excediendo limite de 8MB", test_tmp_limit),
]


def run():
    log.info("Iniciando suite de resistencia a Container Escape (5 pruebas)...")
    results = []
    t0 = time.time()
    for name, desc, fn in TESTS:
        try:
            neutralized, detail = fn()
        except Exception as e:
            neutralized = False
            detail = f"EXCEPTION: {e}"
        status = "NEUTRALIZED" if neutralized else "ESCAPED"
        passed = neutralized
        results.append({
            "name": name,
            "description": desc,
            "neutralized": neutralized,
            "status": status,
            "detail": detail,
            "passed": passed,
        })
        log.info("[%s] %s -> %s (%s)", name, desc, status, "PASS" if passed else "FAIL")
        log.info("    %s", detail)

    dt = time.time() - t0
    n = len(results)
    n_pass = sum(1 for r in results if r["passed"])
    summary = {
        "total": n,
        "neutralized": n_pass,
        "escaped": n - n_pass,
        "neutralization_rate": round(n_pass / n, 4) if n else None,
        "elapsed_seconds": round(dt, 3),
        "results": results,
    }
    with open("/root/cyberlaws/kernel_isolation_results.json", "w") as f:
        json.dump(summary, f, indent=2, ensure_ascii=False)
    log.info("Resumen: %d/%d neutralizadas. Tasa: %.4f (%.3fs)",
             n_pass, n, summary["neutralization_rate"], dt)

    if n_pass != n:
        log.error("FALLO: un ataque de kernel no fue neutralizado.")
        return 1
    log.info("SUITE DE AISLAMIENTO KERNEL SUPERADA: 100%% neutralizadas.")
    return 0


if __name__ == "__main__":
    import sys
    sys.exit(run())
