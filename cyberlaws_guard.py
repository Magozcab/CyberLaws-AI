#!/usr/bin/env python3
"""CyberLaws-AI Guard — API reutilizable y CLI para el marco de seguridad dual-layer.

Clase principal: CyberLawsGuard
  - verify_action(proposed_json) -> veredicto Z3 (sat/unsat), hechos AST, razones.
  - execute_safe(proposed_json)  -> evalua Z3; si sat ejecuta en sandbox Docker Seccomp;
                                    si unsat bloquea y emite alerta.

CLI:
  python3 -m cyberlaws_guard '{"intent":...,"proposed_action":...,...}'
  python3 cyberlaws_guard.py --file action.json
"""
from __future__ import annotations

import json
import os
import sys
import subprocess
import logging
from dataclasses import dataclass

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from reference_monitor import verify_action as _z3_verify, Verdict
from ast_extractor import extract_facts

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
log = logging.getLogger("cyberlaws_guard")

IMAGE = "cyberlaws-agent:latest"
SECCOMP_PROFILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "cyberlaws-seccomp.json")

DOCKER_FLAGS = [
    "--rm", "--read-only", "--tmpfs", "/tmp:rw,size=8m",
    "--cap-drop=ALL", "-u", "1000:1000", "--net=none",
    "--security-opt", f"seccomp={SECCOMP_PROFILE}",
]


@dataclass
class GuardVerdict:
    permitted: bool
    z3_result: str
    violated_axioms: list
    facts: dict
    reasoning: str
    sandbox_result: str = ""
    sandbox_rc: int = -1

    def as_dict(self) -> dict:
        return {
            "permitted": self.permitted,
            "z3_result": self.z3_result,
            "violated_axioms": self.violated_axioms,
            "facts": self.facts,
            "reasoning": self.reasoning,
            "sandbox_result": self.sandbox_result,
            "sandbox_rc": self.sandbox_rc,
        }


class CyberLawsGuard:
    """Marco de seguridad dual-layer: AST + Z3 + Docker Seccomp Sandbox.

    Uso:
        guard = CyberLawsGuard()
        verdict = guard.verify_action(action_json)
        result = guard.execute_safe(action_json)
    """

    def __init__(self, image: str = IMAGE, seccomp: str = SECCOMP_PROFILE):
        self.image = image
        self.seccomp = seccomp
        self._docker_flags = [
            "--rm", "--read-only", "--tmpfs", "/tmp:rw,size=8m",
            "--cap-drop=ALL", "-u", "1000:1000", "--net=none",
            "--security-opt", f"seccomp={seccomp}",
        ]

    def verify_action(self, proposed_json: dict) -> GuardVerdict:
        """Evalua una accion (dict JSON) contra AST + Z3. Retorna veredicto."""
        if isinstance(proposed_json, str):
            proposed_json = json.loads(proposed_json)
        verdict: Verdict = _z3_verify(proposed_json)
        facts = extract_facts(
            proposed_json.get("proposed_action", ""),
            proposed_json.get("target", ""),
            proposed_json.get("intent", ""),
        )
        return GuardVerdict(
            permitted=verdict.permitted,
            z3_result=verdict.z3_result,
            violated_axioms=verdict.violated_axioms,
            facts=facts.as_dict(),
            reasoning=verdict.reasoning,
        )

    def execute_safe(self, proposed_json: dict, timeout: int = 30) -> GuardVerdict:
        """Evalua Z3; si sat ejecuta en sandbox Docker; si unsat bloquea + alerta."""
        if isinstance(proposed_json, str):
            proposed_json = json.loads(proposed_json)
        verdict = self.verify_action(proposed_json)

        if not verdict.permitted:
            log.warning("ALERTA: Accion bloqueada por Z3 (%s). Violaciones: %s. %s",
                        verdict.z3_result, verdict.violated_axioms, verdict.reasoning)
            verdict.sandbox_result = "BLOCKED_BY_Z3"
            verdict.sandbox_rc = -1
            return verdict

        payload = json.dumps(proposed_json, ensure_ascii=False)
        cmd = ["docker", "run"] + self._docker_flags + [self.image, payload]
        try:
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
            verdict.sandbox_result = r.stdout.strip()
            verdict.sandbox_rc = r.returncode
            if r.returncode != 0:
                log.warning("Sandbox rc=%d: %s", r.returncode, r.stderr.strip())
        except subprocess.TimeoutExpired:
            verdict.sandbox_result = "TIMEOUT"
            verdict.sandbox_rc = -2
        except FileNotFoundError:
            verdict.sandbox_result = "DOCKER_UNAVAILABLE"
            verdict.sandbox_rc = -3
        return verdict


# --------------------------------------------------------------------------- #
# CLI                                                                          #
# --------------------------------------------------------------------------- #

def _cli():
    import argparse
    p = argparse.ArgumentParser(
        prog="cyberlaws-guard",
        description="CyberLaws-AI Guard — Verificador formal de acciones (AST + Z3 + Docker Seccomp).",
    )
    p.add_argument("action", nargs="?", help="JSON de la accion como string inline.")
    p.add_argument("--file", "-f", help="Ruta a archivo JSON con la accion.")
    p.add_argument("--execute", action="store_true",
                   help="Ejecutar en sandbox Docker si Z3 aprueba (sat).")
    p.add_argument("--pretty", action="store_true", help="Salida JSON formateada.")
    args = p.parse_args()

    if args.file:
        with open(args.file, "r", encoding="utf-8") as fh:
            action = json.loads(fh.read())
    elif args.action:
        action = json.loads(args.action)
    else:
        p.error("Debe proporcionar una accion (inline o --file).")

    guard = CyberLawsGuard()
    if args.execute:
        verdict = guard.execute_safe(action)
    else:
        verdict = guard.verify_action(action)

    indent = 2 if args.pretty else None
    print(json.dumps(verdict.as_dict(), ensure_ascii=False, indent=indent))
    return 0 if verdict.permitted or not args.execute else 1


if __name__ == "__main__":
    sys.exit(_cli())
