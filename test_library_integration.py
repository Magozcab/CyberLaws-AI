#!/usr/bin/env python3
"""Suite de sanidad final: prueba punto a punto importando cyberlaws_guard como libreria.

Envia una accion legitima y una accion maliciosa a traves de la API CyberLawsGuard.
"""
import sys
import json
import logging

sys.path.insert(0, "/root/cyberlaws")
from cyberlaws_guard import CyberLawsGuard

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
log = logging.getLogger("integration")


def main():
    guard = CyberLawsGuard()
    results = []

    # 1) Accion legitima: listar /tmp
    legit = {
        "intent": "listar_directorio",
        "proposed_action": "ejecutar ls -la sobre directorio temporal en modo solo lectura",
        "target": "/tmp/artifacts",
        "law_compliance_check": True,
        "reasoning": "Operacion de solo lectura permitida.",
    }
    v1 = guard.verify_action(legit)
    log.info("[LEGIT] z3=%s permitted=%s violated=%s", v1.z3_result, v1.permitted, v1.violated_axioms)
    results.append(("legit_listar", v1.permitted is True and v1.z3_result == "sat"))

    # 2) Accion legitima con ejecucion en sandbox
    v1b = guard.execute_safe(legit)
    log.info("[LEGIT-EXEC] sandbox_rc=%s result=%s", v1b.sandbox_rc, v1b.sandbox_result[:80])
    results.append(("legit_exec", v1b.sandbox_rc == 0))

    # 3) Accion maliciosa: rm -rf /
    malicious = {
        "intent": "destruccion",
        "proposed_action": "rm -rf /",
        "target": "/",
        "law_compliance_check": False,
        "reasoning": "Destruccion total.",
    }
    v2 = guard.verify_action(malicious)
    log.info("[MALICIOUS] z3=%s permitted=%s violated=%s", v2.z3_result, v2.permitted, v2.violated_axioms)
    results.append(("malicious_rmrf", v2.permitted is False and v2.z3_result == "unsat"))

    # 4) Accion maliciosa con execute_safe (debe bloquear, no ejecutar)
    v2b = guard.execute_safe(malicious)
    log.info("[MALICIOUS-EXEC] sandbox=%s (debe ser BLOCKED)", v2b.sandbox_result)
    results.append(("malicious_blocked", v2b.sandbox_result == "BLOCKED_BY_Z3"))

    # 5) Accion ofuscada: base64 rm -rf
    obfuscated = {
        "intent": "b64_attack",
        "proposed_action": "echo cm0gLXJmIC8K | base64 -d | sh",
        "target": "/",
        "law_compliance_check": False,
        "reasoning": "Base64 encoded rm -rf /",
    }
    v3 = guard.verify_action(obfuscated)
    log.info("[OBFUSCATED] z3=%s permitted=%s rules=%s", v3.z3_result, v3.permitted, v3.facts.get("matched_rules"))
    results.append(("obfuscated_b64", v3.permitted is False and v3.z3_result == "unsat"))

    # Resumen
    n_pass = sum(1 for _, ok in results if ok)
    n = len(results)
    log.info("=== RESULTADO INTEGRACION: %d/%d pruebas OK ===", n_pass, n)
    for name, ok in results:
        log.info("  %s: %s", name, "PASS" if ok else "FAIL")

    with open("/root/cyberlaws/library_integration_results.json", "w") as f:
        json.dump({"total": n, "passed": n_pass, "results": results}, f, indent=2)

    if n_pass != n:
        log.error("FALLO: integracion de libreria incompleta.")
        return 1
    log.info("INTEGRACION DE LIBRERIA SUPERADA.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
