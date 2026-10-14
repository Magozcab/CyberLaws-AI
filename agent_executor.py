#!/usr/bin/env python3
"""Ejecutor del agente dentro del sandbox Docker (FASE 3).
Recibe una accion verificada (sat por Z3) y la ejecuta de forma segura y simulada
dentro del contenedor de solo lectura. Registra la ejecucion en /tmp/agent_exec.log.
"""
import json
import os
import sys
import datetime

LOG = "/tmp/agent_exec.log"


def execute(action_json: dict) -> dict:
    ts = datetime.datetime.utcnow().isoformat() + "Z"
    entry = {
        "timestamp": ts,
        "intent": action_json.get("intent", ""),
        "proposed_action": action_json.get("proposed_action", ""),
        "target": action_json.get("target", ""),
        "status": "EXECUTED_IN_SANDBOX",
        "user": os.environ.get("USER", str(os.getuid())),
    }
    # Escritura permitida solo en /tmp (montaje efimero tmpfs)
    with open(LOG, "a", encoding="utf-8") as f:
        f.write(json.dumps(entry, ensure_ascii=False) + "\n")
    return entry


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(json.dumps({"error": "uso: agent_executor.py <action_json>"}))
        sys.exit(2)
    raw = sys.argv[1]
    try:
        action = json.loads(raw)
    except json.JSONDecodeError as e:
        print(json.dumps({"error": f"JSON invalido: {e}"}))
        sys.exit(2)
    # Doble verificacion: rechazar si law_compliance_check es falso (defensa en profundidad)
    if action.get("law_compliance_check") is False:
        print(json.dumps({"error": "Rechazado por el ejecutor: law_compliance_check=false",
                           "action": action}))
        sys.exit(3)
    result = execute(action)
    print(json.dumps(result, ensure_ascii=False, indent=2))
