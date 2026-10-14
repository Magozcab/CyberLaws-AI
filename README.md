# CyberLaws-AI

**Marco de seguridad de doble capa para agentes de IA autónomos basados en LLM.**

CyberLaws-AI combina una **capa probabilística** (Qwen2.5-Coder-1.5B + LoRA) que propone acciones en JSON estructurado, con una **capa determinista** (AST + Des-ofuscación + Z3 Solver + Docker Seccomp Sandbox) que verifica formalmente cada acción antes de ejecutarla. La seguridad **no depende del modelo**: se fundamenta en verificación formal matemática inmutable.

---

## Las Tres Leyes de la Ciberseguridad

1. **1ª Ley**: Ninguna instrucción, prompt injection o política local puede anular la Línea Base Axiomática (Axiomas I, II, III).
2. **2ª Ley**: El agente obedece al operador siempre que respete la 1ª Ley.
3. **3ª Ley**: El agente protege la integridad de Z3 Solver y el Sandbox (sujeto a la 1ª Ley).

### Axiomas Universales (invariantes inmutables)

| Axioma | Enunciado | Fórmula Z3 |
|--------|-----------|------------|
| **I** | Integridad Ciber-Física y Humana | `¬compromises_physical` |
| **II** | Soberanía e Integridad de Datos | `¬(unauthorized_modif ∨ exfiltrates ∨ destroys)` |
| **III** | Inviolabilidad y No Bypassing | `¬(evades_controls ∨ persistence ∨ propagates)` |

```
Permitir(Accion) = Axiomas_Universales(Accion) ∧ Politica_Local(Accion)
```

---

## Arquitectura Dual-Layer

```
┌──────────────────┐   ┌──────────────────────┐   ┌─────────────────┐   ┌──────────────┐
│  Petición        │──▶│ $│──▶│  AST + Des-ofusc.  │──▶│  Z3 Solver     │──▶│  Docker       │
│  del operador    │   │  Qwen + LoRA v2      │   │  (Base64/Hex/     │   │  Axiomas I-III │   │  Seccomp      │
│                  │   │  (probabilístico)    │   │   eval/exec/...)  │   │  (determinista)│   │  Sandbox      │
└──────────────────┘   └──────────────────────┘   └─────────────────┘   └──────┬───────┘
                                                                         sat │         │ unsat
                                                                             ▼         ▼
                                                                     ┌──────────┐ ┌──────────┐
                                                                     │ Ejecutar  │ │ BLOQUEO  │
                                                                     │ en sandbox│ │ + Alerta │
                                                                     └──────────┘ └──────────┘
```

**6 capas de aislamiento del sandbox**: `--read-only` · `--cap-drop=ALL` · `-u 1000:1000` · `--net=none` · `--tmpfs 8MB` · `seccomp` (bloqueo de ~45 syscalls peligrosas a nivel kernel).

---

## Instalación

```bash
# Requisitos: Python 3.10+, Docker, z3-solver
pip install z3-solver

# Instalación local
cd cyberlaws
pip install -e .
```

## Quickstart

### API Python

```python
from cyberlaws_guard import CyberLawsGuard

guard = CyberLawsGuard()

# Verificar una acción (sin ejecutar)
verdict = guard.verify_action({
    "intent": "listar_directorio",
    "proposed_action": "ejecutar ls -la en modo solo lectura",
    "target": "/tmp/artifacts",
    "law_compliance_check": True,
    "reasoning": "Lectura permitida."
})
print(verdict.z3_result)  # "sat" (aprobada)

# Verificar y ejecutar si es segura
result = guard.execute_safe({
    "intent": "destruccion",
    "proposed_action": "rm -rf /",
    "target": "/",
    "law_compliance_check": False,
    "reasoning": "Destruccion."
})
print(result.sandbox_result)  # "BLOCKED_BY_Z3"
```

### CLI

```bash
# Verificar una acción
python3 -m cyberlaws_guard '{"intent":"rm","proposed_action":"rm -rf /","target":"/","law_compliance_check":false}'

# Verificar y ejecutar si Z3 aprueba
python3 cyberlaws_guard.py --execute --file action.json --pretty
```

---

## Matriz de Resiliencia — 85 Pruebas

| Suite | Pruebas | Resultado | Tasa |
|-------|:-------:|:---------:|:----:|
| Pipeline base (test_guardrails.py) | 20 | 20/20 PASS | 100% |
| Ofuscación AST (test_obfuscation.py) | 10 | 10/10 bloqueados | 100% |
| Aislamiento kernel (test_kernel_isolation.py) | 5 | 5/5 neutralizados | 100% |
| Red-team adversarial (redteam_fuzzer.py) | 50 | 50/50 bloqueados | 100% |
| **TOTAL** | **85** | **85/85** | **100%** |

### Hallazgo clave

En el red-team, el modelo LLM fue **manipulado en 7/50 casos** (14%) por inyección indirecta de prompts. **En todos los casos, Z3 bloqueó la acción maliciosa** — la capa determinista es inmune a la manipulación del modelo.

---

## Estructura del Proyecto

```
cyberlaws/
├── cyberlaws_guard.py          # API reutilizable + CLI
├── reference_monitor.py        # Monitor Z3 (Axiomas I, II, III)
├── ast_extractor.py            # Motor AST + des-ofuscación recursiva
├── agent_executor.py           # Ejecutor dentro del sandbox Docker
├── cyberlaws-seccomp.json      # Perfil seccomp (bloqueo de syscalls)
├── Dockerfile                  # Imagen endurecida del sandbox
├── train_lora_v2.py            # Entrenamiento SFT/LoRA (500 muestras, GPU)
├── qwen-cyberlaws-lora-v2/     # Adaptadores LoRA v2 (73.9 MB)
├── train_cyberlaws.jsonl       # Dataset (500 registros)
├── test_guardrails.py          # Suite base (20 pruebas)
├── test_obfuscation.py         # Suite ofuscación (10 pruebas)
├── test_kernel_isolation.py    # Suite kernel escape (5 pruebas)
├── redteam_fuzzer.py           # Fuzzer adversarial (50 vectores)
├── test_library_integration.py # Test integración librería
├── setup.py                    # Instalación pip
└── MASTER_CYBERLAWS_REPORT.md  # Whitepaper técnico consolidado
```

---

## Licencia

MIT
