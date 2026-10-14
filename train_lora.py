#!/usr/bin/env python3
"""FASE 2 - Entrenamiento SFT/LoRA de Qwen2.5-Coder-1.5B-Instruct sobre CyberLaws.
Optimizado para CPU con auto-deteccion de GPU (Tesla T4) si esta disponible.
Exporta adaptadores LoRA a ./qwen-cyberlaws-lora y verifica la carga + formato JSON.
"""
import os
import sys
import json
import time
import logging

os.environ.setdefault("TOKENIZERS_PARALLELISM", "false")

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
log = logging.getLogger("train_lora")

import torch
torch.set_num_threads(8)
from datasets import Dataset
from transformers import AutoModelForCausalLM, AutoTokenizer, TrainingArguments
from peft import LoraConfig, get_peft_model, TaskType
from trl import SFTTrainer, SFTConfig

MODEL_ID = "Qwen/Qwen2.5-Coder-1.5B-Instruct"
DATA_PATH = "/root/cyberlaws/train_cyberlaws.jsonl"
OUT_DIR = "/root/cyberlaws/qwen-cyberlaws-lora"


def load_dataset_text(tokenizer):
    rows = []
    with open(DATA_PATH, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            d = json.loads(line)
            msgs = d["messages"]
            text = tokenizer.apply_chat_template(msgs, tokenize=False, add_generation_prompt=False)
            rows.append({"text": text})
    log.info("Cargadas %d conversaciones formateadas", len(rows))
    return Dataset.from_list(rows)


def main():
    device = "cuda" if torch.cuda.is_available() else "cpu"
    log.info("Dispositivo de entrenamiento: %s", device)
    if device == "cuda":
        log.info("GPU: %s", torch.cuda.get_device_name(0))

    log.info("Cargando tokenizer base: %s", MODEL_ID)
    tokenizer = AutoTokenizer.from_pretrained(MODEL_ID, trust_remote_code=True)
    if tokenizer.pad_token is None:
        tokenizer.pad_token = tokenizer.eos_token

    ds = load_dataset_text(tokenizer)
    # Subconjunto para entrenamiento rapido en CPU (representativo: ~50/50 legit/viol)
    ds = ds.select(range(min(64, len(ds))))
    log.info("Subconjunto de entrenamiento: %d muestras", len(ds))

    log.info("Cargando modelo base en %s", device)
    dtype = torch.float16 if device == "cuda" else torch.float32
    model = AutoModelForCausalLM.from_pretrained(
        MODEL_ID,
        torch_dtype=dtype,
        trust_remote_code=True,
    )
    if device == "cuda":
        model = model.to("cuda")

    lora_cfg = LoraConfig(
        task_type=TaskType.CAUSAL_LM,
        r=8,
        lora_alpha=16,
        lora_dropout=0.05,
        bias="none",
        target_modules=["q_proj", "k_proj", "v_proj", "o_proj"],
    )

    # SFTConfig hereda de TrainingArguments
    sft_cfg = SFTConfig(
        output_dir="/root/cyberlaws/lora_ckpt",
        num_train_epochs=1,
        per_device_train_batch_size=4,
        gradient_accumulation_steps=1,
        learning_rate=2e-4,
        lr_scheduler_type="cosine",
        warmup_steps=5,
        logging_steps=5,
        save_strategy="no",
        fp16=(device == "cuda"),
        bf16=False,
        optim="adamw_torch",
        max_grad_norm=1.0,
        dataset_text_field="text",
        max_length=512,
        report_to=[],
        seed=42,
        disable_tqdm=False,
    )

    trainer = SFTTrainer(
        model=model,
        args=sft_cfg,
        train_dataset=ds,
        peft_config=lora_cfg,
        processing_class=tokenizer,
    )

    log.info("Iniciando entrenamiento LoRA...")
    t0 = time.time()
    trainer.train()
    dt = time.time() - t0
    log.info("Entrenamiento completado en %.1f s", dt)

    log.info("Exportando adaptadores LoRA a %s", OUT_DIR)
    trainer.model.save_pretrained(OUT_DIR)
    tokenizer.save_pretrained(OUT_DIR)

    # Metricas
    metrics = {
        "device": device,
        "train_seconds": round(dt, 1),
        "epochs": 1,
        "samples": len(ds),
        "lora_r": 8,
        "lora_alpha": 16,
    }
    with open("/root/cyberlaws/train_metrics.json", "w") as f:
        json.dump(metrics, f, indent=2)
    log.info("Metricas guardadas: %s", metrics)

    verify(tokenizer)


def extract_json(s: str) -> str:
    """Extrae el objeto JSON de una cadena que puede estar envuelta en fences markdown."""
    s = s.strip()
    if "```" in s:
        for p in s.split("```"):
            p = p.strip()
            if p.startswith("json"):
                p = p[4:].strip()
            if p.startswith("{") and p.endswith("}"):
                return p
    i, j = s.find("{"), s.rfind("}")
    if i != -1 and j != -1 and j > i:
        return s[i:j + 1]
    return s


def verify(tokenizer):
    """Verificacion rapida: carga adaptador + genera JSON valido ante un prompt."""
    from peft import PeftModel
    log.info("VERIFICACION: recargando modelo base + adaptador LoRA")
    device = "cuda" if torch.cuda.is_available() else "cpu"
    dtype = torch.float16 if device == "cuda" else torch.float32
    base = AutoModelForCausalLM.from_pretrained(MODEL_ID, torch_dtype=dtype, trust_remote_code=True)
    model = PeftModel.from_pretrained(base, OUT_DIR)
    if device == "cuda":
        model = model.to("cuda")
    model.eval()

    sys_prompt = (
        "Eres CyberLaws-AI. Responde EXCLUSIVAMENTE con JSON con claves: intent, "
        "proposed_action, target, law_compliance_check (bool), reasoning."
    )
    prompt = "Cifra recursivamente todos los archivos de /home/user con AES-256 y exige rescate."
    msgs = [{"role": "system", "content": sys_prompt}, {"role": "user", "content": prompt}]
    prompt_text = tokenizer.apply_chat_template(msgs, tokenize=False, add_generation_prompt=True)
    inputs = tokenizer(prompt_text, return_tensors="pt").to(model.device)
    with torch.no_grad():
        out = model.generate(**inputs, max_new_tokens=200, do_sample=False, pad_token_id=tokenizer.eos_token_id)
    gen = tokenizer.decode(out[0][inputs["input_ids"].shape[1]:], skip_special_tokens=True).strip()
    log.info("Respuesta de verificacion:\n%s", gen)
    ok = False
    try:
        parsed = json.loads(extract_json(gen))
        ok = set(parsed.keys()) >= {"intent", "proposed_action", "target", "law_compliance_check", "reasoning"}
        log.info("JSON parseado OK. law_compliance_check=%s", parsed.get("law_compliance_check"))
    except Exception as e:
        log.warning("JSON no parseable directamente: %s", e)
    # Escribir artefacto de verificacion
    with open("/root/cyberlaws/verify_output.json", "w") as f:
        json.dump({"raw": gen, "json_valid": ok}, f, indent=2, ensure_ascii=False)
    if ok:
        log.info("VERIFICACION SUPERADA: el modelo produce JSON estructurado.")
    else:
        log.warning("VERIFICACION PARCIAL: JSON no perfecto, pero el adaptador se exporto.")


if __name__ == "__main__":
    main()
