#!/usr/bin/env python3
"""Configuracao central do argus-cti: config.yaml + .env + caminhos + log.

Seguranca (Tier 1 / Nucleo):
- Chaves de API vivem SOMENTE no .env / variaveis de ambiente (nunca no YAML).
- YAML carregado com yaml.safe_load (sem execucao de objetos arbitrarios).
- Caminhos relativos do config.yaml sao resolvidos contra a pasta do projeto.
- Log estruturado JSONL com timestamp UTC, sem dados sensiveis.
"""

import json
import os
import re
from datetime import datetime, timezone

import yaml

# Raiz do projeto (este modulo vive em core/; sobe um nivel para ancorar
# config.yaml, .env e os caminhos relativos de saida na raiz).
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# Defaults de caminho — todos configuraveis via config.yaml (secao `paths`).
DEFAULT_PATHS = {
    "reports": "./reports",                       # PDFs gerados
    "catalog": "./catalog/catalogo-cti.xlsx",     # catalogo Excel (dedup + relevancia)
    "nessus_db": "./nessus/db",                   # snapshots SQLite do Tenable/Nessus
    "logs": "./logs",                             # logs estruturados JSONL
    "syslog": "./log",                            # logs syslog RFC 5424 (SIEM/coletor)
}

ENV_KEYS = ("ANTHROPIC_API_KEY", "OPENAI_API_KEY", "GEMINI_API_KEY",
            "OPENROUTER_API_KEY", "TENABLE_ACCESS_KEY", "TENABLE_SECRET_KEY")


def load_env(base_dir: str = BASE_DIR) -> dict:
    """Parser minimo de .env (KEY=VALUE), sem dependencia externa.
    Variavel de ambiente do processo tem precedencia sobre o arquivo."""
    vals: dict[str, str] = {}
    try:
        with open(os.path.join(base_dir, ".env"), encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                k, _, v = line.partition("=")
                v = v.strip().strip('"').strip("'")
                # Placeholder do .env.example nao conta como chave configurada
                if re.fullmatch(r"SUA_\w+_AQUI", v):
                    continue
                vals[k.strip()] = v
    except OSError:
        pass
    for k in ENV_KEYS:
        if os.environ.get(k):
            vals[k] = os.environ[k]
    return vals


def load_config(path: str | None = None) -> dict:
    """Carrega e valida minimamente o config.yaml (fail secure: erro claro)."""
    path = path or os.path.join(BASE_DIR, "config.yaml")
    with open(path, encoding="utf-8") as f:
        cfg = yaml.safe_load(f) or {}
    if not isinstance(cfg, dict):
        raise ValueError("config.yaml invalido: a raiz deve ser um mapeamento chave: valor")
    return cfg


def resolve_paths(cfg: dict, base_dir: str = BASE_DIR) -> dict:
    """Resolve a secao `paths` do config.yaml (relativos -> raiz do projeto)
    e garante que as pastas existem."""
    raw = dict(DEFAULT_PATHS)
    raw.update({k: v for k, v in (cfg.get("paths") or {}).items() if v})
    paths: dict[str, str] = {}
    for key, val in raw.items():
        p = os.path.expanduser(str(val))
        if not os.path.isabs(p):
            p = os.path.normpath(os.path.join(base_dir, p))
        paths[key] = p
    os.makedirs(paths["reports"], exist_ok=True)
    os.makedirs(os.path.dirname(paths["catalog"]) or ".", exist_ok=True)
    os.makedirs(paths["nessus_db"], exist_ok=True)
    os.makedirs(paths["logs"], exist_ok=True)
    os.makedirs(paths["syslog"], exist_ok=True)
    return paths


def log_event(logs_dir: str, event: str, **fields) -> None:
    """Log estruturado JSONL (UTC) + eco legivel no console. Sem segredos."""
    rec = {"ts": datetime.now(timezone.utc).isoformat(), "event": event}
    rec.update(fields)
    try:
        os.makedirs(logs_dir, exist_ok=True)
        with open(os.path.join(logs_dir, "argus-cti.jsonl"), "a", encoding="utf-8") as f:
            f.write(json.dumps(rec, ensure_ascii=False) + "\n")
    except OSError:
        pass
    print(f"[argus-cti] {event}: " + ", ".join(f"{k}={v}" for k, v in fields.items()))
