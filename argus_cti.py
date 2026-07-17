#!/usr/bin/env python3
"""argus-cti — curador diario de Cyber Threat Intelligence para SOC/CSIRT/DFIR.

Fluxo: coleta feeds -> curadoria LLM (triagem + estruturacao com Regra Mestra
anti-fabricacao) -> filtro de relevancia organizacional -> dedup via catalogo
Excel -> correlacao opcional Nessus/Tenable -> PDF (identidade Argus) ->
registro no catalogo.

Uso:
    python argus_cti.py                  # execucao completa
    python argus_cti.py --dry-run        # cura e mostra, sem gravar PDF/catalogo
    python argus_cti.py --hours 48       # janela de coleta maior
    python argus_cti.py --config x.yaml  # config alternativo
"""

import argparse
import json
import sys
import time
from datetime import date

import requests

import collector
import curator
import llm_client
import tenable_sync
from catalog_checker import append_to_catalog, check_catalog, is_duplicate, is_irrelevant
from pdf_generator import generate_pdf
from settings import load_config, load_env, log_event, resolve_paths


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(
        prog="argus-cti",
        description="Curador diario de CTI: coleta, cura via LLM e gera o boletim PDF.")
    ap.add_argument("--config", default=None, help="caminho do config.yaml")
    ap.add_argument("--max-news", type=int, default=None,
                    help="maximo de noticias no boletim (sobrepoe o config)")
    ap.add_argument("--hours", type=int, default=24,
                    help="janela de coleta em horas (default: 24)")
    ap.add_argument("--output", default=None, help="caminho alternativo do PDF")
    ap.add_argument("--dry-run", action="store_true",
                    help="coleta e cura, mas nao grava PDF nem catalogo")
    ap.add_argument("--list-models", action="store_true",
                    help="lista os modelos disponiveis no provedor configurado e sai")
    args = ap.parse_args(argv)

    # -- Configuracao (fail secure: erro claro, sem stack p/ usuario) ----------
    try:
        cfg = load_config(args.config)
    except (OSError, ValueError) as e:
        print(f"ERRO de configuracao: {e}")
        return 1
    paths = resolve_paths(cfg)
    env = load_env()
    logs = paths["logs"]

    max_news = args.max_news or int(cfg.get("max_news", 10))
    technologies = [t for t in (cfg.get("technologies") or []) if t]
    modo = "TECNOLOGIAS" if technologies else "GERAL"

    try:
        client = llm_client.create_client(cfg, env)
    except llm_client.LLMError as e:
        print(f"ERRO: {e}")
        log_event(logs, "erro_config_llm", erro=str(e))
        return 1

    if args.list_models:
        try:
            for m in client.list_models():
                print(m)
            return 0
        except llm_client.LLMError as e:
            print(f"ERRO ao listar modelos: {e}")
            return 1
        except requests.HTTPError as e:
            st = e.response.status_code if e.response is not None else "?"
            print(f"ERRO ao listar modelos: HTTP {st}")
            return 1
        except requests.RequestException as e:
            print(f"ERRO ao listar modelos: {type(e).__name__}")
            return 1

    log_event(logs, "inicio", provider=client.provider, model=client.model,
              modo=modo, max_news=max_news, dry_run=args.dry_run)

    # -- Catalogo: memoria de dedup + inteligencia de relevancia ---------------
    known = check_catalog(paths["catalog"])
    log_event(logs, "catalogo_carregado", titulos=len(known["titles"]),
              urls=len(known["urls"]), techs_classificadas=len(known["tech_relevance"]))

    # -- Coleta (fallback 48h se a janela padrao vier vazia) -------------------
    candidatos = collector.fetch_recent(cfg.get("sources"), hours=args.hours)
    if not candidatos and args.hours == 24:
        log_event(logs, "coleta_vazia_ampliando", horas=48)
        candidatos = collector.fetch_recent(cfg.get("sources"), hours=48)
    if not candidatos:
        log_event(logs, "sem_candidatas")
        print("Nenhuma noticia coletada — verifique as fontes no config.yaml.")
        return 0
    log_event(logs, "coleta", candidatas=len(candidatos))

    # -- Triagem LLM + filtros deterministicos (relevancia antes de duplicata) -
    try:
        selecionadas = curator.select_news(
            client, candidatos, max_news * 2, technologies,
            priorities=cfg.get("priority"), ignores=cfg.get("ignore"))
    except (curator.CurationError, llm_client.LLMError) as e:
        print(f"ERRO na triagem LLM: {e}")
        log_event(logs, "erro_triagem", erro=str(e)[:300])
        return 1

    finais, ign_rel, ign_dup = [], [], []
    for sel in selecionadas:
        urls_historia = [sel["url"]] + [e["url"] for e in sel.get("extras", [])]
        cand = {"titulo": sel["titulo"], "tecnologia": sel.get("tecnologia", ""),
                "fontes": urls_historia}
        irr, motivo = is_irrelevant(cand, known)
        if irr:
            ign_rel.append(motivo)
            log_event(logs, "ignorada_relevancia", titulo=sel["titulo"][:90], motivo=motivo)
            continue
        dup, motivo = is_duplicate(cand, known)
        if dup:
            ign_dup.append(motivo)
            log_event(logs, "ignorada_duplicata", titulo=sel["titulo"][:90], motivo=motivo)
            continue
        finais.append(sel)
        if len(finais) >= max_news:
            break

    if not finais:
        log_event(logs, "sem_noticias_novas", duplicatas=len(ign_dup),
                  relevancia=len(ign_rel))
        print("Nada novo hoje: todas as candidatas ja estavam no catalogo "
              "ou foram filtradas por relevancia.")
        return 0

    # -- Estruturacao por historia: consolida o texto de TODAS as fontes ------
    noticias = []
    for i_sel, sel in enumerate(finais):
        if i_sel:
            time.sleep(2)   # espaca as chamadas ao LLM (evita rajada em pico de demanda)
        textos = [(sel["url"], collector.fetch_article_text(sel["url"]))]
        for extra in sel.get("extras", []):
            t = collector.fetch_article_text(extra["url"])
            if t:                       # fonte extra ilegivel nao entra no prompt
                textos.append((extra["url"], t))
        if len(textos) > 1:
            log_event(logs, "consolidando_fontes", titulo=sel["titulo"][:80],
                      fontes=len(textos))
        try:
            noticias.append(curator.structure_news(client, sel, textos))
        except (curator.CurationError, llm_client.LLMError) as e:
            log_event(logs, "falha_estruturacao", titulo=sel["titulo"][:90],
                      erro=str(e)[:200])
    if not noticias:
        log_event(logs, "nada_estruturado")
        print("ERRO: nenhuma noticia pode ser estruturada pelo LLM.")
        return 1

    # -- Correlacao Nessus (opcional, fail-secure) ------------------------------
    nessus_meta = tenable_sync.enrich_noticias(noticias, cfg=cfg, paths=paths, env=env)

    if args.dry_run:
        print(json.dumps(noticias, ensure_ascii=False, indent=2, default=str))
        log_event(logs, "dry_run_fim", noticias=len(noticias))
        return 0

    # -- PDF + catalogo ----------------------------------------------------------
    pdf = generate_pdf(noticias, paths, modo=modo, technologies=technologies,
                       output_path=args.output)
    added = append_to_catalog(paths["catalog"], noticias, date.today(), known=known)

    com_ttps = sum(1 for n in noticias if n.get("ttps"))
    com_iocs = sum(1 for n in noticias if n.get("iocs"))
    log_event(logs, "fim", pdf=pdf, noticias=len(noticias), catalogadas=added,
              ignoradas_duplicata=len(ign_dup), ignoradas_relevancia=len(ign_rel),
              com_ttps=com_ttps, com_iocs=com_iocs,
              nessus_matches=nessus_meta.get("matches", 0))

    print("\n== argus-cti — resumo ==")
    print(f"PDF        : {pdf}")
    print(f"Modo       : {modo}" + (f" ({', '.join(technologies)})" if technologies else ""))
    print(f"Noticias   : {len(noticias)} (TTPs: {com_ttps} | IOCs: {com_iocs})")
    print(f"Ignoradas  : {len(ign_dup)} duplicata(s), {len(ign_rel)} por relevancia")
    print(f"Nessus     : {nessus_meta.get('matches', 0)} noticia(s) com ativos expostos")
    print(f"Catalogo   : {added} registro(s) novos em {paths['catalog']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
