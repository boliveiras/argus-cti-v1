#!/usr/bin/env python3
"""Curadoria CTI via LLM: seleciona, traduz e estrutura noticias.

Regra Mestra (anti-fabricacao): TTPs e IOCs alimentam bloqueios em producao e
regras de SIEM — um indicador inventado gera bloqueio indevido ou falso senso
de cobertura. Por isso o prompt exige extracao SOMENTE do texto fornecido, e
a saida do LLM passa por validacao deterministica (schema, formato de CVE e
TTP, defang de dominios/URLs) antes de entrar no boletim. LLM e tratado como
entrada nao confiavel: JSON parseado com json.loads, nunca eval.
"""

import json
import re
import unicodedata

CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$")
TTP_RE = re.compile(r"^T\d{4}(\.\d{3})?$")
CRITICIDADES = {"CRITICO", "ALTO", "MEDIO", "BAIXO", "INFO"}
IOC_TIPOS = {"IP", "Dominio C2", "URL C2", "SHA256", "MD5", "E-mail",
             "Pacote npm", "Pacote PyPI", "Arquivo", "Hunting (SIEM)"}
# Nomenclatura: "Hunting" e o termo padrao nos relatorios; variantes em PT
# vindas do LLM sao normalizadas antes da validacao.
_TIPO_ALIASES = {"caca (siem)": "Hunting (SIEM)", "caça (siem)": "Hunting (SIEM)",
                 "hunting": "Hunting (SIEM)", "hunt (siem)": "Hunting (SIEM)"}
DEFANG_TIPOS = {"Dominio C2", "URL C2", "E-mail"}


class CurationError(RuntimeError):
    """Saida do LLM invalida ou impossivel de validar."""


SYSTEM_CURADOR = (
    "Voce e um analista senior de Cyber Threat Intelligence (CTI) que apoia times "
    "SOC/CSIRT/DFIR. Voce responde SEMPRE com JSON valido e nada mais (sem markdown, "
    "sem cercas de codigo, sem comentarios). Voce NUNCA inventa fatos, CVEs, IOCs ou "
    "TTPs: usa apenas as informacoes presentes no material fornecido no prompt."
)

# Fallbacks usados quando o config.yaml nao define `priority` / `ignore`
_PRIORIDADES_DEFAULT = [
    "vulnerabilidades criticas (CVSS alto)", "exploracao ativa", "zero-day",
    "ransomware", "APT", "vazamento de dados", "phishing relevante",
    "novas TTPs", "patches criticos de grandes fornecedores",
]
_IGNORE_DEFAULT = [
    "conteudo promocional", "opiniao sem evidencia tecnica",
]


def _parse_json(text: str):
    """Parse tolerante: remove cercas de codigo e isola o primeiro JSON."""
    t = text.strip()
    t = re.sub(r"^```[a-zA-Z]*\s*", "", t)
    t = re.sub(r"\s*```$", "", t)
    try:
        return json.loads(t)
    except json.JSONDecodeError:
        pass
    starts = [i for i in (t.find("["), t.find("{")) if i >= 0]
    if not starts:
        raise CurationError("Resposta do LLM sem JSON reconhecivel")
    start = min(starts)
    end = max(t.rfind("]"), t.rfind("}"))
    if end <= start:
        raise CurationError("JSON truncado na resposta do LLM")
    try:
        return json.loads(t[start:end + 1])
    except json.JSONDecodeError as e:
        raise CurationError(f"JSON invalido na resposta do LLM: {e}") from e


def _norm_crit(v: str) -> str:
    nfkd = unicodedata.normalize("NFKD", str(v or ""))
    up = nfkd.encode("ascii", "ignore").decode("ascii").upper().strip()
    return up if up in CRITICIDADES else "INFO"


def defang(valor: str) -> str:
    """Defang de URL/dominio/e-mail (hxxp, [.]) para evitar clique acidental."""
    v = str(valor)
    v = v.replace("https://", "hxxps://").replace("http://", "hxxp://")
    if "[.]" not in v:
        v = v.replace(".", "[.]")
    return v


def select_news(client, candidatos: list[dict], max_select: int,
                technologies: list[str], priorities: list[str] | None = None,
                ignores: list[str] | None = None) -> list[dict]:
    """Pede ao LLM a triagem das candidatas mais relevantes para CTI.
    `priorities`/`ignores` vem do config.yaml (secoes `priority` e `ignore`);
    ausentes -> defaults de CTI. Retorna as escolhidas com `tecnologia`."""
    if not candidatos:
        return []
    prioridades = "; ".join(str(p) for p in (priorities or _PRIORIDADES_DEFAULT) if p)
    exclusoes = "; ".join(str(i) for i in (ignores or _IGNORE_DEFAULT) if i)
    linhas = "\n".join(f"{i}. {c['titulo']}" for i, c in enumerate(candidatos))
    foco = (f"FOCO: priorize noticias das tecnologias monitoradas: "
            f"{', '.join(technologies)}. Complete com noticias gerais se faltar.\n"
            if technologies else "")
    user = (
        f"Candidatas coletadas nos feeds (indice. titulo):\n{linhas}\n\n"
        f"{foco}"
        f"Selecione ate {max_select} HISTORIAS com maior valor para um time "
        f"SOC/CSIRT/DFIR, priorizando (em ordem): {prioridades}. "
        f"Exclua: {exclusoes}. "
        "Quando a MESMA historia aparecer em mais de uma fonte, NAO descarte: "
        "agrupe — escolha o indice da cobertura mais completa em 'i' e liste os "
        "indices das demais coberturas da mesma historia em 'duplicatas' (as fontes "
        "extras serao lidas e consolidadas na mesma noticia do boletim). "
        "Para cada historia identifique a tecnologia principal no formato curto "
        "'Fornecedor Produto' (ex: 'Fortinet FortiGate'); use \"\" se for noticia geral "
        "sem tecnologia especifica (campanhas, prisoes, relatorios).\n\n"
        'Responda apenas: [{"i": <indice>, "duplicatas": [<indices>], "tecnologia": "..."}, ...] '
        "ordenado do mais para o menos relevante ('duplicatas' = [] quando a historia "
        "so aparece em uma fonte)."
    )
    data = _parse_json(client.generate(SYSTEM_CURADOR, user))
    if not isinstance(data, list):
        raise CurationError("Selecao: esperado um array JSON")
    out, vistos = [], set()
    for item in data:
        if not isinstance(item, dict):
            continue
        try:
            idx = int(item.get("i"))
        except (TypeError, ValueError):
            continue
        if idx in vistos or not 0 <= idx < len(candidatos):
            continue
        vistos.add(idx)
        sel = dict(candidatos[idx])
        sel["tecnologia"] = str(item.get("tecnologia") or "").strip()
        # Coberturas extras da mesma historia (consolidadas na estruturacao).
        # Cap de 2 extras: limita o tamanho do prompt sem perder as fontes ricas.
        extras = []
        for d_idx in (item.get("duplicatas") or []):
            try:
                d_idx = int(d_idx)
            except (TypeError, ValueError):
                continue
            if d_idx == idx or d_idx in vistos or not 0 <= d_idx < len(candidatos):
                continue
            vistos.add(d_idx)
            extras.append(candidatos[d_idx])
            if len(extras) >= 2:
                break
        sel["extras"] = extras
        out.append(sel)
        if len(out) >= max_select:
            break
    return out


def structure_news(client, sel: dict, article_texts: list[tuple[str, str]]) -> dict:
    """Estrutura uma historia em dict validado do boletim.

    `article_texts` = [(url, texto), ...] — quando a mesma historia foi coberta
    por mais de uma fonte, TODOS os textos entram no prompt e o LLM consolida
    as informacoes (uniao de fatos, CVEs, TTPs e IOCs), sem perder o que so
    aparece em uma das coberturas."""
    urls = [u for u, _ in article_texts] or [sel.get("url", "")]
    blocos = []
    for i, (u, txt) in enumerate(article_texts, 1):
        corpo = txt or "(texto indisponivel nesta fonte)"
        blocos.append(f"--- FONTE {i}: {u} ---\n{corpo}")
    material = "\n\n".join(blocos) or (
        "(texto do artigo indisponivel — use apenas o titulo; "
        "nesse caso ttps e iocs DEVEM ser listas vazias)")
    consolidacao = (
        "Ha mais de uma fonte cobrindo a MESMA historia: consolide TODAS as "
        "informacoes relevantes em uma unica noticia — uniao de fatos, CVEs, "
        "TTPs e IOCs de todas as fontes, sem duplicar itens equivalentes. Em "
        "caso de divergencia entre fontes, prefira o dado mais especifico.\n\n"
        if len(article_texts) > 1 else "")
    user = (
        "Estruture a noticia abaixo para o boletim diario de CTI, em portugues do "
        "Brasil, sem jargao excessivo.\n\n"
        f"TITULO ORIGINAL: {sel['titulo']}\n"
        f"TECNOLOGIA (sugerida na triagem): {sel.get('tecnologia', '')}\n\n"
        f"{consolidacao}"
        f"TEXTO DAS FONTES (unica fonte de verdade):\n{material}\n\n"
        "REGRA MESTRA — NUNCA FABRICAR: cves, ttps e iocs so podem conter o que esta "
        "escrito no TEXTO acima. IOC copiado caractere a caractere. TTP so com "
        "comportamento concreto descrito no texto (campo contexto obrigatorio citando "
        "esse comportamento). Sem material suficiente -> listas vazias []. E melhor um "
        "boletim sem IOCs do que um IOC inventado.\n\n"
        "Responda apenas com o objeto JSON:\n"
        "{\n"
        '  "titulo": "titulo objetivo em PT-BR",\n'
        '  "criticidade": "CRITICO|ALTO|MEDIO|BAIXO|INFO",\n'
        '  "resumo": "3-6 frases claras",\n'
        '  "proteger": "patches, hardening, mitigacoes",\n'
        '  "impacto": "quem e afetado e riscos para empresas",\n'
        '  "acoes": ["acao imediata 1", "acao 2", "..."],\n'
        '  "tecnologia": "Fornecedor Produto ou \\"\\"",\n'
        '  "cves": ["CVE-AAAA-NNNNN citadas no texto (TODAS, sem duplicata)"],\n'
        '  "ttps": [{"id": "T1190", "nome": "nome oficial MITRE ATT&CK", '
        '"contexto": "comportamento descrito no texto"}],\n'
        '  "iocs": [{"tipo": "IP|Dominio C2|URL C2|SHA256|MD5|E-mail|Pacote npm|'
        'Pacote PyPI|Arquivo|Hunting (SIEM)", "valor": "..."}]\n'
        "}"
    )
    data = _parse_json(client.generate(SYSTEM_CURADOR, user))
    if not isinstance(data, dict):
        raise CurationError("Estruturacao: esperado um objeto JSON")
    return validate_noticia(data, fonte_urls=urls)


def validate_noticia(d: dict, fonte_urls: list[str]) -> dict:
    """Validacao deterministica da saida do LLM (nao confiavel por definicao)."""
    def txt(key, obrigatorio=True):
        v = str(d.get(key) or "").strip()
        if obrigatorio and not v:
            raise CurationError(f"Campo obrigatorio vazio: {key}")
        return v

    noticia = {
        "titulo": txt("titulo"),
        "criticidade": _norm_crit(d.get("criticidade")),
        "resumo": txt("resumo"),
        "proteger": txt("proteger"),
        "impacto": txt("impacto"),
        "tecnologia": txt("tecnologia", obrigatorio=False),
        "fontes": [u for u in fonte_urls if u],
    }

    acoes = [str(a).strip() for a in (d.get("acoes") or []) if str(a).strip()]
    if not acoes:
        raise CurationError("Lista de acoes vazia")
    noticia["acoes"] = acoes[:8]

    cves, seen = [], set()
    for c in d.get("cves") or []:
        c = str(c).strip().upper()
        if CVE_RE.fullmatch(c) and c not in seen:
            seen.add(c)
            cves.append(c)
    noticia["cves"] = cves

    ttps = []
    for t in d.get("ttps") or []:
        if not isinstance(t, dict):
            continue
        tid = str(t.get("id") or "").strip().upper()
        nome = str(t.get("nome") or "").strip()
        ctx = str(t.get("contexto") or "").strip()
        # Regra Mestra: sem contexto extraido da fonte, o TTP nao entra.
        if TTP_RE.fullmatch(tid) and nome and ctx:
            ttps.append({"id": tid, "nome": nome, "contexto": ctx})
    noticia["ttps"] = ttps

    iocs = []
    for i in d.get("iocs") or []:
        if not isinstance(i, dict):
            continue
        tipo = str(i.get("tipo") or "").strip()
        tipo = _TIPO_ALIASES.get(tipo.lower(), tipo)
        valor = str(i.get("valor") or "").strip()
        if not valor or tipo not in IOC_TIPOS:
            continue
        if tipo in DEFANG_TIPOS:
            valor = defang(valor)  # garante defang mesmo se o LLM esquecer
        iocs.append({"tipo": tipo, "valor": valor})
    noticia["iocs"] = iocs

    return noticia
