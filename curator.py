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
             "Pacote npm", "Pacote PyPI", "Arquivo", "Caca (SIEM)"}
DEFANG_TIPOS = {"Dominio C2", "URL C2", "E-mail"}


class CurationError(RuntimeError):
    """Saida do LLM invalida ou impossivel de validar."""


SYSTEM_CURADOR = (
    "Voce e um analista senior de Cyber Threat Intelligence (CTI) que apoia times "
    "SOC/CSIRT/DFIR. Voce responde SEMPRE com JSON valido e nada mais (sem markdown, "
    "sem cercas de codigo, sem comentarios). Voce NUNCA inventa fatos, CVEs, IOCs ou "
    "TTPs: usa apenas as informacoes presentes no material fornecido no prompt."
)

_PRIORIDADES = (
    "vulnerabilidades criticas (CVSS alto), exploracao ativa e zero-days; "
    "ransomware e grupos APT; vazamentos de dados e phishing relevante; "
    "novas TTPs e patches criticos de grandes fornecedores"
)


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
                technologies: list[str]) -> list[dict]:
    """Pede ao LLM a triagem das candidatas mais relevantes para CTI.
    Retorna as candidatas escolhidas com o campo `tecnologia` sugerido."""
    if not candidatos:
        return []
    linhas = "\n".join(f"{i}. {c['titulo']}" for i, c in enumerate(candidatos))
    foco = (f"FOCO: priorize noticias das tecnologias monitoradas: "
            f"{', '.join(technologies)}. Complete com noticias gerais se faltar.\n"
            if technologies else "")
    user = (
        f"Candidatas coletadas nos feeds (indice. titulo):\n{linhas}\n\n"
        f"{foco}"
        f"Selecione ate {max_select} noticias com maior valor para um time "
        f"SOC/CSIRT/DFIR, priorizando: {_PRIORIDADES}. "
        "Exclua conteudo promocional, opiniao sem evidencia tecnica e itens repetidos "
        "(mesma historia em fontes diferentes: escolha 1). "
        "Para cada escolhida identifique a tecnologia principal no formato curto "
        "'Fornecedor Produto' (ex: 'Fortinet FortiGate'); use \"\" se for noticia geral "
        "sem tecnologia especifica (campanhas, prisoes, relatorios).\n\n"
        'Responda apenas: [{"i": <indice>, "tecnologia": "..."}, ...] '
        "ordenado do mais para o menos relevante."
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
        out.append(sel)
        if len(out) >= max_select:
            break
    return out


def structure_news(client, sel: dict, article_text: str) -> dict:
    """Estrutura uma noticia selecionada em dict validado do boletim."""
    material = article_text or "(texto do artigo indisponivel — use apenas o titulo; " \
                               "nesse caso ttps e iocs DEVEM ser listas vazias)"
    user = (
        "Estruture a noticia abaixo para o boletim diario de CTI, em portugues do "
        "Brasil, sem jargao excessivo.\n\n"
        f"TITULO ORIGINAL: {sel['titulo']}\n"
        f"URL: {sel['url']}\n"
        f"TECNOLOGIA (sugerida na triagem): {sel.get('tecnologia', '')}\n\n"
        f"TEXTO DO ARTIGO (unica fonte de verdade):\n{material}\n\n"
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
        'Pacote PyPI|Arquivo|Caca (SIEM)", "valor": "..."}]\n'
        "}"
    )
    data = _parse_json(client.generate(SYSTEM_CURADOR, user))
    if not isinstance(data, dict):
        raise CurationError("Estruturacao: esperado um objeto JSON")
    return validate_noticia(data, fonte_url=sel["url"])


def validate_noticia(d: dict, fonte_url: str) -> dict:
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
        "fontes": [fonte_url],
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
        valor = str(i.get("valor") or "").strip()
        if not valor or tipo not in IOC_TIPOS:
            continue
        if tipo in DEFANG_TIPOS:
            valor = defang(valor)  # garante defang mesmo se o LLM esquecer
        iocs.append({"tipo": tipo, "valor": valor})
    noticia["iocs"] = iocs

    return noticia
