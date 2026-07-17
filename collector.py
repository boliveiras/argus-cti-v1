#!/usr/bin/env python3
"""Coleta de noticias em feeds RSS/Atom + extracao de texto de artigos.

- Toda requisicao tem timeout e User-Agent proprio.
- Fonte fora do ar nunca derruba a coleta (degradacao graciosa por fonte).
- Conteudo coletado e tratado como NAO confiavel: quem consome (curator/
  pdf_generator) valida e escapa antes de usar.
"""

import re

# Justificativa B405: feeds vem de fontes configuradas pelo usuario e o
# ElementTree do CPython nao resolve entidades externas (XXE) por padrao.
import xml.etree.ElementTree as ET  # nosec B405
from datetime import datetime, timedelta, timezone
from email.utils import parsedate_to_datetime
from html.parser import HTMLParser

import requests

UA = {"User-Agent": "argus-cti/1.0 (coletor de feeds CTI)"}
TIMEOUT = 20
MAX_PER_SOURCE = 30


def _parse_date(s: str | None):
    if not s:
        return None
    s = s.strip()
    try:
        return parsedate_to_datetime(s)          # RFC 822 (RSS)
    except (TypeError, ValueError):
        pass
    try:
        dt = datetime.fromisoformat(s.replace("Z", "+00:00"))   # ISO 8601 (Atom)
        return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
    except ValueError:
        return None


def _local(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def parse_feed(xml_text: str) -> list[dict]:
    """Extrai {titulo, url, published} de RSS 2.0 ou Atom. Tolerante a erros."""
    items: list[dict] = []
    try:
        # B314: mesmo racional do import (sem XXE no parser do CPython)
        root = ET.fromstring(xml_text)  # nosec B314
    except ET.ParseError:
        return items
    for el in root.iter():
        if _local(el.tag) not in ("item", "entry"):
            continue
        title, link, pub = None, None, None
        for ch in el:
            t = _local(ch.tag)
            if t == "title":
                title = (ch.text or "").strip()
            elif t == "link":
                link = (ch.text or "").strip() or ch.attrib.get("href", "").strip()
            elif t in ("pubDate", "published", "updated", "date") and not pub:
                pub = (ch.text or "").strip()
        if title and link and link.startswith("http"):
            items.append({"titulo": title, "url": link, "published": _parse_date(pub)})
    return items


def fetch_recent(sources: list[str] | None, hours: int = 24) -> list[dict]:
    """Coleta candidatas das ultimas `hours` horas em todas as fontes."""
    cutoff = datetime.now(timezone.utc) - timedelta(hours=hours)
    seen: set[str] = set()
    out: list[dict] = []
    for src in sources or []:
        try:
            r = requests.get(src, headers=UA, timeout=TIMEOUT)
            r.raise_for_status()
            items = parse_feed(r.text)
        except requests.RequestException as e:
            print(f"[collector] AVISO fonte inacessivel: {src} ({type(e).__name__})")
            continue
        count = 0
        for it in items[:MAX_PER_SOURCE]:
            pub = it["published"]
            if pub is not None and pub < cutoff:
                continue
            key = it["url"].split("?")[0].split("#")[0].rstrip("/").lower()
            if key in seen:
                continue
            seen.add(key)
            it["fonte"] = src
            out.append(it)
            count += 1
        print(f"[collector] {src}: {count} candidata(s) nas ultimas {hours}h")
    return out


class _TextExtractor(HTMLParser):
    """Extrai texto visivel de HTML com a stdlib (sem dependencia extra)."""

    SKIP = {"script", "style", "nav", "header", "footer", "aside", "form",
            "noscript", "svg", "button"}

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self._skip = 0
        self.chunks: list[str] = []

    def handle_starttag(self, tag, attrs):
        if tag in self.SKIP:
            self._skip += 1

    def handle_endtag(self, tag):
        if tag in self.SKIP and self._skip:
            self._skip -= 1

    def handle_data(self, data):
        if not self._skip and data.strip():
            self.chunks.append(data.strip())


def fetch_article_text(url: str, max_chars: int = 12000) -> str:
    """Baixa o artigo e devolve texto plano (limitado) para o prompt do LLM.
    Falha de rede/parse -> string vazia (o curador segue so com o titulo)."""
    try:
        r = requests.get(url, headers=UA, timeout=TIMEOUT)
        r.raise_for_status()
    except requests.RequestException:
        return ""
    parser = _TextExtractor()
    try:
        parser.feed(r.text)
    except Exception:
        return ""
    text = re.sub(r"\s+", " ", " ".join(parser.chunks))
    return text[:max_chars]
