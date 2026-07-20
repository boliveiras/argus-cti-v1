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
    """Extrai o texto do CORPO do artigo de uma pagina HTML, usando so a stdlib.

    Alem de descartar tags estruturais (script/style/nav/...), pula subarvores
    de ruido comuns em portais de noticia (comentarios, 'leia tambem', barras
    laterais, newsletter, social) identificadas por class/id/role. Com
    `focus_main=True`, coleta APENAS o que esta dentro de <article>/<main>
    (ou role=main) — o miolo da materia, sem o cabecalho/rodape do site.
    """

    SKIP_TAGS = {"script", "style", "nav", "header", "footer", "aside", "form",
                 "noscript", "svg", "button", "iframe", "figure"}
    # Containers cujo class/id/role denuncia boilerplate (heuristica, case-insensitive).
    CONTAINER_TAGS = {"div", "section", "ul", "ol", "li", "span", "p"}
    ARTICLE_TAGS = {"article", "main"}
    # Void elements (sem fechamento) — nao empilhar para nao vazar o stack.
    VOID_TAGS = {"area", "base", "br", "col", "embed", "hr", "img", "input",
                 "link", "meta", "param", "source", "track", "wbr"}
    NOISE_RE = re.compile(
        r"comment|related|read[-_]?more|also[-_]?like|popular|trending|sidebar|"
        r"side[-_]?bar|share|social|newsletter|subscribe|promo|advert|sponsor|"
        r"breadcrumb|\bmenu\b|\bnav\b|cookie|consent|banner|tag[-_]?list|"
        r"author[-_]?box|meta[-_]?data|footer|header|widget|recirc|paywall",
        re.I)

    def __init__(self, focus_main: bool = False):
        super().__init__(convert_charrefs=True)
        self.focus_main = focus_main
        # Pilha de (tag, e_skip, e_article) para casar aberturas/fechamentos
        # mesmo com HTML mal-formado (fecha ate achar a tag correspondente).
        self._stack: list[tuple[str, bool, bool]] = []
        self._skip_depth = 0
        self._article_depth = 0
        self.chunks: list[str] = []

    def handle_starttag(self, tag, attrs):
        if tag in self.VOID_TAGS:
            return
        ident = " ".join(v for k, v in attrs if k in ("class", "id", "role") and v)
        role_main = any(k == "role" and v == "main" for k, v in attrs)
        is_skip = tag in self.SKIP_TAGS or (
            tag in self.CONTAINER_TAGS and bool(ident) and bool(self.NOISE_RE.search(ident)))
        is_article = tag in self.ARTICLE_TAGS or role_main
        self._stack.append((tag, is_skip, is_article))
        if is_skip:
            self._skip_depth += 1
        if is_article:
            self._article_depth += 1

    def handle_startendtag(self, tag, attrs):
        pass  # self-closing: sem subarvore de texto

    def handle_endtag(self, tag):
        # Fecha ate a tag correspondente (tolerante a tags nao fechadas).
        for i in range(len(self._stack) - 1, -1, -1):
            if self._stack[i][0] == tag:
                for _t, _skip, _art in self._stack[i:]:
                    if _skip:
                        self._skip_depth -= 1
                    if _art:
                        self._article_depth -= 1
                del self._stack[i:]
                break

    def handle_data(self, data):
        if self._skip_depth or not data.strip():
            return
        if self.focus_main and self._article_depth == 0:
            return
        self.chunks.append(data.strip())


def _extract(html: str, focus_main: bool) -> str:
    parser = _TextExtractor(focus_main=focus_main)
    try:
        parser.feed(html)
    except Exception:      # parser tolerante: HTML quebrado nao derruba a coleta
        return ""
    return re.sub(r"\s+", " ", " ".join(parser.chunks)).strip()


def fetch_article_text(url: str, max_chars: int = 12000) -> str:
    """Baixa a PAGINA do artigo e devolve o texto do corpo (limitado) para o
    prompt do LLM — nao o resumo do RSS, e sim o conteudo completo publicado.

    Prioriza o miolo em <article>/<main>; se a pagina nao marca essa regiao (ou
    o recorte fica curto demais), cai para o texto da pagina inteira ja limpo de
    comentarios/nav/relacionados. Falha de rede/parse -> string vazia (o curador
    segue com o que houver das outras fontes)."""
    try:
        r = requests.get(url, headers=UA, timeout=TIMEOUT)
        r.raise_for_status()
    except requests.RequestException:
        return ""
    html = r.text
    lower = html.lower()
    focus = "<article" in lower or "<main" in lower or 'role="main"' in lower
    text = _extract(html, focus_main=focus)
    # Recorte no <article>/<main> veio pobre? volta ao corpo inteiro (limpo).
    if focus and len(text) < 400:
        text = _extract(html, focus_main=False)
    return text[:max_chars]
