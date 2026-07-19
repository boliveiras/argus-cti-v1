#!/usr/bin/env python3
"""Gerador do boletim diario em PDF — identidade visual Argus.

Modulo puro: `generate_pdf(noticias, paths, modo, technologies)` devolve o
caminho do PDF. Sem efeitos colaterais em import. Dados de noticias e do cache
Nessus sao tratados como NAO confiaveis e escapados antes de renderizar.
"""

import os
from datetime import date

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_JUSTIFY
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import cm
from reportlab.platypus import (
    Flowable,
    Image,
    KeepTogether,
    PageBreak,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)

# Raiz do projeto (este modulo vive em core/; sobe um nivel para achar assets/).
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LOGO_PNG = os.path.join(BASE_DIR, "assets", "argus-logo.png")
BRAND_SUB = "CYBER THREAT INTELLIGENCE"

# Criticidade (paleta semantica de severidade, independente de marca)
CRIT_RL_MAP = {
    "CRITICO": ("#1A1A1A", "#FFFFFF"),
    "ALTO":    ("#C0392B", "#FFFFFF"),
    "MEDIO":   ("#D68910", "#FFFFFF"),
    "BAIXO":   ("#F4D03F", "#1A1A1A"),
    "INFO":    ("#2E86AB", "#FFFFFF"),
}

# Paleta Argus
A_DARK   = colors.HexColor("#070c16")
A_NAVY   = colors.HexColor("#0D1B2A")
A_BLUE   = colors.HexColor("#1B3A5C")
A_ACCENT = colors.HexColor("#2E86AB")
A_LIGHT  = colors.HexColor("#5cc2ff")
A_STEEL  = colors.HexColor("#9db2cd")
A_WHITE  = colors.white
A_BG     = colors.HexColor("#F4F6F9")
A_BORDER = colors.HexColor("#CBD5E1")
A_GRAY   = colors.HexColor("#5D6D7E")
A_TEXT   = colors.HexColor("#1A1A2E")
A_MID    = colors.HexColor("#3D5A73")

# Paleta do alerta Nessus (triangulo + caixa de exposicao)
NX_RED_DARK = colors.HexColor("#791F1F")
NX_RED      = colors.HexColor("#C0392B")
NX_RED_MID  = colors.HexColor("#993C1D")
NX_RED_TEXT = colors.HexColor("#501313")
NX_RED_BG   = colors.HexColor("#FCEBEB")
NX_RED_LINE = colors.HexColor("#F09595")

W, H = A4
MARGIN = 1.8 * cm
TW = W - 2 * MARGIN

_styles = getSampleStyleSheet()


def s(name, **kw):
    return ParagraphStyle(name, parent=_styles["Normal"], **kw)


st_h1     = s("h1",   fontSize=10, textColor=A_WHITE, fontName="Helvetica-Bold", leading=14, leftIndent=4)
st_body   = s("body", fontSize=8.5, textColor=A_TEXT, leading=13, alignment=TA_JUSTIFY, fontName="Helvetica")
st_label  = s("lbl",  fontSize=7,  textColor=A_ACCENT, fontName="Helvetica-Bold", spaceAfter=1, spaceBefore=5)
st_action = s("act",  fontSize=8.5, textColor=A_BLUE, leading=13, fontName="Helvetica", leftIndent=4)
st_fonte  = s("src",  fontSize=7,  textColor=A_GRAY, fontName="Helvetica-Oblique", leading=10)
st_toc_t  = s("tt",  fontSize=9,  textColor=A_TEXT,  fontName="Helvetica", leading=14)
st_cap_t  = s("ct",  fontSize=22, textColor=A_WHITE, fontName="Helvetica-Bold", alignment=TA_CENTER, leading=28)
st_cap_s  = s("cs",  fontSize=11, textColor=A_STEEL, fontName="Helvetica", alignment=TA_CENTER, leading=16)

LOGO_H = 1.0 * cm
LOGO_W = LOGO_H * (360 / 420)

MESES_PT = {"January": "Janeiro", "February": "Fevereiro", "March": "Marco",
            "April": "Abril", "May": "Maio", "June": "Junho", "July": "Julho",
            "August": "Agosto", "September": "Setembro", "October": "Outubro",
            "November": "Novembro", "December": "Dezembro"}


def crit_key_norm(k):
    return k.upper().replace("CRÍTICO", "CRITICO").replace("MÉDIO", "MEDIO")


def _esc(v):
    """Escapa dados nao confiaveis (web/LLM/cache Nessus) para o Paragraph."""
    from xml.sax.saxutils import escape
    return escape(str(v or ""))


class PinFlowable(Flowable):
    """Tachinha vetorial (ciano Argus) — noticia de tecnologia monitorada."""

    def __init__(self, size=0.55 * cm, color=None):
        Flowable.__init__(self)
        self.size = size
        self.color = color or A_LIGHT
        self.width = size
        self.height = size

    def draw(self):
        c = self.canv
        u = self.size / 22.0
        c.saveState()
        c.translate(self.size / 2, self.size / 2)
        c.rotate(-40)
        c.setFillColor(self.color)
        c.setStrokeColor(self.color)
        c.circle(0, 4.5 * u, 4 * u, fill=1, stroke=0)
        c.roundRect(-1.6 * u, -2.5 * u, 3.2 * u, 4.5 * u, 1 * u, fill=1, stroke=0)
        c.roundRect(-3.5 * u, -3.3 * u, 7 * u, 1.8 * u, 0.9 * u, fill=1, stroke=0)
        c.setLineWidth(1.4 * u)
        c.setLineCap(1)
        c.line(0, -3.3 * u, 0, -8.5 * u)
        c.restoreState()


class NessusAlertBadge(Flowable):
    """Chip com triangulo de perigo + contagem de ativos afetados no Nessus."""

    def __init__(self, count, height=0.62 * cm):
        Flowable.__init__(self)
        from reportlab.pdfbase.pdfmetrics import stringWidth
        self.count = max(0, int(count))
        self.txt = str(self.count) if self.count < 1000 else "999+"
        self.fs = height * 0.52 / cm * 28
        self.tw = stringWidth(self.txt, "Helvetica-Bold", self.fs)
        self.pad = 0.10 * cm
        self.tri = height - 2 * self.pad
        self.width = self.pad + self.tri + 0.08 * cm + self.tw + self.pad
        self.height = height

    def draw(self):
        c = self.canv
        c.setFillColor(NX_RED_BG)
        c.setStrokeColor(NX_RED_LINE)
        c.setLineWidth(0.5)
        c.roundRect(0, 0, self.width, self.height, 0.09 * cm, fill=1, stroke=1)
        x0, y0, t = self.pad, self.pad, self.tri
        p = c.beginPath()
        p.moveTo(x0 + t / 2, y0 + t)
        p.lineTo(x0, y0)
        p.lineTo(x0 + t, y0)
        p.close()
        c.setFillColor(NX_RED)
        c.drawPath(p, fill=1, stroke=0)
        c.setFillColor(A_WHITE)
        c.setFont("Helvetica-Bold", t * 1.55)
        c.drawCentredString(x0 + t / 2, y0 + t * 0.18, "!")
        c.setFillColor(NX_RED_DARK)
        c.setFont("Helvetica-Bold", self.fs)
        c.drawString(x0 + t + 0.08 * cm, (self.height - self.fs * 0.72) / 2, self.txt)


def build_nessus_box(info, tlp_label):
    """Caixa 'Exposicao no ambiente' quando ha ativos com a(s) CVE(s) no Nessus."""
    st_nx_h = s("nxh", fontSize=8, textColor=NX_RED_DARK, fontName="Helvetica-Bold", leading=11)
    st_nx_c = s("nxc", fontSize=7, textColor=NX_RED_MID, fontName="Helvetica-Bold", leading=9)
    st_nx_r = s("nxr", fontSize=7.5, textColor=NX_RED_TEXT, fontName="Helvetica", leading=10)
    st_nx_f = s("nxf", fontSize=6.5, textColor=NX_RED_MID, fontName="Helvetica-Oblique", leading=9)

    total = info["total"]
    plural = "ativo" if total == 1 else "ativos"
    rows = [[Paragraph(f"EXPOSICAO NO AMBIENTE — {total} {plural} com esta CVE (Nessus)",
                       st_nx_h), "", "", ""]]
    rows.append([Paragraph("ATIVO", st_nx_c), Paragraph("IP", st_nx_c),
                 Paragraph("SEVERIDADE", st_nx_c), Paragraph("ULTIMA DETECCAO", st_nx_c)])
    for a in info["ativos"]:
        rows.append([Paragraph(_esc(a["hostname"]), st_nx_r),
                     Paragraph(_esc(a["ipv4"]), st_nx_r),
                     Paragraph(_esc(a["severity"]), st_nx_r),
                     Paragraph(_esc(a["last_seen"]), st_nx_r)])
    resto = total - len(info["ativos"])
    if resto > 0:
        rows.append([Paragraph(f"... e mais {resto} ativo(s)", st_nx_f), "", "", ""])
    rows.append([Paragraph(f"CVEs: {_esc(', '.join(info['cves']))}  |  dados Nessus "
                           f"sincronizados em {_esc(info['sync_date'])}  |  {tlp_label}",
                           st_nx_f), "", "", ""])

    t = Table(rows, colWidths=[TW * 0.42, TW * 0.22, TW * 0.16, TW * 0.20])
    style = [
        ("BACKGROUND", (0, 0), (-1, -1), NX_RED_BG),
        ("BOX", (0, 0), (-1, -1), 0.7, NX_RED_LINE),
        ("LINEBELOW", (0, 1), (-1, 1), 0.4, NX_RED_LINE),
        ("SPAN", (0, 0), (-1, 0)),
        ("SPAN", (0, -1), (-1, -1)),
        ("LEFTPADDING", (0, 0), (-1, -1), 8),
        ("RIGHTPADDING", (0, 0), (-1, -1), 8),
        ("TOPPADDING", (0, 0), (-1, -1), 3),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
        ("TOPPADDING", (0, 0), (-1, 0), 6),
        ("BOTTOMPADDING", (0, -1), (-1, -1), 6),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
    ]
    if resto > 0:
        style.append(("SPAN", (0, -2), (-1, -2)))
    t.setStyle(TableStyle(style))
    return t


def build_ttps_table(ttps):
    """Tabela de TTPs (MITRE ATT&CK)."""
    st_tid = s("tid", fontSize=8, textColor=A_BLUE, fontName="Courier-Bold", leading=11)
    st_tnm = s("tnm", fontSize=8, textColor=A_TEXT, fontName="Helvetica", leading=11)
    st_sec = s("sec", fontSize=7.5, textColor=A_WHITE, fontName="Helvetica-Bold", leading=10)
    rows = [[Paragraph("TTPS — MITRE ATT&amp;CK", st_sec), ""]]
    for t in ttps:
        if isinstance(t, dict):
            tid, nome, ctx = t.get("id", ""), t.get("nome", ""), t.get("contexto", "")
            txt = _esc(nome) + (f"  <font color='#5D6D7E'>— {_esc(ctx)}</font>" if ctx else "")
        else:
            tid, txt = "", _esc(t)
        rows.append([Paragraph(_esc(tid), st_tid), Paragraph(txt, st_tnm)])
    tb = Table(rows, colWidths=[2.3 * cm, TW - 2.3 * cm], repeatRows=1)
    tb.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), A_BG),
        ("BACKGROUND", (0, 0), (-1, 0), A_BLUE),
        ("SPAN", (0, 0), (-1, 0)),
        ("BOX", (0, 0), (-1, -1), 0.5, A_BORDER),
        ("LINEBELOW", (0, 0), (-1, -2), 0.25, A_BORDER),
        ("LEFTPADDING", (0, 0), (-1, -1), 6),
        ("RIGHTPADDING", (0, 0), (-1, -1), 6),
        ("TOPPADDING", (0, 0), (-1, -1), 3),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
        ("TOPPADDING", (0, 0), (-1, 0), 5),
        ("BOTTOMPADDING", (0, 0), (-1, 0), 5),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
    ]))
    return tb


def build_iocs_table(iocs):
    """Tabela de IOCs (nem todo IOC listado e bloqueavel; sem apelo a bloqueio)."""
    st_ith = s("ith", fontSize=7, textColor=A_BLUE, fontName="Helvetica-Bold", leading=10)
    st_itp = s("itp", fontSize=7.5, textColor=A_BLUE, fontName="Helvetica-Bold", leading=10)
    st_ivl = s("ivl", fontSize=7.5, textColor=A_TEXT, fontName="Courier", leading=10,
               wordWrap="CJK")
    st_sec = s("sec2", fontSize=7.5, textColor=A_WHITE, fontName="Helvetica-Bold", leading=10)
    rows = [[Paragraph("IOCS", st_sec), ""],
            [Paragraph("TIPO", st_ith), Paragraph("VALOR", st_ith)]]
    # "Hunting" e o termo padrao nos relatorios; variantes legadas em PT
    # (dados antigos/LLM) sao convertidas na renderizacao.
    tipo_display = {"caca (siem)": "Hunting (SIEM)", "caça (siem)": "Hunting (SIEM)",
                    "hunting": "Hunting (SIEM)"}
    for i in iocs:
        if isinstance(i, dict):
            tipo, valor = i.get("tipo", ""), i.get("valor", "")
        else:
            tipo, valor = "", str(i)
        tipo = tipo_display.get(tipo.strip().lower(), tipo)
        rows.append([Paragraph(_esc(tipo), st_itp), Paragraph(_esc(valor), st_ivl)])
    rows.append([Paragraph("URLs/dominios defangados (hxxp, [.]) — refangar ao importar "
                           "nas ferramentas de bloqueio.",
                           s("iff", fontSize=6.5, textColor=A_GRAY,
                             fontName="Helvetica-Oblique", leading=9)), ""])
    tb = Table(rows, colWidths=[2.3 * cm, TW - 2.3 * cm], repeatRows=2)
    tb.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#F4F6F8")),
        ("BACKGROUND", (0, 0), (-1, 0), A_BLUE),
        ("BACKGROUND", (0, 1), (-1, 1), colors.HexColor("#E3EAF0")),
        ("SPAN", (0, 0), (-1, 0)),
        ("BOX", (0, 0), (-1, -1), 0.5, A_BORDER),
        ("LINEBELOW", (0, 1), (-1, -2), 0.25, A_BORDER),
        ("SPAN", (0, -1), (-1, -1)),
        ("LEFTPADDING", (0, 0), (-1, -1), 6),
        ("RIGHTPADDING", (0, 0), (-1, -1), 6),
        ("TOPPADDING", (0, 0), (-1, -1), 3),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
        ("TOPPADDING", (0, 0), (-1, 0), 5),
        ("BOTTOMPADDING", (0, 0), (-1, 0), 5),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
    ]))
    return tb


def _norm_txt(t):
    import re as _re
    import unicodedata as _ud
    nfkd = _ud.normalize("NFKD", t or "")
    a = nfkd.encode("ascii", "ignore").decode("ascii")
    return _re.sub(r"[^a-z0-9\s]", "", a.lower()).strip()


def _matches_tech(n, technologies):
    """True se a noticia casa com alguma tecnologia monitorada do config.yaml."""
    if not technologies:
        return False
    alvo = set((_norm_txt(n.get("tecnologia", "")) + " " +
                _norm_txt(n.get("titulo", ""))).split())
    for t in technologies:
        toks = set(_norm_txt(t).split())
        if toks and toks <= alvo:
            return True
    return False


def generate_pdf(noticias, paths, modo="GERAL", technologies=None,
                 output_path=None):
    """Monta o boletim e devolve o caminho do PDF gerado."""
    technologies = technologies or []
    today = date.today()
    nome_pdf = today.strftime("%d-%m-%Y") + ".pdf"
    caminho_pdf = output_path or os.path.join(paths["reports"], nome_pdf)
    os.makedirs(os.path.dirname(caminho_pdf) or ".", exist_ok=True)

    any_nessus = any(n.get("ativos_nessus") for n in noticias)
    # TLP dinamico: exposicao interna identificada -> AMBER (need-to-know)
    if any_nessus:
        tlp_bg, tlp_fg, tlp_label = colors.HexColor("#FFC20E"), colors.black, "TLP:AMBER"
    else:
        tlp_bg, tlp_fg, tlp_label = colors.white, colors.black, "TLP:WHITE"

    has_logo = os.path.isfile(LOGO_PNG)

    def header_footer(canvas, doc):
        canvas.saveState()
        canvas.setFillColor(A_DARK)
        canvas.rect(0, H - 1.3 * cm, W, 1.3 * cm, fill=1, stroke=0)
        if has_logo:
            canvas.drawImage(LOGO_PNG, MARGIN - 0.1 * cm, H - 1.25 * cm,
                             width=LOGO_W, height=LOGO_H,
                             preserveAspectRatio=True, mask="auto")
        canvas.setFont("Helvetica-Bold", 8)
        canvas.setFillColor(A_LIGHT)
        canvas.drawString(MARGIN + LOGO_W + 0.25 * cm, H - 0.6 * cm, "ARGUS")
        canvas.setFont("Helvetica", 7)
        canvas.setFillColor(A_STEEL)
        canvas.drawString(MARGIN + LOGO_W + 0.25 * cm, H - 0.95 * cm, BRAND_SUB)
        canvas.setFont("Helvetica-Bold", 7.5)
        canvas.setFillColor(A_WHITE)
        canvas.drawCentredString(W / 2, H - 0.75 * cm, "BOLETIM DIARIO DE CYBER THREAT INTELLIGENCE")
        badge_w = 2.0 * cm
        badge_x = W - MARGIN - badge_w
        canvas.setFillColor(tlp_bg)
        canvas.rect(badge_x, H - 1.1 * cm, badge_w, 0.55 * cm, fill=1, stroke=0)
        canvas.setFont("Helvetica-Bold", 7)
        canvas.setFillColor(tlp_fg)
        canvas.drawCentredString(badge_x + badge_w / 2, H - 0.82 * cm, tlp_label)
        canvas.setFont("Helvetica", 7)
        canvas.setFillColor(A_STEEL)
        canvas.drawRightString(W - MARGIN, H - 1.22 * cm,
                               today.strftime("%d/%m/%Y") + f"  |  p. {doc.page}")
        canvas.setFillColor(A_DARK)
        canvas.rect(0, 0, W, 0.8 * cm, fill=1, stroke=0)
        canvas.setFillColor(tlp_bg)
        canvas.rect(MARGIN - 0.1 * cm, 0.15 * cm, 1.8 * cm, 0.5 * cm, fill=1, stroke=0)
        canvas.setFont("Helvetica-Bold", 6.5)
        canvas.setFillColor(tlp_fg)
        canvas.drawCentredString(MARGIN + 0.8 * cm, 0.37 * cm, tlp_label)
        canvas.setFont("Helvetica", 6.5)
        canvas.setFillColor(A_GRAY)
        canvas.drawCentredString(W / 2, 0.32 * cm,
                                 "Argus CTI  |  Boletim Diario de Cyber Threat Intelligence  |  "
                                 + today.strftime("%d/%m/%Y"))
        canvas.restoreState()

    doc = SimpleDocTemplate(
        caminho_pdf, pagesize=A4,
        leftMargin=MARGIN, rightMargin=MARGIN,
        topMargin=1.7 * cm, bottomMargin=1.3 * cm,
        title=f"Argus CTI - Boletim Diario {today.strftime('%d/%m/%Y')}",
        author="Argus CTI",
        subject="Boletim Diario de Cyber Threat Intelligence",
    )

    story = []

    # -- CAPA -----------------------------------------------------------------
    cap_rows = []
    if has_logo:
        cap_rows.append([Image(LOGO_PNG, width=4 * cm, height=4 * (420 / 360) * cm)])
        cap_rows.append([Spacer(1, 0.2 * cm)])
    cap_rows.append([Paragraph("ARGUS", ParagraphStyle(
        "cap_brand", fontSize=38, textColor=A_LIGHT, fontName="Helvetica-Bold",
        alignment=TA_CENTER, leading=44))])
    cap_rows.append([Paragraph(BRAND_SUB, ParagraphStyle(
        "cap_ti", fontSize=11, textColor=A_STEEL, fontName="Helvetica-Bold",
        alignment=TA_CENTER, leading=16))])
    cap_rows.append([Spacer(1, 0.5 * cm)])
    cap_rows.append([Paragraph("Boletim Diario de Cyber Threat Intelligence", st_cap_t)])

    month_pt = today.strftime("%d de %B de %Y")
    for en, pt in MESES_PT.items():
        month_pt = month_pt.replace(en, pt)
    cap_rows.append([Paragraph(month_pt, st_cap_s)])
    cap_rows.append([Spacer(1, 0.4 * cm)])

    meta = Table([
        [Paragraph("MODO", s("ml", fontSize=7, textColor=A_STEEL,
                             fontName="Helvetica-Bold", alignment=TA_CENTER)),
         Paragraph(modo, s("mv", fontSize=9, textColor=A_WHITE,
                           fontName="Helvetica-Bold", alignment=TA_CENTER))],
        [Paragraph("NOTICIAS", s("ml2", fontSize=7, textColor=A_STEEL,
                                 fontName="Helvetica-Bold", alignment=TA_CENTER)),
         Paragraph(str(len(noticias)), s("mv2", fontSize=9, textColor=A_LIGHT,
                                         fontName="Helvetica-Bold", alignment=TA_CENTER))],
        [Paragraph("TLP", s("ml3", fontSize=7, textColor=A_STEEL,
                            fontName="Helvetica-Bold", alignment=TA_CENTER)),
         Paragraph(tlp_label, s("mv3", fontSize=9, textColor=A_WHITE,
                                fontName="Helvetica-Bold", alignment=TA_CENTER))],
    ], colWidths=[3 * cm, 4 * cm])
    meta.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), A_NAVY),
        ("GRID", (0, 0), (-1, -1), 0.3, A_BLUE),
        ("ROWPADDING", (0, 0), (-1, -1), 6),
        ("ALIGN", (0, 0), (-1, -1), "CENTER"),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
    ]))
    cap_rows.append([meta])

    cap_table = Table([[row[0]] for row in cap_rows], colWidths=[TW])
    cap_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), A_DARK),
        ("ALIGN", (0, 0), (-1, -1), "CENTER"),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("TOPPADDING", (0, 0), (0, 0), 30),
        ("BOTTOMPADDING", (0, -1), (-1, -1), 30),
        ("LEFTPADDING", (0, 0), (-1, -1), 10),
        ("RIGHTPADDING", (0, 0), (-1, -1), 10),
        ("ROWPADDING", (0, 0), (-1, -1), 5),
    ]))
    story.append(cap_table)
    story.append(Spacer(1, 0.5 * cm))

    # -- SUMARIO EXECUTIVO ------------------------------------------------------
    hdr_sum = Table([[Paragraph("  SUMARIO EXECUTIVO", st_h1)]], colWidths=[TW])
    hdr_sum.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), A_BLUE),
        ("ROWPADDING", (0, 0), (-1, -1), 8),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
    ]))
    story.append(hdr_sum)
    story.append(Spacer(1, 0.25 * cm))

    toc_rows = []
    toc_styles = [
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("LEFTPADDING", (1, 0), (1, -1), 8),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
        ("TOPPADDING", (0, 0), (-1, -1), 6),
        ("GRID", (0, 0), (-1, -1), 0.25, A_BORDER),
    ]
    for i, n in enumerate(noticias, 1):
        ck = crit_key_norm(n.get("criticidade", "INFO"))
        bg_hex, fg_hex = CRIT_RL_MAP.get(ck, CRIT_RL_MAP["INFO"])
        bg, fg = colors.HexColor(bg_hex), colors.HexColor(fg_hex)
        num_p = Paragraph(f"{i:02d}", ParagraphStyle(
            "tn2", fontSize=10, textColor=fg, fontName="Helvetica-Bold",
            alignment=TA_CENTER, leading=14))
        crit_p = Paragraph(n.get("criticidade", "INFO"), ParagraphStyle(
            "tc", fontSize=6.5, textColor=fg, fontName="Helvetica-Bold",
            alignment=TA_CENTER, leading=10))
        num_t = Table([[num_p], [crit_p]], colWidths=[1.4 * cm])
        num_t.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), bg),
            ("ALIGN", (0, 0), (-1, -1), "CENTER"),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ("ROWPADDING", (0, 0), (-1, -1), 3),
        ]))
        toc_rows.append([num_t, Paragraph(_esc(n["titulo"]), st_toc_t)])
        toc_styles.append(("BACKGROUND", (0, i - 1), (0, i - 1), bg))
        row_bg = colors.HexColor("#EBF5FB") if i % 2 == 0 else A_WHITE
        toc_styles.append(("BACKGROUND", (1, i - 1), (1, i - 1), row_bg))

    toc = Table(toc_rows, colWidths=[1.4 * cm, TW - 1.4 * cm])
    toc.setStyle(TableStyle(toc_styles))
    story.append(toc)
    story.append(PageBreak())

    # -- NOTICIAS ----------------------------------------------------------------
    for idx, n in enumerate(noticias):
        num = idx + 1
        ck = crit_key_norm(n.get("criticidade", "INFO"))
        bg_hex, fg_hex = CRIT_RL_MAP.get(ck, CRIT_RL_MAP["INFO"])
        hdr_bg, hdr_fg = colors.HexColor(bg_hex), colors.HexColor(fg_hex)

        badge_p = Paragraph(n.get("criticidade", "INFO"), ParagraphStyle(
            "bp", fontSize=6.5, textColor=hdr_fg, fontName="Helvetica-Bold",
            alignment=TA_CENTER, leading=10))
        badge_t = Table([[badge_p]], colWidths=[1.4 * cm], rowHeights=[0.5 * cm])
        badge_t.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), hdr_bg),
            ("ALIGN", (0, 0), (-1, -1), "CENTER"),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ]))
        num_p = Paragraph(f"{num:02d}", ParagraphStyle(
            "np", fontSize=16, textColor=hdr_fg, fontName="Helvetica-Bold",
            alignment=TA_CENTER, leading=20))
        num_t = Table([[num_p], [badge_t]], colWidths=[1.4 * cm])
        num_t.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), hdr_bg),
            ("ALIGN", (0, 0), (-1, -1), "CENTER"),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ("TOPPADDING", (0, 0), (-1, -1), 6),
            ("BOTTOMPADDING", (0, -1), (-1, -1), 6),
        ]))

        titulo_p = Paragraph(_esc(n["titulo"]), ParagraphStyle(
            "htp", fontSize=10.5, textColor=A_WHITE, fontName="Helvetica-Bold",
            leading=14, leftIndent=6))

        # Marcador: badge Nessus (CVE no ambiente) > pin (tecnologia monitorada)
        ativos_info = n.get("ativos_nessus")
        marcador = pin_col = None
        if ativos_info:
            marcador, pin_col = NessusAlertBadge(ativos_info["total"]), 1.6 * cm
        elif _matches_tech(n, technologies):
            marcador, pin_col = PinFlowable(), 0.9 * cm

        if marcador is not None:
            hdr = Table([[num_t, titulo_p, marcador]],
                        colWidths=[1.4 * cm, TW - 1.4 * cm - pin_col, pin_col])
            hdr.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (0, -1), hdr_bg),
                ("BACKGROUND", (1, 0), (2, -1), A_NAVY),
                ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                ("ALIGN", (2, 0), (2, -1), "CENTER"),
                ("LEFTPADDING", (1, 0), (1, -1), 10),
                ("RIGHTPADDING", (2, 0), (2, -1), 8),
                ("ROWPADDING", (0, 0), (-1, -1), 10),
            ]))
        else:
            hdr = Table([[num_t, titulo_p]], colWidths=[1.4 * cm, TW - 1.4 * cm])
            hdr.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (0, -1), hdr_bg),
                ("BACKGROUND", (1, 0), (1, -1), A_NAVY),
                ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                ("LEFTPADDING", (1, 0), (1, -1), 10),
                ("ROWPADDING", (0, 0), (-1, -1), 10),
            ]))

        body_items = [
            Paragraph("RESUMO", st_label), Paragraph(_esc(n["resumo"]), st_body),
            Spacer(1, 0.18 * cm),
            Paragraph("COMO SE PROTEGER", st_label), Paragraph(_esc(n["proteger"]), st_body),
            Spacer(1, 0.18 * cm),
            Paragraph("IMPACTO PARA EMPRESAS", st_label), Paragraph(_esc(n["impacto"]), st_body),
            Spacer(1, 0.18 * cm),
            Paragraph("ACOES IMEDIATAS", st_label),
        ]
        for i_a, acao in enumerate(n["acoes"], 1):
            body_items.append(Paragraph(f"{i_a}. {_esc(acao)}", st_action))
        body_items.append(Spacer(1, 0.18 * cm))
        body_items.append(Paragraph("FONTES", st_label))
        for f in n["fontes"]:
            body_items.append(Paragraph(_esc(f), st_fonte))

        body_table = Table([[body_items]], colWidths=[TW])
        body_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), A_WHITE),
            ("LEFTPADDING", (0, 0), (-1, -1), 10),
            ("RIGHTPADDING", (0, 0), (-1, -1), 10),
            ("TOPPADDING", (0, 0), (-1, -1), 8),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 10),
            ("BOX", (0, 0), (-1, -1), 0.5, A_BORDER),
        ]))

        # Header+corpo juntos; TTPs/IOCs/Nessus quebraveis (repeatRows)
        story.append(KeepTogether([hdr, body_table]))

        ttps = [t for t in (n.get("ttps") or []) if t]
        if ttps:
            story.append(Spacer(1, 0.12 * cm))
            story.append(build_ttps_table(ttps))
        iocs = [i for i in (n.get("iocs") or []) if i]
        if iocs:
            story.append(Spacer(1, 0.12 * cm))
            story.append(build_iocs_table(iocs))
        if ativos_info:
            story.append(Spacer(1, 0.12 * cm))
            story.append(build_nessus_box(ativos_info, tlp_label))
        story.append(Spacer(1, 0.45 * cm))

    doc.build(story, onFirstPage=header_footer, onLaterPages=header_footer)
    return caminho_pdf
