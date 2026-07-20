#!/usr/bin/env python3
"""Logger syslog no formato RFC 5424, gravando em arquivo.

Complementa (nao substitui) o log JSONL de `settings.log_event`: aqui a saida
segue o padrao syslog RFC 5424 para consumo por SIEM/coletores (facility
`local0`). Cada linha:

    <PRI>1 TIMESTAMP HOSTNAME APP-NAME PROCID MSGID [SD] MSG

- PRI = facility*8 + severity  (local0=16; info=6 -> <134>)
- TIMESTAMP em UTC RFC 3339 com milissegundos
- SD (structured data) opcional: metricas como tokens/modelo entram aqui
- Fail-secure: falha de escrita nunca derruba a execucao do boletim.
"""

import os
import socket
from datetime import datetime, timezone

# PEN de exemplo reservado pela RFC 5424 (projeto de portfolio, sem PEN proprio).
_PEN = "32473"
_NIL = "-"
_FACILITY_LOCAL0 = 16
_SEVERITY = {
    "emerg": 0, "alert": 1, "crit": 2, "err": 3,
    "warning": 4, "notice": 5, "info": 6, "debug": 7,
}


def _pri(severity: str) -> int:
    return _FACILITY_LOCAL0 * 8 + _SEVERITY.get(severity, 6)


def _sd_escape(value) -> str:
    """Escapa os caracteres reservados em PARAM-VALUE (RFC 5424 6.3.3): \\ " ]."""
    return str(value).replace("\\", "\\\\").replace('"', '\\"').replace("]", "\\]")


def _clean(token: str, fallback: str = _NIL) -> str:
    """HOSTNAME/APP-NAME/MSGID nao podem ter espacos; vazio -> NIL ('-')."""
    t = "".join(c for c in str(token) if c.isprintable() and not c.isspace())
    return t[:48] or fallback


class SyslogLogger:
    """Escreve linhas RFC 5424 em `<log_dir>/<filename>` (append, UTF-8)."""

    def __init__(self, log_dir: str, app: str = "argus-cti",
                 filename: str = "argus-cti.log"):
        self.dir = log_dir
        self.path = os.path.join(log_dir, filename)
        self.app = _clean(app)
        self.host = _clean(socket.gethostname())
        self.pid = str(os.getpid())

    def emit(self, msgid: str, msg: str, severity: str = "info", **sd) -> str:
        """Grava uma mensagem. `sd` vira structured-data (ex.: tokens_total=1801).
        Devolve a linha formatada (util para teste/eco)."""
        ts = (datetime.now(timezone.utc)
              .isoformat(timespec="milliseconds").replace("+00:00", "Z"))
        if sd:
            params = " ".join(f'{k}="{_sd_escape(v)}"' for k, v in sd.items())
            structured = f"[{self.app}@{_PEN} {params}]"
        else:
            structured = _NIL
        line = (f"<{_pri(severity)}>1 {ts} {self.host} {self.app} {self.pid} "
                f"{_clean(msgid)} {structured} {msg}")
        try:
            os.makedirs(self.dir, exist_ok=True)
            with open(self.path, "a", encoding="utf-8") as f:
                f.write(line + "\n")
        except OSError:
            pass  # fail-secure: logar nunca quebra o boletim
        return line
