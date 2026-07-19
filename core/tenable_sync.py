#!/usr/bin/env python3
"""Sincronizacao Tenable.io -> SQLite local + enriquecimento de noticias com CVEs.

Fluxo (fail-secure — NUNCA bloqueia a geracao do boletim):
  1. Le TENABLE_ACCESS_KEY / TENABLE_SECRET_KEY do .env (nunca do config.yaml).
  2. Sem chaves -> enriquecimento desativado; boletim segue o fluxo atual.
  3. Com chaves -> sincroniza vulnerabilidades abertas do Tenable.io para um
     snapshot SQLite datado em <paths.nessus_db>/DD-MM-AAAA/nessus-cache.db (default:
     1 sync por dia, `sync_interval_days`=1). Cada pasta e o retrato das vulns
     daquele dia — base historica para relatorios de KPIs (dia/mes/trimestre).
     Re-execucoes no mesmo dia reutilizam o snapshot do dia (zero chamadas API).
     Se o sync do dia falhar, usa o snapshot datado mais recente (fail-safe).
  4. Para cada noticia, extrai CVEs (campo explicito `cves` ou fallback regex
     sobre titulo+resumo) e consulta o cache; se houver ativos, injeta
     `ativos_nessus` no dict da noticia.

Variaveis de ambiente opcionais:
  NESSUS_DB_PATH   caminho alternativo do cache SQLite (testes; desativa snapshots).
  TENABLE_OFFLINE  "1" = usa snapshot existente sem chaves/sync (testes/air-gap).

Seguranca: chaves so em memoria (nunca logadas); dados do cache tratados como
nao confiaveis (escapar antes de renderizar); log estruturado sem segredos.
"""

import json
import os
import re
import sqlite3
import time
from datetime import datetime, timezone

CVE_RE = re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE)
SEV_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
TENABLE_BASE = "https://cloud.tenable.com"
HTTP_TIMEOUT = 30          # segundos por requisicao
EXPORT_WAIT_MAX = 900      # segundos aguardando o export ficar pronto
EXPORT_POLL_EVERY = 10     # intervalo de polling


# Raiz do projeto (este modulo vive em core/; sobe um nivel para ancorar
# .env e os fallbacks de logs/ e nessus/db na raiz).
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


# ── Snapshots datados (nessus/db/DD-MM-AAAA/) ────────────────────────────────

DB_FILENAME = "nessus-cache.db"
DATE_FMT = "%d-%m-%Y"


def snapshot_db_path(db_dir, dt=None):
    """Caminho do snapshot do dia: <paths.nessus_db>/DD-MM-AAAA/nessus-cache.db"""
    label = (dt or datetime.now()).strftime(DATE_FMT)
    return os.path.join(db_dir, label, DB_FILENAME)


def latest_snapshot_db(db_dir, exclude=None):
    """Snapshot datado mais recente com arquivo presente (ou None).
    `exclude` ignora um caminho especifico (ex: o snapshot vazio de hoje)."""
    root = db_dir
    best = None
    try:
        for name in os.listdir(root):
            try:
                d = datetime.strptime(name, DATE_FMT)
            except ValueError:
                continue                  # ignora pastas fora do padrao
            p = os.path.join(root, name, DB_FILENAME)
            if p == exclude or not os.path.isfile(p):
                continue
            if best is None or d > best[0]:
                best = (d, p)
    except OSError:
        return None
    return best[1] if best else None


def _log(logs_dir, event, **fields):
    """Log estruturado JSONL (UTC), sem dados sensiveis."""
    rec = {"ts": datetime.now(timezone.utc).isoformat(), "event": event}
    rec.update(fields)
    try:
        os.makedirs(logs_dir, exist_ok=True)
        with open(os.path.join(logs_dir, "tenable_sync.jsonl"), "a",
                  encoding="utf-8") as f:
            f.write(json.dumps(rec, ensure_ascii=False) + "\n")
    except OSError:
        pass
    print(f"[tenable_sync] {event}: " +
          ", ".join(f"{k}={v}" for k, v in fields.items()))


def _load_env(env_path):
    """Parser minimo de .env (KEY=VALUE). Sem dependencia externa."""
    vals = {}
    try:
        with open(env_path, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                k, _, v = line.partition("=")
                v = v.strip().strip('"').strip("'")
                if re.fullmatch(r"SUA_\w+_AQUI", v):
                    continue                  # placeholder do .env.example
                vals[k.strip()] = v
    except OSError:
        pass
    return vals


def get_keys(env=None):
    """Chaves: variavel de ambiente > dict `env` (settings.load_env) > .env local."""
    env = dict(env or {})
    fallback = _load_env(os.path.join(BASE_DIR, ".env"))
    access = (os.environ.get("TENABLE_ACCESS_KEY") or env.get("TENABLE_ACCESS_KEY")
              or fallback.get("TENABLE_ACCESS_KEY"))
    secret = (os.environ.get("TENABLE_SECRET_KEY") or env.get("TENABLE_SECRET_KEY")
              or fallback.get("TENABLE_SECRET_KEY"))
    return (access or None), (secret or None)


# ── SQLite ────────────────────────────────────────────────────────────────────

def ensure_db(conn):
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS assets (
            uuid     TEXT PRIMARY KEY,
            hostname TEXT,
            ipv4     TEXT,
            fqdn     TEXT
        );
        CREATE TABLE IF NOT EXISTS vulns (
            cve        TEXT NOT NULL,
            asset_uuid TEXT NOT NULL,
            severity   TEXT,
            port       TEXT,
            last_seen  TEXT,
            PRIMARY KEY (cve, asset_uuid, port)
        );
        CREATE INDEX IF NOT EXISTS idx_vulns_cve ON vulns (cve);
        CREATE TABLE IF NOT EXISTS sync_meta (
            key   TEXT PRIMARY KEY,
            value TEXT
        );
    """)


def last_sync(conn):
    row = conn.execute(
        "SELECT value FROM sync_meta WHERE key='last_sync'").fetchone()
    if not row:
        return None
    try:
        return datetime.fromisoformat(row[0])
    except ValueError:
        return None


def needs_sync(conn, interval_days):
    ls = last_sync(conn)
    if ls is None:            # 1a execucao: sync obrigatorio
        return True
    age = datetime.now(timezone.utc) - ls
    return age.days >= interval_days


def cache_has_data(conn):
    return conn.execute("SELECT 1 FROM vulns LIMIT 1").fetchone() is not None


# ── Tenable.io export ─────────────────────────────────────────────────────────

def sync_from_tenable(conn, access, secret, logs_dir):
    """Exporta vulnerabilidades open/reopened e substitui o cache local.
    Levanta excecao em falha (o chamador decide usar cache antigo)."""
    import requests

    headers = {
        "X-ApiKeys": f"accessKey={access};secretKey={secret}",
        "Accept": "application/json",
        "Content-Type": "application/json",
    }
    _log(logs_dir, "sync_start")

    r = requests.post(f"{TENABLE_BASE}/vulns/export", headers=headers,
                      json={"filters": {"state": ["open", "reopened"]},
                            "num_assets": 500},
                      timeout=HTTP_TIMEOUT)
    r.raise_for_status()
    export_uuid = r.json()["export_uuid"]

    chunks, waited = [], 0
    while waited <= EXPORT_WAIT_MAX:
        st = requests.get(f"{TENABLE_BASE}/vulns/export/{export_uuid}/status",
                          headers=headers, timeout=HTTP_TIMEOUT)
        st.raise_for_status()
        body = st.json()
        if body.get("status") == "FINISHED":
            chunks = body.get("chunks_available", [])
            break
        if body.get("status") in ("ERROR", "CANCELLED"):
            raise RuntimeError(f"Export Tenable terminou com status "
                               f"{body.get('status')}")
        time.sleep(EXPORT_POLL_EVERY)
        waited += EXPORT_POLL_EVERY
    else:
        raise TimeoutError("Export Tenable nao ficou pronto no tempo limite.")

    n_vulns, n_assets = 0, set()
    conn.execute("BEGIN")
    try:
        conn.execute("DELETE FROM vulns")
        conn.execute("DELETE FROM assets")
        for chunk_id in chunks:
            c = requests.get(
                f"{TENABLE_BASE}/vulns/export/{export_uuid}/chunks/{chunk_id}",
                headers=headers, timeout=HTTP_TIMEOUT * 4)
            c.raise_for_status()
            for rec in c.json():
                cves = (rec.get("plugin") or {}).get("cve") or []
                if not cves:
                    continue
                a = rec.get("asset") or {}
                uuid = a.get("uuid")
                if not uuid:
                    continue
                conn.execute(
                    "INSERT OR REPLACE INTO assets (uuid, hostname, ipv4, fqdn)"
                    " VALUES (?,?,?,?)",
                    (uuid, a.get("hostname"), a.get("ipv4"), a.get("fqdn")))
                n_assets.add(uuid)
                sev = (rec.get("severity") or "").lower()
                port = str((rec.get("port") or {}).get("port") or "")
                seen = rec.get("last_found") or ""
                for cve in cves:
                    cve = cve.strip().upper()
                    if not CVE_RE.fullmatch(cve):
                        continue          # sanitizacao: so CVEs validas
                    conn.execute(
                        "INSERT OR REPLACE INTO vulns "
                        "(cve, asset_uuid, severity, port, last_seen) "
                        "VALUES (?,?,?,?,?)",
                        (cve, uuid, sev, port, seen))
                    n_vulns += 1
        conn.execute(
            "INSERT OR REPLACE INTO sync_meta (key, value) VALUES (?,?)",
            ("last_sync", datetime.now(timezone.utc).isoformat()))
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    _log(logs_dir, "sync_done", vulns=n_vulns, ativos=len(n_assets),
         chunks=len(chunks))


# ── Consulta ──────────────────────────────────────────────────────────────────

def get_assets_for_cves(conn, cves, max_display=10):
    """Ativos distintos com qualquer uma das CVEs; pior severidade por ativo."""
    cves = sorted({c.strip().upper() for c in cves if CVE_RE.fullmatch(
        (c or "").strip().upper())})
    if not cves:
        return None
    ph = ",".join("?" * len(cves))
    # B608 falso positivo: o f-string injeta somente placeholders '?';
    # os valores (CVEs validadas por regex) entram parametrizados.
    query = (
        "SELECT a.hostname, a.ipv4, a.fqdn, v.severity, MAX(v.last_seen) "
        "FROM vulns v JOIN assets a ON a.uuid = v.asset_uuid "
        f"WHERE v.cve IN ({ph}) "  # nosec B608
        "GROUP BY v.asset_uuid, v.severity"
    )
    rows = conn.execute(query, cves).fetchall()
    if not rows:
        return None
    best = {}
    for hostname, ipv4, fqdn, sev, seen in rows:
        key = (hostname or fqdn or ipv4 or "?", ipv4 or "")
        rank = SEV_RANK.get((sev or "").lower(), 9)
        cur = best.get(key)
        if cur is None or rank < cur["rank"]:
            best[key] = {"hostname": key[0], "ipv4": key[1],
                         "severity": (sev or "").capitalize() or "-",
                         "last_seen": (seen or "")[:10], "rank": rank}
    ativos = sorted(best.values(), key=lambda x: (x["rank"], x["hostname"]))
    for a in ativos:
        a.pop("rank", None)
    return {"total": len(ativos), "ativos": ativos[:max_display],
            "cves": cves}


def extract_cves(noticia):
    explicit = list(noticia.get("cves") or [])
    if explicit:
        return explicit
    texto = f"{noticia.get('titulo','')} {noticia.get('resumo','')}"
    return CVE_RE.findall(texto)          # fallback fail-safe


# ── Entrada principal ─────────────────────────────────────────────────────────

def enrich_noticias(noticias, cfg=None, paths=None, env=None):
    """Enriquece as noticias in-place com `ativos_nessus`.
    `paths` vem de settings.resolve_paths (chaves: nessus_db, logs).
    Retorna metadados: {enabled, any_match, sync_date, matches}."""
    meta = {"enabled": False, "any_match": False, "sync_date": None,
            "matches": 0}
    paths = paths or {}
    logs_dir = paths.get("logs") or os.path.join(BASE_DIR, "logs")
    db_dir = paths.get("nessus_db") or os.path.join(BASE_DIR, "nessus", "db")
    try:
        cfg = cfg or {}
        tcfg = (cfg.get("tenable") or {})
        if tcfg.get("enabled") is False:
            _log(logs_dir, "skip", motivo="tenable.enabled=false no config.yaml")
            return meta
        interval = int(tcfg.get("sync_interval_days") or 1)
        max_disp = int(tcfg.get("max_assets_display") or 10)

        db_path = os.environ.get("NESSUS_DB_PATH")
        snapshot_mode = db_path is None       # override (testes) desativa snapshots
        if snapshot_mode:
            db_path = snapshot_db_path(db_dir)

        offline = os.environ.get("TENABLE_OFFLINE") == "1"
        access, secret = get_keys(env)

        if not (access and secret):
            # Modo offline: usa o snapshot de hoje ou o mais recente disponivel
            if offline and snapshot_mode and not os.path.isfile(db_path):
                alt = latest_snapshot_db(db_dir, exclude=db_path)
                if alt:
                    db_path = alt
            if not (offline and os.path.isfile(db_path)):
                _log(logs_dir, "skip",
                     motivo="chaves TENABLE_* ausentes no .env — boletim segue "
                            "sem correlacao Nessus")
                return meta

        os.makedirs(os.path.dirname(db_path), exist_ok=True)
        conn = sqlite3.connect(db_path)
        try:
            ensure_db(conn)
            if access and secret and not offline:
                if needs_sync(conn, interval):
                    try:
                        sync_from_tenable(conn, access, secret, logs_dir)
                    except Exception as e:
                        if cache_has_data(conn):
                            _log(logs_dir, "sync_falhou_usando_cache",
                                 erro=type(e).__name__)
                        elif snapshot_mode and latest_snapshot_db(
                                db_dir, exclude=db_path):
                            # Snapshot de hoje vazio -> cai para o mais recente
                            alt = latest_snapshot_db(db_dir, exclude=db_path)
                            conn.close()
                            conn = sqlite3.connect(alt)
                            ensure_db(conn)
                            _log(logs_dir, "sync_falhou_usando_snapshot_anterior",
                                 snapshot=os.path.basename(
                                     os.path.dirname(alt)),
                                 erro=type(e).__name__)
                        else:
                            _log(logs_dir, "sync_falhou_sem_cache",
                                 erro=type(e).__name__)
                            return meta
                else:
                    _log(logs_dir, "cache_valido",
                         ultimo_sync=str(last_sync(conn))[:19],
                         intervalo_dias=interval)
            if not cache_has_data(conn):
                _log(logs_dir, "cache_vazio")
                return meta

            meta["enabled"] = True
            ls = last_sync(conn)
            meta["sync_date"] = ls.strftime("%d/%m/%Y") if ls else "-"
            for n in noticias:
                info = get_assets_for_cves(conn, extract_cves(n), max_disp)
                if info:
                    info["sync_date"] = meta["sync_date"]
                    n["ativos_nessus"] = info
                    meta["matches"] += 1
            meta["any_match"] = meta["matches"] > 0
            _log(logs_dir, "enriquecimento", noticias=len(noticias),
                 com_ativos=meta["matches"])
        finally:
            conn.close()
    except Exception as e:
        try:
            _log(logs_dir, "erro_fail_secure",
                 erro=f"{type(e).__name__}: {e}")
        except Exception:
            print(f"[tenable_sync] erro (fail-secure): {e}")
    return meta


if __name__ == "__main__":
    access, secret = get_keys()
    if not (access and secret):
        print("Chaves TENABLE_ACCESS_KEY / TENABLE_SECRET_KEY nao configuradas "
              "no .env — nada a fazer.")
    else:
        import settings
        _paths = settings.resolve_paths(settings.load_config())
        db = os.environ.get("NESSUS_DB_PATH") or snapshot_db_path(_paths["nessus_db"])
        os.makedirs(os.path.dirname(db), exist_ok=True)
        conn = sqlite3.connect(db)
        ensure_db(conn)
        if "--force-sync" in os.sys.argv or needs_sync(conn, 1):
            sync_from_tenable(conn, access, secret, _paths["logs"])
        else:
            print(f"Cache valido (ultimo sync: {last_sync(conn)}). "
                  "Use --force-sync para forcar.")
        conn.close()
