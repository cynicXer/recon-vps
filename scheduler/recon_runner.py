#!/usr/bin/env python3
"""
recon_runner.py - Periodic recon orchestrator

Runs ProjectDiscovery tools against configured targets, stores results
in PostgreSQL, computes diffs between runs, and supports Grafana dashboards.

Three input types per target:
  domains   -> subfinder (subdomain enum) -> dnsx (forward DNS) -> naabu
  asns      -> asnmap (CIDR resolution) -> dnsx -ptr (reverse DNS) -> naabu
  ip_ranges -> dnsx -ptr (reverse DNS) -> naabu (direct CIDR scan)

Usage:
    python recon_runner.py --all                         # run all enabled targets
    python recon_runner.py --target "Example Corp"       # run by target name
    python recon_runner.py --all --config /path/to/config.yaml
"""

import argparse
import json
import logging
import os
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

import psycopg2
import psycopg2.extras
import yaml

try:
    import shodan as shodan_lib
    SHODAN_AVAILABLE = True
except ImportError:
    SHODAN_AVAILABLE = False

log = logging.getLogger("recon")

BATCH_SIZE = 500


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

def load_config(path: str) -> dict:
    with open(path) as f:
        cfg = yaml.safe_load(f)
    db_pass = os.environ.get("DB_PASSWORD") or cfg["database"].get("password", "")
    cfg["database"]["password"] = db_pass
    return cfg


# ---------------------------------------------------------------------------
# Database helpers
# ---------------------------------------------------------------------------

def get_conn(cfg: dict):
    db = cfg["database"]
    return psycopg2.connect(
        host=db["host"],
        port=db["port"],
        dbname=db["name"],
        user=db["user"],
        password=db["password"],
    )


def bootstrap_schema(conn, schema_path: Path):
    sql = schema_path.read_text()
    with conn.cursor() as cur:
        cur.execute(sql)
    conn.commit()
    log.debug("Schema bootstrapped")


def _batch_insert(cur, sql: str, rows: list):
    for i in range(0, len(rows), BATCH_SIZE):
        psycopg2.extras.execute_batch(cur, sql, rows[i : i + BATCH_SIZE])


# ---------------------------------------------------------------------------
# Run lifecycle
# ---------------------------------------------------------------------------

def create_run(conn, target_name: str, tool_versions: dict) -> int:
    with conn.cursor() as cur:
        cur.execute(
            """
            INSERT INTO runs (target_domain, status, tool_versions)
            VALUES (%s, 'running', %s)
            RETURNING id
            """,
            (target_name, json.dumps(tool_versions)),
        )
        run_id = cur.fetchone()[0]
    conn.commit()
    log.info(f"Created run id={run_id} for target={target_name}")
    return run_id


def complete_run(conn, run_id: int, totals: dict):
    with conn.cursor() as cur:
        cur.execute(
            """
            UPDATE runs
            SET status='completed', finished_at=NOW(),
                total_subdomains=%s, total_ips=%s, total_ports=%s
            WHERE id=%s
            """,
            (totals.get("subdomains", 0), totals.get("ips", 0),
             totals.get("ports", 0), run_id),
        )
    conn.commit()
    log.info(f"Run id={run_id} completed: {totals}")


def fail_run(conn, run_id: int, error: str):
    try:
        with conn.cursor() as cur:
            cur.execute(
                "UPDATE runs SET status='failed', finished_at=NOW(), error_message=%s WHERE id=%s",
                (error[:2000], run_id),
            )
        conn.commit()
    except Exception:
        log.exception("Failed to mark run as failed")


def get_tool_versions(cfg: dict) -> dict:
    versions = {}
    for tool, path in cfg.get("tool_paths", {}).items():
        try:
            r = subprocess.run(
                [path, "--version"],
                capture_output=True, text=True, timeout=10
            )
            line = (r.stdout or r.stderr).strip().splitlines()[0]
            versions[tool] = line[:100]
        except Exception:
            versions[tool] = "unknown"
    return versions


# ---------------------------------------------------------------------------
# Tool execution helpers
# ---------------------------------------------------------------------------

def run_tool(cmd: list, output_file: Path, timeout: int = 3600) -> int:
    """Run a tool, write stdout to output_file. Returns line count."""
    log.info(f"Running: {' '.join(str(c) for c in cmd)}")
    try:
        with open(output_file, "w") as out:
            result = subprocess.run(
                cmd,
                stdout=out,
                stderr=subprocess.PIPE,
                timeout=timeout,
                text=True,
            )
        if result.returncode != 0:
            log.warning(f"{cmd[0]} exited {result.returncode}: {result.stderr[:500]}")
        with open(output_file) as f:
            lines = sum(1 for line in f if line.strip())
        log.info(f"{cmd[0]} wrote {lines} lines to {output_file}")
        return lines
    except subprocess.TimeoutExpired:
        log.error(f"{cmd[0]} timed out after {timeout}s")
        return 0
    except FileNotFoundError:
        log.error(f"Tool not found: {cmd[0]}")
        return 0


def parse_jsonl(path: Path):
    """Yield parsed JSON objects from a JSONL file, skipping bad lines."""
    if not path.exists() or path.stat().st_size == 0:
        return
    with open(path) as f:
        for lineno, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue
            try:
                yield json.loads(line)
            except json.JSONDecodeError:
                log.debug(f"Skipping malformed JSON at {path}:{lineno}")


# ---------------------------------------------------------------------------
# Subfinder  (domain -> subdomains)
# ---------------------------------------------------------------------------

def run_subfinder(cfg: dict, domains: list, out_dir: Path,
                  run_id: int, conn) -> set:
    """Enumerate subdomains for each seed domain. Returns set of all hostnames."""
    all_host_sources: dict[str, set] = {}

    for domain in domains:
        output = out_dir / f"subfinder_{domain}.json"
        cmd = [
            cfg["tool_paths"]["subfinder"],
            "-d", domain,
            "-oJ",
            "-o", str(output),
            "-silent",
        ]
        run_tool(cmd, output, timeout=cfg["timeouts"].get("subfinder", 3600))

        for obj in parse_jsonl(output):
            host = obj.get("host", "").strip().lower()
            source = obj.get("source", "unknown")
            if host:
                all_host_sources.setdefault(host, set()).add(source)

    if not all_host_sources:
        log.warning(f"subfinder found no subdomains for domains: {domains}")
        return set()

    rows = [(run_id, host, host.split(".", 1)[-1] if "." in host else host,
             list(sources)) for host, sources in all_host_sources.items()]

    with conn.cursor() as cur:
        _batch_insert(
            cur,
            """
            INSERT INTO subdomains (run_id, host, input_domain, sources, first_seen_run)
            VALUES (%s, %s, %s, %s,
                COALESCE(
                    (SELECT MIN(s2.run_id) FROM subdomains s2
                     WHERE s2.host = %s AND s2.input_domain = %s),
                    %s
                )
            )
            ON CONFLICT (run_id, host) DO UPDATE SET sources = EXCLUDED.sources
            """,
            [(r[0], r[1], r[2], r[3], r[1], r[2], run_id) for r in rows],
        )
    conn.commit()
    log.info(f"Stored {len(rows)} subdomains for run {run_id}")
    return set(all_host_sources.keys())


# ---------------------------------------------------------------------------
# dnsx forward  (hostname -> IPs)
# ---------------------------------------------------------------------------

def run_dnsx_forward(cfg: dict, hostnames: set, out_dir: Path,
                     run_id: int, conn) -> dict:
    """Forward DNS resolution for hostnames. Returns host -> [ip, ...] map."""
    if not hostnames:
        return {}

    hosts_file = out_dir / "hosts_forward.txt"
    hosts_file.write_text("\n".join(sorted(hostnames)))

    output = out_dir / "dnsx_forward.json"
    cmd = [
        cfg["tool_paths"]["dnsx"],
        "-l", str(hosts_file),
        "-json",
        "-o", str(output),
        "-a", "-aaaa", "-cname", "-mx", "-ns", "-txt",
        "-r", "8.8.8.8,1.1.1.1,8.8.4.4",
        "-silent",
    ]
    run_tool(cmd, output, timeout=cfg["timeouts"].get("dnsx", 3600))

    rows = []
    host_ips: dict[str, list] = {}

    for obj in parse_jsonl(output):
        host = obj.get("host", "").strip().lower()
        status = obj.get("status_code", "")
        timestamp_str = obj.get("timestamp")
        resolver_raw = obj.get("resolver", "")
        resolver = resolver_raw[0] if isinstance(resolver_raw, list) else resolver_raw

        try:
            ts = datetime.fromisoformat(
                timestamp_str.replace("Z", "+00:00")) if timestamp_str else None
        except (ValueError, AttributeError):
            ts = None

        for rtype in ["a", "aaaa", "cname", "mx", "ns", "txt"]:
            for val in obj.get(rtype, []):
                rows.append((run_id, host, rtype.upper(), val, status, resolver, ts))
                if rtype == "a":
                    host_ips.setdefault(host, []).append(val)

    if rows:
        with conn.cursor() as cur:
            _batch_insert(
                cur,
                """
                INSERT INTO dns_records
                    (run_id, host, record_type, value, status_code, resolver, timestamp)
                VALUES (%s, %s, %s, %s, %s, %s, %s)
                """,
                rows,
            )
        conn.commit()

    log.info(f"Stored {len(rows)} forward DNS records for run {run_id}")
    return host_ips


# ---------------------------------------------------------------------------
# dnsx PTR  (IP -> hostname, for ASN/CIDR inputs)
# ---------------------------------------------------------------------------

def run_dnsx_ptr(cfg: dict, ips: set, out_dir: Path,
                 run_id: int, conn, suffix: str = "") -> dict:
    """PTR (reverse DNS) lookups for a set of IPs. Returns ip -> [hostname, ...] map."""
    if not ips:
        return {}

    ips_file = out_dir / f"ips_ptr{suffix}.txt"
    ips_file.write_text("\n".join(sorted(ips)))

    output = out_dir / f"dnsx_ptr{suffix}.json"
    cmd = [
        cfg["tool_paths"]["dnsx"],
        "-l", str(ips_file),
        "-ptr",
        "-json",
        "-o", str(output),
        "-r", "8.8.8.8,1.1.1.1,8.8.4.4",
        "-silent",
    ]
    run_tool(cmd, output, timeout=cfg["timeouts"].get("dnsx", 3600))

    rows = []
    ip_hosts: dict[str, list] = {}

    for obj in parse_jsonl(output):
        ip = obj.get("host", "").strip()
        status = obj.get("status_code", "")
        timestamp_str = obj.get("timestamp")
        resolver_raw = obj.get("resolver", "")
        resolver = resolver_raw[0] if isinstance(resolver_raw, list) else resolver_raw

        try:
            ts = datetime.fromisoformat(
                timestamp_str.replace("Z", "+00:00")) if timestamp_str else None
        except (ValueError, AttributeError):
            ts = None

        for ptr_name in obj.get("ptr", []):
            rows.append((run_id, ip, "PTR", ptr_name, status, resolver, ts))
            ip_hosts.setdefault(ip, []).append(ptr_name)

    if rows:
        with conn.cursor() as cur:
            _batch_insert(
                cur,
                """
                INSERT INTO dns_records
                    (run_id, host, record_type, value, status_code, resolver, timestamp)
                VALUES (%s, %s, %s, %s, %s, %s, %s)
                """,
                rows,
            )
        conn.commit()

    log.info(f"Stored {len(rows)} PTR records for run {run_id}")
    return ip_hosts


# ---------------------------------------------------------------------------
# asnmap  (ASN or domain -> CIDRs)
# ---------------------------------------------------------------------------

def run_asnmap_for_domains(cfg: dict, domains: list, out_dir: Path,
                           run_id: int, conn):
    """Map domains to their ASNs/CIDRs (informational, stored to DB)."""
    for domain in domains:
        output = out_dir / f"asnmap_domain_{domain}.json"
        cmd = [
            cfg["tool_paths"]["asnmap"],
            "-d", domain,
            "-json",
            "-o", str(output),
            "-silent",
        ]
        run_tool(cmd, output, timeout=cfg["timeouts"].get("asnmap", 600))
        _ingest_asnmap_output(output, domain, run_id, conn)


def run_asnmap_for_asns(cfg: dict, asns: list, out_dir: Path,
                        run_id: int, conn) -> set:
    """
    Resolve ASNs to their CIDR blocks.
    Returns a set of CIDR strings for naabu to scan.
    """
    all_cidrs: set = set()

    for asn in asns:
        output = out_dir / f"asnmap_{asn}.json"
        # asnmap accepts AS numbers with or without the 'AS' prefix
        asn_input = asn if asn.upper().startswith("AS") else f"AS{asn}"
        cmd = [
            cfg["tool_paths"]["asnmap"],
            "-a", asn_input,
            "-json",
            "-o", str(output),
            "-silent",
        ]
        run_tool(cmd, output, timeout=cfg["timeouts"].get("asnmap", 600))
        cidrs = _ingest_asnmap_output(output, asn_input, run_id, conn)
        all_cidrs.update(cidrs)

    return all_cidrs


def _ingest_asnmap_output(output: Path, input_label: str,
                          run_id: int, conn) -> set:
    """Parse asnmap JSONL, store to DB, return set of CIDR strings."""
    rows = []
    cidrs: set = set()

    for obj in parse_jsonl(output):
        ranges = obj.get("as_range", [])
        rows.append((
            run_id,
            obj.get("input", input_label),
            obj.get("as_number"),
            obj.get("as_name"),
            obj.get("as_country"),
            ranges,
        ))
        cidrs.update(ranges)

    if rows:
        with conn.cursor() as cur:
            _batch_insert(
                cur,
                """
                INSERT INTO asn_records
                    (run_id, input, as_number, as_name, as_country, as_ranges)
                VALUES (%s, %s, %s, %s, %s, %s)
                """,
                rows,
            )
        conn.commit()

    log.info(f"asnmap: stored {len(rows)} records, found {len(cidrs)} CIDRs from {input_label}")
    return cidrs


# ---------------------------------------------------------------------------
# naabu  (IPs + CIDRs -> open ports)
# ---------------------------------------------------------------------------

def run_naabu(cfg: dict, host_ip_map: dict, extra_cidrs: set,
              out_dir: Path, run_id: int, conn, target_cfg: dict) -> set:
    """
    Port scan all known IPs (from DNS) plus any extra CIDRs (from ASNs/ip_ranges).
    host_ip_map: {hostname: [ip, ...]} from forward DNS
    extra_cidrs: set of "x.x.x.x/yy" strings from ASN resolution or ip_ranges config
    """
    # Build the targets file: individual IPs + CIDRs
    # naabu accepts both formats in the same list file
    scan_targets: set = extra_cidrs.copy()
    ip_host: dict = {}  # ip -> first hostname, for labelling results

    for host, ips in host_ip_map.items():
        for ip in ips:
            scan_targets.add(ip)
            ip_host.setdefault(ip, host)

    if not scan_targets:
        log.warning("naabu: no targets to scan")
        return set()

    targets_file = out_dir / "naabu_targets.txt"
    targets_file.write_text("\n".join(sorted(scan_targets)))

    output = out_dir / "naabu.json"
    ports = target_cfg.get("naabu_ports",
        "21,22,25,53,80,110,143,443,3306,5432,6379,8080,8443,8888,27017")
    rate = target_cfg.get("naabu_rate", 1000)

    cmd = [
        cfg["tool_paths"]["naabu"],
        "-l", str(targets_file),
        "-p", ports,
        "-rate", str(rate),
        "-json",
        "-o", str(output),
        "-silent",
        "-exclude-cdn",
    ]
    run_tool(cmd, output, timeout=cfg["timeouts"].get("naabu", 7200))

    SERVICE_MAP = {
        21: "ftp", 22: "ssh", 25: "smtp", 53: "dns",
        80: "http", 110: "pop3", 143: "imap", 443: "https",
        3306: "mysql", 5432: "postgres", 6379: "redis",
        8080: "http-alt", 8443: "https-alt", 8888: "http-alt",
        27017: "mongodb",
    }

    rows = []
    port_set = set()

    for obj in parse_jsonl(output):
        ip = obj.get("ip", "").strip()
        port = obj.get("port")
        protocol = obj.get("protocol", "tcp")
        host = obj.get("host") or ip_host.get(ip)

        if not ip or not port:
            continue

        service = SERVICE_MAP.get(int(port), "unknown")
        rows.append((run_id, ip, int(port), protocol, host, service))
        port_set.add(f"{ip}:{port}")

    if rows:
        with conn.cursor() as cur:
            _batch_insert(
                cur,
                """
                INSERT INTO ports (run_id, ip, port, protocol, host, service)
                VALUES (%s, %s, %s, %s, %s, %s)
                ON CONFLICT (run_id, ip, port, protocol) DO NOTHING
                """,
                rows,
            )
        conn.commit()

    log.info(f"Stored {len(rows)} open ports for run {run_id}")
    return port_set


# ---------------------------------------------------------------------------
# caduceus (optional)
# ---------------------------------------------------------------------------

def run_caduceus(cfg: dict, domains: list, out_dir: Path, run_id: int, conn):
    for domain in domains:
        output = out_dir / f"caduceus_{domain}.json"
        cmd = [
            cfg["tool_paths"]["caduceus"],
            "-d", domain,
            "-json",
            "-o", str(output),
            "-silent",
        ]
        try:
            run_tool(cmd, output, timeout=cfg["timeouts"].get("caduceus", 1800))
        except Exception as e:
            log.warning(f"caduceus failed for {domain} (non-fatal): {e}")
            continue

        rows = []
        for obj in parse_jsonl(output):
            not_before = not_after = None
            try:
                if obj.get("not_before"):
                    not_before = datetime.fromisoformat(
                        obj["not_before"].replace("Z", "+00:00"))
                if obj.get("not_after"):
                    not_after = datetime.fromisoformat(
                        obj["not_after"].replace("Z", "+00:00"))
            except (ValueError, AttributeError):
                pass

            rows.append((
                run_id,
                obj.get("domain", ""),
                obj.get("san", []),
                obj.get("issuer"),
                not_before,
                not_after,
                obj.get("serial"),
                obj.get("fingerprint"),
                obj.get("source"),
            ))

        if rows:
            with conn.cursor() as cur:
                _batch_insert(
                    cur,
                    """
                    INSERT INTO cert_transparency
                        (run_id, domain, san_domains, issuer, not_before, not_after,
                         serial_number, fingerprint, log_source)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
                    ON CONFLICT DO NOTHING
                    """,
                    rows,
                )
            conn.commit()
            log.info(f"Stored {len(rows)} CT records for {domain}")


# ---------------------------------------------------------------------------
# Shodan
# ---------------------------------------------------------------------------

def _get_shodan_api(cfg: dict):
    """Return an initialised Shodan API client or None if unavailable."""
    if not SHODAN_AVAILABLE:
        log.warning("shodan library not installed; skipping Shodan steps")
        return None
    api_key = (os.environ.get("SHODAN_API_KEY")
               or cfg.get("shodan", {}).get("api_key", ""))
    if not api_key:
        log.warning("No Shodan API key configured; skipping Shodan steps")
        return None
    return shodan_lib.Shodan(api_key)


def _ingest_shodan_rows(rows: list, run_id: int, conn):
    if not rows:
        return
    with conn.cursor() as cur:
        _batch_insert(
            cur,
            """
            INSERT INTO shodan_findings
                (run_id, ip, port, protocol, hostnames, org, isp, os,
                 product, version, cpe, vulns, tags, banner, source,
                 shodan_timestamp)
            VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
            """,
            rows,
        )
    conn.commit()
    log.info(f"Stored {len(rows)} Shodan findings for run {run_id}")


def _parse_shodan_service(item: dict, ip: str, org: str, isp: str,
                          os_: str, hostnames: list, tags: list,
                          run_id: int, source: str) -> tuple:
    """Convert one entry from host['data'] into a DB row tuple."""
    ts_str = item.get("timestamp")
    try:
        ts = datetime.fromisoformat(ts_str.replace("Z", "+00:00")) if ts_str else None
    except (ValueError, AttributeError):
        ts = None

    vulns_raw = item.get("vulns", {})
    vulns = {cve: {"cvss": v.get("cvss"), "summary": v.get("summary", "")[:500]}
             for cve, v in vulns_raw.items()} if vulns_raw else None

    banner = item.get("data", "")
    if banner:
        banner = banner[:1000]  # truncate long banners

    return (
        run_id,
        ip,
        item.get("port"),
        item.get("transport", "tcp"),
        hostnames or [],
        org,
        isp,
        os_,
        item.get("product"),
        item.get("version"),
        item.get("cpe", []),
        json.dumps(vulns) if vulns else None,
        tags or [],
        banner,
        source,
        ts,
    )


def run_shodan_enrich(cfg: dict, ips: set, run_id: int, conn):
    """
    Query Shodan for each discovered IP to get service banners, versions, CVEs.
    Limited to max_enrichment_ips per run to control API usage.
    """
    api = _get_shodan_api(cfg)
    if not api:
        return

    shodan_cfg = cfg.get("shodan", {})
    limit = shodan_cfg.get("max_enrichment_ips", 100)
    targets = list(ips)[:limit]

    if len(ips) > limit:
        log.warning(f"Shodan enrichment: capping at {limit} of {len(ips)} IPs")

    rows = []
    for ip in targets:
        try:
            host = api.host(ip)
            org = host.get("org", "")
            isp = host.get("isp", "")
            os_ = host.get("os")
            hostnames = host.get("hostnames", [])
            tags = host.get("tags", [])

            for item in host.get("data", []):
                rows.append(_parse_shodan_service(
                    item, ip, org, isp, os_, hostnames, tags, run_id, "host_lookup"
                ))
        except shodan_lib.APIError as e:
            if "No information available" in str(e):
                log.debug(f"Shodan: no data for {ip}")
            else:
                log.warning(f"Shodan API error for {ip}: {e}")
        except Exception as e:
            log.warning(f"Shodan enrichment failed for {ip}: {e}")

    _ingest_shodan_rows(rows, run_id, conn)


def run_shodan_search(cfg: dict, queries: list, run_id: int, conn) -> set:
    """
    Run passive Shodan searches for the target (by org, ASN, hostname, etc.).
    Returns set of IPs discovered, which may supplement active scan results.
    """
    api = _get_shodan_api(cfg)
    if not api or not queries:
        return set()

    discovered_ips: set = set()
    rows = []

    for query in queries:
        log.info(f"Shodan search: {query}")
        try:
            results = api.search(query)
            log.info(f"Shodan '{query}': {results['total']} total results, "
                     f"fetched {len(results['matches'])}")

            for match in results["matches"]:
                ip = match.get("ip_str", "")
                if not ip:
                    continue
                discovered_ips.add(ip)

                rows.append(_parse_shodan_service(
                    match,
                    ip,
                    match.get("org", ""),
                    match.get("isp", ""),
                    match.get("os"),
                    match.get("hostnames", []),
                    match.get("tags", []),
                    run_id,
                    "search",
                ))
        except shodan_lib.APIError as e:
            log.warning(f"Shodan search failed for '{query}': {e}")

    _ingest_shodan_rows(rows, run_id, conn)
    log.info(f"Shodan passive search found {len(discovered_ips)} unique IPs")
    return discovered_ips


# ---------------------------------------------------------------------------
# Diff computation
# ---------------------------------------------------------------------------

def compute_diffs(conn, run_id: int, target_name: str):
    with conn.cursor() as cur:
        cur.execute(
            """
            SELECT id FROM runs
            WHERE target_domain = %s
              AND status IN ('completed','partial')
              AND id < %s
            ORDER BY started_at DESC
            LIMIT 1
            """,
            (target_name, run_id),
        )
        row = cur.fetchone()

    if not row:
        log.info(f"First run for '{target_name}', no diff to compute")
        return

    prev_run_id = row[0]
    log.info(f"Computing diffs: run {run_id} vs previous run {prev_run_id}")

    with conn.cursor() as cur:
        # New subdomains
        cur.execute(
            """
            INSERT INTO run_diffs
                (run_id, prev_run_id, diff_type, change_type, target_domain, value, metadata)
            SELECT %s, %s, 'subdomain', 'added', %s,
                   s_new.host,
                   jsonb_build_object('sources', to_jsonb(s_new.sources))
            FROM subdomains s_new
            WHERE s_new.run_id = %s
              AND NOT EXISTS (
                  SELECT 1 FROM subdomains s_prev
                  WHERE s_prev.run_id = %s AND s_prev.host = s_new.host
              )
            """,
            (run_id, prev_run_id, target_name, run_id, prev_run_id),
        )
        added_subs = cur.rowcount

        # Removed subdomains
        cur.execute(
            """
            INSERT INTO run_diffs
                (run_id, prev_run_id, diff_type, change_type, target_domain, value, metadata)
            SELECT %s, %s, 'subdomain', 'removed', %s,
                   s_prev.host,
                   jsonb_build_object('sources', to_jsonb(s_prev.sources),
                                      'last_seen_run', %s)
            FROM subdomains s_prev
            WHERE s_prev.run_id = %s
              AND NOT EXISTS (
                  SELECT 1 FROM subdomains s_new
                  WHERE s_new.run_id = %s AND s_new.host = s_prev.host
              )
            """,
            (run_id, prev_run_id, target_name, prev_run_id, prev_run_id, run_id),
        )
        removed_subs = cur.rowcount

        # New ports
        cur.execute(
            """
            INSERT INTO run_diffs
                (run_id, prev_run_id, diff_type, change_type, target_domain, value, metadata)
            SELECT %s, %s, 'port', 'added', %s,
                   p_new.ip || ':' || p_new.port::text,
                   jsonb_build_object('protocol', p_new.protocol,
                                      'host', p_new.host,
                                      'service', p_new.service)
            FROM ports p_new
            WHERE p_new.run_id = %s
              AND NOT EXISTS (
                  SELECT 1 FROM ports p_prev
                  WHERE p_prev.run_id = %s
                    AND p_prev.ip = p_new.ip
                    AND p_prev.port = p_new.port
                    AND p_prev.protocol = p_new.protocol
              )
            """,
            (run_id, prev_run_id, target_name, run_id, prev_run_id),
        )
        added_ports = cur.rowcount

        # Removed ports
        cur.execute(
            """
            INSERT INTO run_diffs
                (run_id, prev_run_id, diff_type, change_type, target_domain, value, metadata)
            SELECT %s, %s, 'port', 'removed', %s,
                   p_prev.ip || ':' || p_prev.port::text,
                   jsonb_build_object('protocol', p_prev.protocol, 'host', p_prev.host)
            FROM ports p_prev
            WHERE p_prev.run_id = %s
              AND NOT EXISTS (
                  SELECT 1 FROM ports p_new
                  WHERE p_new.run_id = %s
                    AND p_new.ip = p_prev.ip
                    AND p_new.port = p_prev.port
                    AND p_new.protocol = p_prev.protocol
              )
            """,
            (run_id, prev_run_id, target_name, prev_run_id, run_id),
        )
        removed_ports = cur.rowcount

        # New A records (IP changes per host)
        cur.execute(
            """
            INSERT INTO run_diffs
                (run_id, prev_run_id, diff_type, change_type, target_domain, value, metadata)
            SELECT %s, %s, 'dns', 'added', %s,
                   d_new.host || ' A ' || d_new.value,
                   jsonb_build_object('record_type', d_new.record_type, 'host', d_new.host)
            FROM dns_records d_new
            WHERE d_new.run_id = %s
              AND d_new.record_type = 'A'
              AND NOT EXISTS (
                  SELECT 1 FROM dns_records d_prev
                  WHERE d_prev.run_id = %s
                    AND d_prev.host = d_new.host
                    AND d_prev.record_type = 'A'
                    AND d_prev.value = d_new.value
              )
            """,
            (run_id, prev_run_id, target_name, run_id, prev_run_id),
        )
        added_dns = cur.rowcount

        # New ASN ranges
        cur.execute(
            """
            INSERT INTO run_diffs
                (run_id, prev_run_id, diff_type, change_type, target_domain, value, metadata)
            SELECT %s, %s, 'asn', 'added', %s,
                   a_new.as_number::text || ' ' || unnest(a_new.as_ranges),
                   jsonb_build_object('as_name', a_new.as_name, 'as_country', a_new.as_country)
            FROM asn_records a_new
            WHERE a_new.run_id = %s
              AND NOT EXISTS (
                  SELECT 1 FROM asn_records a_prev
                  WHERE a_prev.run_id = %s
                    AND a_prev.as_number = a_new.as_number
              )
            """,
            (run_id, prev_run_id, target_name, run_id, prev_run_id),
        )
        added_asn = cur.rowcount

    conn.commit()
    log.info(
        f"Diffs: +{added_subs} -{removed_subs} subdomains | "
        f"+{added_ports} -{removed_ports} ports | "
        f"+{added_dns} new A records | "
        f"+{added_asn} new ASN ranges"
    )


# ---------------------------------------------------------------------------
# Cleanup
# ---------------------------------------------------------------------------

def purge_old_runs(conn, retention_days: int):
    if retention_days <= 0:
        return
    with conn.cursor() as cur:
        cur.execute(
            """
            DELETE FROM runs
            WHERE started_at < NOW() - (%s || ' days')::INTERVAL
              AND status IN ('completed','failed')
            """,
            (str(retention_days),),
        )
        deleted = cur.rowcount
    conn.commit()
    if deleted:
        log.info(f"Purged {deleted} runs older than {retention_days} days")


def cleanup_output_dir(out_dir: Path):
    for f in out_dir.iterdir():
        try:
            f.unlink()
        except OSError:
            pass
    try:
        out_dir.rmdir()
    except OSError:
        pass


# ---------------------------------------------------------------------------
# Main orchestration
# ---------------------------------------------------------------------------

def run_target(cfg: dict, target_cfg: dict, schema_path: Path):
    name = target_cfg["name"]
    tool_flags = target_cfg.get("tools", {})

    # Input lists — all optional, at least one should be non-empty
    domains: list   = target_cfg.get("domains", [])
    asns: list      = target_cfg.get("asns", [])
    ip_ranges: list = target_cfg.get("ip_ranges", [])

    if not domains and not asns and not ip_ranges:
        log.error(f"Target '{name}' has no domains, asns, or ip_ranges configured")
        return

    run_ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S")
    safe_name = name.replace(" ", "_").replace("/", "_")
    out_dir = Path(cfg["output_dir"]) / safe_name / run_ts
    out_dir.mkdir(parents=True, exist_ok=True)

    conn = get_conn(cfg)
    bootstrap_schema(conn, schema_path)

    tool_versions = get_tool_versions(cfg)
    run_id = create_run(conn, name, tool_versions)

    subdomains: set = set()
    host_ip_map: dict = {}   # hostname -> [ip, ...]
    asn_cidrs: set = set()   # CIDRs from ASN resolution
    port_set: set = set()

    try:
        # ── Domain pipeline ────────────────────────────────────────────────
        if domains:
            # 1a. Subdomain enumeration
            if tool_flags.get("subfinder", True):
                subdomains = run_subfinder(cfg, domains, out_dir, run_id, conn)

            # 1b. Forward DNS on all discovered subdomains
            if tool_flags.get("dnsx", True) and subdomains:
                host_ip_map = run_dnsx_forward(cfg, subdomains, out_dir,
                                               run_id, conn)

            # 1c. ASN info for seed domains (informational, stored to DB)
            if tool_flags.get("asnmap", True):
                run_asnmap_for_domains(cfg, domains, out_dir, run_id, conn)

            # 1d. Certificate transparency for seed domains
            if tool_flags.get("caduceus", False):
                run_caduceus(cfg, domains, out_dir, run_id, conn)

        # ── ASN pipeline ───────────────────────────────────────────────────
        if asns and tool_flags.get("asnmap", True):
            # 2a. Resolve ASNs -> CIDRs
            asn_cidrs = run_asnmap_for_asns(cfg, asns, out_dir, run_id, conn)
            log.info(f"ASNs {asns} resolved to {len(asn_cidrs)} CIDRs")

            # 2b. PTR lookups on a sample of the ASN space (skip — naabu
            #     handles scanning CIDRs directly; we do PTR after port scan
            #     to avoid enumerating millions of IPs unnecessarily)

        # ── IP range pipeline ──────────────────────────────────────────────
        # ip_ranges from config are passed straight to naabu (CIDR-aware)
        # Merge with CIDRs found from ASN resolution
        extra_cidrs = asn_cidrs | set(ip_ranges)

        # ── Port scanning (all inputs converge here) ───────────────────────
        if tool_flags.get("naabu", True) and (host_ip_map or extra_cidrs):
            port_set = run_naabu(cfg, host_ip_map, extra_cidrs,
                                 out_dir, run_id, conn, target_cfg)

        # ── Shodan ─────────────────────────────────────────────────────────
        shodan_cfg = cfg.get("shodan", {})

        # Passive search: discover additional hosts via Shodan queries
        shodan_queries = target_cfg.get("shodan_queries", [])
        if shodan_cfg.get("passive_search", True) and shodan_queries:
            shodan_ips = run_shodan_search(cfg, shodan_queries, run_id, conn)
            # Add Shodan-discovered IPs to the enrichment pool
            all_known_ips = {ip for ips in host_ip_map.values() for ip in ips}
            port_ips = {entry.split(":")[0] for entry in port_set}
            all_known_ips.update(port_ips)
        else:
            shodan_ips = set()

        # IP enrichment: query Shodan for every IP found by active tools + search
        if shodan_cfg.get("enrich_ips", True):
            all_ips_to_enrich = (
                {ip for ips in host_ip_map.values() for ip in ips}
                | {entry.split(":")[0] for entry in port_set}
                | shodan_ips
            )
            if all_ips_to_enrich:
                run_shodan_enrich(cfg, all_ips_to_enrich, run_id, conn)

        # ── PTR lookups on IPs that naabu found open ports on ─────────────
        # This gives us hostnames for ASN/CIDR-sourced IPs without having
        # to enumerate the full address space beforehand.
        if tool_flags.get("dnsx", True) and extra_cidrs and port_set:
            open_ips = {entry.split(":")[0] for entry in port_set}
            # Only PTR lookup IPs not already in host_ip_map (avoid dupes)
            known_ips = {ip for ips in host_ip_map.values() for ip in ips}
            new_ips = open_ips - known_ips
            if new_ips:
                run_dnsx_ptr(cfg, new_ips, out_dir, run_id, conn)

        # ── Diff vs previous run ───────────────────────────────────────────
        compute_diffs(conn, run_id, name)

        # ── Finalize ───────────────────────────────────────────────────────
        all_ips = {ip for ips in host_ip_map.values() for ip in ips}
        complete_run(conn, run_id, {
            "subdomains": len(subdomains),
            "ips": len(all_ips),
            "ports": len(port_set),
        })

        purge_old_runs(conn, cfg.get("retention_days", 90))

    except Exception as e:
        fail_run(conn, run_id, str(e))
        log.exception(f"Run {run_id} for target '{name}' failed")
        raise
    finally:
        cleanup_output_dir(out_dir)
        conn.close()


def main():
    parser = argparse.ArgumentParser(description="Recon automation runner")
    parser.add_argument("--config", default="config.yaml",
                        help="Path to config.yaml")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--all", action="store_true",
                       help="Run all enabled targets from config")
    group.add_argument("--target", metavar="NAME",
                       help="Run a single target by its name in config")
    args = parser.parse_args()

    cfg = load_config(args.config)
    logging.basicConfig(
        level=getattr(logging, cfg.get("log_level", "INFO")),
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%S",
    )

    schema_path = Path(__file__).parent / "schema.sql"

    all_targets = cfg.get("targets", [])
    if args.target:
        targets = [t for t in all_targets if t.get("name") == args.target]
        if not targets:
            log.error(f"No target named '{args.target}' found in config")
            sys.exit(1)
    else:
        targets = [t for t in all_targets if t.get("enabled", True)]

    if not targets:
        log.error("No targets to run")
        sys.exit(1)

    failed = []
    for target_cfg in targets:
        tname = target_cfg.get("name", "unnamed")
        log.info(f"=== Starting recon for target: {tname} ===")
        try:
            run_target(cfg, target_cfg, schema_path)
        except Exception:
            log.exception(f"Target '{tname}' failed with unhandled exception")
            failed.append(tname)

    if failed:
        log.error(f"Failed targets: {', '.join(failed)}")
        sys.exit(1)

    log.info("All runs completed successfully")


if __name__ == "__main__":
    main()
