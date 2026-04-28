"""m38_browser_activity — Offline browser activity and risk analysis.

Reads browser data from the offline Windows partition for:
  - Google Chrome
  - Microsoft Edge (Chromium)
  - Mozilla Firefox
  - Internet Explorer (Vista/legacy, best-effort)

Collects:
  - Browser profiles found
  - Top visited domains (not full URLs — browsing history is customer-sensitive)
  - Download history with full URLs (needed for malware triage)
  - Installed extensions with suspicious-extension flags
  - Saved credential file indicators (presence only — passwords NOT extracted)
  - Obsolete browser version detection

Safety rules (enforced in code):
  - Full browsing history URLs are NEVER written to the log.
  - Domain summary only (visit count per domain).
  - Login Data / key4.db presence is flagged but never read for content.
  - Download URLs ARE logged (required for malware triage).

Usage (REPL):
    import runpy ; temp = runpy._run_module_as_main("bootstrap")
    # Then: bootstrap run m38_browser_activity -- --target /mnt/windows

Output:
    logs/browser_activity_<timestamp>.json
"""

from __future__ import annotations

import argparse
import json
import re
import sqlite3
import tempfile
import shutil
from collections import Counter
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

DESCRIPTION = (
    "Browser activity: profiles, domain visit summary, download history, "
    "extensions, credential indicators — Chrome, Edge, Firefox, IE"
)

# ---------------------------------------------------------------------------
# Known suspicious extension IDs (a small curated set)
# ---------------------------------------------------------------------------

# These IDs have been associated with adware / info-stealers.
_SUSPICIOUS_EXT_IDS = {
    "aapbdbdomjkkjkaonfhkkikfgjllcleb",  # Google Translate (impersonator)
    "bmnlcjabgnpnenekpadlanbbkooimhnj",  # Hola VPN (known data-sharing)
    "cjpalhdlnbpafiamejdnhcphjbkeiagm",  # uBlock Origin (impersonator variant)
    "oiigbmnaadbkfbmpbfijlflahbdbdgdf",  # ScreenSearch adware
    "hifnmchbghoakiagkdkehiacmfpngloe",  # FastSave adware
    "kajibbejlbohfaggdiogboambcijhkke",  # SimilarWeb tracker
}

# Permissions that should not normally appear on legitimate extensions
_HIGH_RISK_PERMISSIONS = {
    "debugger", "proxy", "nativeMessaging", "clipboardRead",
    "cookies", "webRequest", "webRequestBlocking",
}

# ---------------------------------------------------------------------------
# Suspicious download indicators
# ---------------------------------------------------------------------------

_SUSPICIOUS_DOWNLOAD_EXTS = {
    ".exe", ".bat", ".cmd", ".ps1", ".vbs", ".js", ".jse",
    ".wsf", ".hta", ".scr", ".pif", ".cpl", ".dll", ".msi",
    ".jar", ".reg",
}

_SUSPICIOUS_DOWNLOAD_PATTERNS = [
    r"pastebin\.com",
    r"mega\.nz",
    r"anonfiles",
    r"temp\d+\.",
    r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}",   # IP address URL
    r"discord\.com/api/webhooks",
    r"raw\.githubusercontent\.com.*\.exe",
]

# ---------------------------------------------------------------------------
# SQLite helper — copies the DB file to a temp location to avoid WAL issues
# ---------------------------------------------------------------------------

def _open_sqlite_copy(db_path: Path) -> Optional[sqlite3.Connection]:
    """Copy the database to a temp file and open it read-only.
    Returns None on error."""
    try:
        tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
        tmp_path = Path(tmp.name)
        tmp.close()
        shutil.copy2(str(db_path), str(tmp_path))
        # Also copy WAL file if present
        wal = db_path.with_suffix(db_path.suffix + "-wal")
        if wal.exists():
            shutil.copy2(str(wal), str(tmp_path.with_suffix(tmp_path.suffix + "-wal")))
        shm = db_path.with_suffix(db_path.suffix + "-shm")
        if shm.exists():
            shutil.copy2(str(shm), str(tmp_path.with_suffix(tmp_path.suffix + "-shm")))
        conn = sqlite3.connect(str(tmp_path))
        conn.row_factory = sqlite3.Row
        return conn
    except Exception:
        return None


def _close_and_cleanup(conn: Optional[sqlite3.Connection], tmp_path_hint: Optional[str] = None) -> None:
    if conn:
        try:
            db_path = conn.execute("PRAGMA database_list").fetchone()
            if db_path:
                tmp_path_str = db_path[2]
            conn.close()
            Path(tmp_path_str).unlink(missing_ok=True)
            Path(tmp_path_str + "-wal").unlink(missing_ok=True)
            Path(tmp_path_str + "-shm").unlink(missing_ok=True)
        except Exception:
            pass


# ---------------------------------------------------------------------------
# Domain extraction helper
# ---------------------------------------------------------------------------

def _extract_domain(url: str) -> str:
    """Extract netloc/domain from a URL, stripping www. prefix."""
    m = re.search(r"https?://([^/?\s#]+)", url)
    if not m:
        return ""
    host = m.group(1).lower()
    if host.startswith("www."):
        host = host[4:]
    return host


def _is_suspicious_download(url: str, local_path: str) -> bool:
    url_lower = url.lower()
    path_lower = local_path.lower()
    # Check file extension in path
    for ext in _SUSPICIOUS_DOWNLOAD_EXTS:
        if path_lower.endswith(ext):
            return True
    # Check URL patterns
    for pat in _SUSPICIOUS_DOWNLOAD_PATTERNS:
        if re.search(pat, url_lower):
            return True
    return False


# ---------------------------------------------------------------------------
# Chrome / Edge (Chromium) reader
# ---------------------------------------------------------------------------

# Chrome epoch: microseconds since 1601-01-01
_CHROME_EPOCH_OFFSET_US = 11644473600 * 1_000_000


def _chrome_epoch_to_iso(ts_us: int) -> Optional[str]:
    if ts_us == 0:
        return None
    try:
        from datetime import datetime, timezone
        epoch_us = ts_us - _CHROME_EPOCH_OFFSET_US
        dt = datetime.fromtimestamp(epoch_us / 1_000_000, tz=timezone.utc)
        return dt.strftime("%Y-%m-%dT%H:%M:%SZ")
    except Exception:
        return None


def _read_chromium_history(profile_dir: Path) -> Tuple[dict, List[dict], List[str]]:
    """Read Chrome/Edge History SQLite database.
    Returns (domain_summary, downloads, limitations)."""
    limitations: List[str] = []
    domain_counts: Counter = Counter()
    downloads: List[dict] = []

    history_db = profile_dir / "History"
    if not history_db.exists():
        limitations.append(f"History database not found: {history_db.name}")
        return {}, downloads, limitations

    conn = _open_sqlite_copy(history_db)
    if conn is None:
        limitations.append(f"Could not open History database: {history_db.name}")
        return {}, downloads, limitations

    try:
        # Domain visit summary — do NOT log full URLs
        try:
            rows = conn.execute(
                "SELECT url, visit_count FROM urls ORDER BY visit_count DESC LIMIT 5000"
            ).fetchall()
            for row in rows:
                domain = _extract_domain(row["url"])
                if domain:
                    domain_counts[domain] += row["visit_count"]
        except Exception as exc:
            limitations.append(f"History URLs query failed: {exc}")

        # Downloads — full URLs logged for malware triage
        try:
            dl_rows = conn.execute(
                "SELECT target_path, tab_url, total_bytes, state, end_time "
                "FROM downloads ORDER BY end_time DESC LIMIT 500"
            ).fetchall()
            for dl in dl_rows:
                url       = dl["tab_url"] or ""
                local     = dl["target_path"] or ""
                suspicious = _is_suspicious_download(url, local)
                downloads.append({
                    "url":        url,
                    "local_path": local,
                    "size_bytes": dl["total_bytes"],
                    "state":      dl["state"],
                    "date":       _chrome_epoch_to_iso(dl["end_time"] or 0),
                    "suspicious": suspicious,
                })
        except Exception as exc:
            limitations.append(f"Downloads query failed: {exc}")

    finally:
        _close_and_cleanup(conn)

    top_domains = [
        {"domain": d, "visit_count": c}
        for d, c in domain_counts.most_common(50)
    ]
    return {"top_domains": top_domains, "total_unique_domains": len(domain_counts)}, downloads, limitations


def _read_chromium_extensions(profile_dir: Path) -> Tuple[List[dict], List[str]]:
    """Read Chrome/Edge extensions from Extensions/ subdirectory."""
    limitations: List[str] = []
    extensions: List[dict] = []

    ext_dir = profile_dir / "Extensions"
    if not ext_dir.is_dir():
        return extensions, limitations

    for ext_id_dir in sorted(ext_dir.iterdir()):
        if not ext_id_dir.is_dir():
            continue
        ext_id = ext_id_dir.name
        # Each extension has one or more version subdirectories
        for version_dir in sorted(ext_id_dir.iterdir()):
            if not version_dir.is_dir():
                continue
            manifest_path = version_dir / "manifest.json"
            if not manifest_path.exists():
                continue
            try:
                manifest = json.loads(manifest_path.read_text(encoding="utf-8", errors="replace"))
                name        = manifest.get("name", "")
                description = manifest.get("description", "")[:120]
                version     = manifest.get("version", "")
                permissions = manifest.get("permissions", [])
                bg_scripts  = manifest.get("background", {}).get("scripts", [])
                content_scripts = manifest.get("content_scripts", [])

                flags: List[str] = []
                if ext_id in _SUSPICIOUS_EXT_IDS:
                    flags.append("known_suspicious_id")
                high_risk = [p for p in permissions if p in _HIGH_RISK_PERMISSIONS]
                if high_risk:
                    flags.append(f"high_risk_permissions:{','.join(high_risk)}")
                if "<all_urls>" in permissions or "http://*/*" in permissions:
                    flags.append("access_all_urls")
                if any(re.search(r"\.(exe|bat|ps1|vbs|hta)", s.lower()) for s in bg_scripts):
                    flags.append("suspicious_background_script")

                extensions.append({
                    "id":          ext_id,
                    "name":        name,
                    "version":     version,
                    "description": description,
                    "permissions": permissions[:20],  # cap
                    "flags":       flags,
                })
                break  # only read one version
            except Exception as exc:
                extensions.append({"id": ext_id, "parse_error": str(exc)})
                break

    return extensions, limitations


def _read_chromium_profile(profile_dir: Path, browser: str, user: str) -> dict:
    history, downloads, lim1 = _read_chromium_history(profile_dir)
    extensions, lim2 = _read_chromium_extensions(profile_dir)
    saved_creds = (profile_dir / "Login Data").exists()
    cookies_present = (profile_dir / "Cookies").exists()

    return {
        "browser":          browser,
        "user":             user,
        "profile_dir":      str(profile_dir),
        "history":          history,
        "downloads":        downloads,
        "extensions":       extensions,
        "saved_credentials_indicator": saved_creds,
        "cookies_present":  cookies_present,
        "limitations":      lim1 + lim2,
    }


# ---------------------------------------------------------------------------
# Firefox reader
# ---------------------------------------------------------------------------

# Firefox epoch: microseconds since Unix epoch (for moz_historyvisits.visit_date)

def _ff_epoch_to_iso(ts_us: int) -> Optional[str]:
    if ts_us == 0:
        return None
    try:
        from datetime import datetime, timezone
        dt = datetime.fromtimestamp(ts_us / 1_000_000, tz=timezone.utc)
        return dt.strftime("%Y-%m-%dT%H:%M:%SZ")
    except Exception:
        return None


def _read_firefox_profile(profile_dir: Path, user: str) -> dict:
    limitations: List[str] = []
    domain_counts: Counter = Counter()
    downloads: List[dict] = []

    places_db = profile_dir / "places.sqlite"
    if places_db.exists():
        conn = _open_sqlite_copy(places_db)
        if conn is None:
            limitations.append("Could not open places.sqlite")
        else:
            try:
                # Domain visit summary (no full URLs logged)
                try:
                    rows = conn.execute(
                        "SELECT url, visit_count FROM moz_places "
                        "WHERE visit_count > 0 LIMIT 5000"
                    ).fetchall()
                    for row in rows:
                        domain = _extract_domain(row["url"])
                        if domain:
                            domain_counts[domain] += row["visit_count"]
                except Exception as exc:
                    limitations.append(f"Firefox history query failed: {exc}")

                # Downloads (from moz_annos + places or from downloads table)
                try:
                    dl_rows = conn.execute(
                        "SELECT p.url, a.content "
                        "FROM moz_annos a "
                        "JOIN moz_places p ON p.id = a.place_id "
                        "WHERE a.anno_attribute_id IN ("
                        "  SELECT id FROM moz_anno_attributes "
                        "  WHERE name LIKE '%download%' OR name LIKE '%metadata%'"
                        ") LIMIT 200"
                    ).fetchall()
                    for dl in dl_rows:
                        url = dl["url"] or ""
                        local = ""
                        try:
                            meta = json.loads(dl["content"] or "{}")
                            local = meta.get("targetPath", "")
                        except Exception:
                            pass
                        suspicious = _is_suspicious_download(url, local)
                        downloads.append({
                            "url": url,
                            "local_path": local,
                            "suspicious": suspicious,
                        })
                except Exception:
                    pass  # older Firefox profiles may not have moz_annos

            finally:
                _close_and_cleanup(conn)
    else:
        limitations.append("places.sqlite not found")

    # Extensions from extensions.json
    extensions: List[dict] = []
    ext_json = profile_dir / "extensions.json"
    if ext_json.exists():
        try:
            data = json.loads(ext_json.read_text(encoding="utf-8", errors="replace"))
            addons = data.get("addons", [])
            for addon in addons:
                addon_id    = addon.get("id", "")
                name        = addon.get("defaultLocale", {}).get("name", "") or addon.get("id", "")
                version     = addon.get("version", "")
                addon_type  = addon.get("type", "")
                active      = addon.get("active", True)
                permissions = addon.get("userPermissions", {}).get("permissions", [])

                flags: List[str] = []
                if not active:
                    flags.append("disabled")
                high_risk = [p for p in permissions if p in _HIGH_RISK_PERMISSIONS]
                if high_risk:
                    flags.append(f"high_risk_permissions:{','.join(high_risk)}")
                if "<all_urls>" in (addon.get("userPermissions", {}).get("origins", []) or []):
                    flags.append("access_all_urls")

                extensions.append({
                    "id":      addon_id,
                    "name":    name,
                    "version": version,
                    "type":    addon_type,
                    "active":  active,
                    "flags":   flags,
                })
        except Exception as exc:
            limitations.append(f"extensions.json parse error: {exc}")
    else:
        limitations.append("extensions.json not found")

    saved_creds = (profile_dir / "key4.db").exists() or (profile_dir / "key3.db").exists()
    cookies_present = (profile_dir / "cookies.sqlite").exists()

    top_domains = [
        {"domain": d, "visit_count": c}
        for d, c in domain_counts.most_common(50)
    ]
    history = {"top_domains": top_domains, "total_unique_domains": len(domain_counts)}

    return {
        "browser":          "Firefox",
        "user":             user,
        "profile_dir":      str(profile_dir),
        "history":          history,
        "downloads":        downloads,
        "extensions":       extensions,
        "saved_credentials_indicator": saved_creds,
        "cookies_present":  cookies_present,
        "limitations":      limitations,
    }


# ---------------------------------------------------------------------------
# Internet Explorer (Vista) — best-effort
# index.dat is proprietary; we only check for presence and read TypedURLs
# from the registry (handled by m36_execution_history).
# ---------------------------------------------------------------------------

def _check_ie_presence(user_dir: Path) -> Optional[dict]:
    """Check for IE history presence and read any accessible typed URLs."""
    history_dir = user_dir / "AppData" / "Local" / "Microsoft" / "Windows" / "History"
    index_dat   = history_dir / "History.IE5" / "index.dat"
    favourites  = user_dir / "Favorites"

    if not history_dir.exists() and not favourites.exists():
        return None

    fav_count = 0
    if favourites.is_dir():
        fav_count = sum(1 for _ in favourites.rglob("*.url"))

    index_dat_size = 0
    if index_dat.exists():
        try:
            index_dat_size = index_dat.stat().st_size
        except OSError:
            pass

    return {
        "browser":       "Internet Explorer",
        "user":          user_dir.name,
        "history_dir":   str(history_dir),
        "index_dat_present": index_dat.exists(),
        "index_dat_bytes":   index_dat_size,
        "favourites_count":  fav_count,
        "limitations": [
            "IE index.dat is a proprietary binary format; full URL history not parsed"
        ],
    }


# ---------------------------------------------------------------------------
# Browser profile discovery
# ---------------------------------------------------------------------------

def _find_chromium_profiles(user_dir: Path, browser: str, rel_path: str) -> List[Tuple[Path, str]]:
    """Return [(profile_path, user_name), ...] for a Chromium-based browser."""
    base = user_dir / rel_path.replace("/", "/")
    results: List[Tuple[Path, str]] = []
    if not base.is_dir():
        return results

    # Standard "Default" profile
    default = base / "Default"
    if default.is_dir() and (default / "History").exists():
        results.append((default, user_dir.name))

    # Additional profiles (Profile 1, Profile 2, …)
    for item in sorted(base.iterdir()):
        if item.name.startswith("Profile ") and item.is_dir():
            results.append((item, user_dir.name))

    return results


def _find_firefox_profiles(user_dir: Path) -> List[Path]:
    """Return list of Firefox profile directories under Roaming/Mozilla/Firefox."""
    profiles_dir = (
        user_dir / "AppData" / "Roaming" / "Mozilla" / "Firefox" / "Profiles"
    )
    if not profiles_dir.is_dir():
        return []
    return [d for d in sorted(profiles_dir.iterdir()) if d.is_dir()]


# ---------------------------------------------------------------------------
# Main analysis
# ---------------------------------------------------------------------------

def analyse(target: Path) -> dict:
    limitations: List[str] = []
    profiles: List[dict] = []

    users_dir = target / "Users"
    if not users_dir.is_dir():
        limitations.append("Users directory not found; browser data unavailable")
        return {
            "scan_status":  "ok",
            "verdict":      "UNKNOWN",
            "profiles":     profiles,
            "summary":      {},
            "limitations":  limitations,
        }

    for user_dir in sorted(users_dir.iterdir()):
        if not user_dir.is_dir():
            continue

        # Chrome
        for prof_path, user in _find_chromium_profiles(
            user_dir, "Chrome",
            "AppData/Local/Google/Chrome/User Data"
        ):
            profiles.append(_read_chromium_profile(prof_path, "Chrome", user))

        # Edge (Chromium)
        for prof_path, user in _find_chromium_profiles(
            user_dir, "Edge",
            "AppData/Local/Microsoft/Edge/User Data"
        ):
            profiles.append(_read_chromium_profile(prof_path, "Edge", user))

        # Firefox
        for ff_prof in _find_firefox_profiles(user_dir):
            profiles.append(_read_firefox_profile(ff_prof, user_dir.name))

        # Internet Explorer
        ie = _check_ie_presence(user_dir)
        if ie:
            profiles.append(ie)

    if not profiles:
        limitations.append("No browser profiles found")

    # Aggregate flags
    all_suspicious_downloads: List[dict] = []
    all_flagged_extensions:   List[dict] = []
    saved_creds_users: List[str] = []

    for prof in profiles:
        for dl in prof.get("downloads", []):
            if dl.get("suspicious"):
                all_suspicious_downloads.append({
                    "browser": prof.get("browser"),
                    "user":    prof.get("user"),
                    **dl,
                })
        for ext in prof.get("extensions", []):
            if ext.get("flags"):
                all_flagged_extensions.append({
                    "browser": prof.get("browser"),
                    "user":    prof.get("user"),
                    **ext,
                })
        if prof.get("saved_credentials_indicator"):
            saved_creds_users.append(f"{prof.get('browser')}:{prof.get('user')}")

    verdict = "OK"
    if all_suspicious_downloads or all_flagged_extensions:
        verdict = "WARNING"
    if any(
        "known_suspicious_id" in ext.get("flags", [])
        for ext in all_flagged_extensions
    ):
        verdict = "SUSPICIOUS"

    summary = {
        "browser_profiles_found":       len(profiles),
        "browsers_present":             list(dict.fromkeys(p.get("browser", "") for p in profiles)),
        "suspicious_download_count":    len(all_suspicious_downloads),
        "flagged_extension_count":      len(all_flagged_extensions),
        "saved_credentials_browsers":   saved_creds_users,
    }

    return {
        "scan_status":            "ok",
        "verdict":                verdict,
        "summary":                summary,
        "profiles":               profiles,
        "suspicious_downloads":   all_suspicious_downloads,
        "flagged_extensions":     all_flagged_extensions,
        "limitations":            limitations,
    }


# ---------------------------------------------------------------------------
# Report printing
# ---------------------------------------------------------------------------

def _print_report(data: dict) -> None:
    print("\n=== BROWSER ACTIVITY ANALYSIS ===")
    print(f"Verdict   : {data.get('verdict', '?')}")
    s = data.get("summary", {})
    browsers = ", ".join(s.get("browsers_present", [])) or "none found"
    print(f"Browsers  : {s.get('browser_profiles_found', 0)} profiles — {browsers}")

    susp_dl = data.get("suspicious_downloads", [])
    if susp_dl:
        print(f"\nSuspicious downloads ({len(susp_dl)}):")
        for dl in susp_dl[:20]:
            url   = dl.get("url", "")
            local = dl.get("local_path", "")
            print(f"  [{dl.get('browser')} / {dl.get('user')}]")
            print(f"    url  : {url[:120]}")
            if local:
                print(f"    local: {local[:100]}")

    flagged_ext = data.get("flagged_extensions", [])
    if flagged_ext:
        print(f"\nFlagged extensions ({len(flagged_ext)}):")
        for ext in flagged_ext:
            flags = ", ".join(ext.get("flags", []))
            print(f"  [{ext.get('browser')} / {ext.get('user')}] "
                  f"{ext.get('name', ext.get('id', '?'))} "
                  f"v{ext.get('version', '?')}  [{flags}]")

    cred_users = s.get("saved_credentials_browsers", [])
    if cred_users:
        print(f"\nSaved credential files detected: {', '.join(cred_users)}")
        print("  (passwords NOT extracted — presence indicator only)")

    for prof in data.get("profiles", []):
        hist = prof.get("history", {})
        top  = hist.get("top_domains", [])
        if top:
            print(f"\nTop domains [{prof.get('browser')} / {prof.get('user')}]:")
            for d in top[:10]:
                print(f"  {d.get('domain', '?'):45}  {d.get('visit_count', 0):>5} visits")

    limits = data.get("limitations", [])
    for prof in data.get("profiles", []):
        limits.extend(prof.get("limitations", []))
    if limits:
        print("\nLimitations:")
        for lim in dict.fromkeys(limits):
            print(f"  - {lim}")


# ---------------------------------------------------------------------------
# Module entry point
# ---------------------------------------------------------------------------

def run(root: Path, argv: list) -> int:
    from toolkit import find_windows_target  # noqa: PLC0415

    parser = argparse.ArgumentParser(
        prog="m38_browser_activity",
        description=DESCRIPTION,
    )
    parser.add_argument("--target", default="",
                        help="Path to mounted Windows partition (auto-detect if omitted)")
    parser.add_argument("--summary", action="store_true",
                        help="Print summary only")
    args = parser.parse_args(argv)

    target_str = args.target.strip()
    if not target_str:
        target_path = find_windows_target()
        if target_path is None:
            print("ERROR: Could not auto-detect Windows installation. Pass --target.")
            return 2
        print(f"[m38] Auto-detected Windows target: {target_path}")
    else:
        target_path = Path(target_str)

    if not target_path.exists():
        print(f"ERROR: Target does not exist: {target_path}")
        return 2

    import time
    from datetime import datetime as _dt, timezone as _tz

    print(f"[m38] Analysing browser activity in {target_path} ...")
    data = analyse(target_path)
    data["generated"] = _dt.now(_tz.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    data["target"]    = str(target_path)

    if not args.summary:
        _print_report(data)

    logs_dir = root / "logs"
    logs_dir.mkdir(parents=True, exist_ok=True)
    ts = time.strftime("%Y%m%d_%H%M%S")
    out_path = logs_dir / f"browser_activity_{ts}.json"
    out_path.write_text(json.dumps(data, indent=2, default=str), encoding="utf-8")
    print(f"[m38] Log written: {out_path}")

    return 0 if data.get("verdict") == "OK" else 1
