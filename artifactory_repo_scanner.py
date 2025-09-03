#!/usr/bin/env python3
import json
import requests
import argparse
import threading
import sqlite3
import os
import time
import re
from packaging.version import Version, InvalidVersion
from urllib.parse import quote, urlparse
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from requests.packages.urllib3.exceptions import InsecureRequestWarning
from concurrent.futures import ThreadPoolExecutor, as_completed

# Disable SSL warnings
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

DB_FILE = "scanner.db"
DB_LOCK = threading.Lock()

# ============================================================
# DB helpers (durable resume + latest-version cache)
# ============================================================

def init_db(fresh=False):
    if fresh and os.path.exists(DB_FILE):
        os.remove(DB_FILE)
    conn = sqlite3.connect(DB_FILE, check_same_thread=False)
    cur = conn.cursor()

    # servers
    cur.execute("""
        CREATE TABLE IF NOT EXISTS servers (
            id INTEGER PRIMARY KEY,
            url TEXT UNIQUE,
            version TEXT,
            header TEXT
        )
    """)
    # add flags if missing
    cur.execute("PRAGMA table_info(servers)")
    cols = [r[1] for r in cur.fetchall()]
    if "repos_enumerated" not in cols:
        cur.execute("ALTER TABLE servers ADD COLUMN repos_enumerated INTEGER DEFAULT 0")
    if "files_completed" not in cols:
        cur.execute("ALTER TABLE servers ADD COLUMN files_completed INTEGER DEFAULT 0")

    # repos (+ package_type)
    cur.execute("""
        CREATE TABLE IF NOT EXISTS repos (
            id INTEGER PRIMARY KEY,
            server_id INTEGER,
            repo_key TEXT,
            repo_type TEXT,               -- LOCAL / REMOTE / VIRTUAL
            listed INTEGER DEFAULT 0,     -- 1 when fully listed
            package_type TEXT,            -- maven / generic / docker / ...
            UNIQUE(server_id, repo_key)
        )
    """)
    # ensure package_type exists for old DBs
    cur.execute("PRAGMA table_info(repos)")
    rcols = [r[1] for r in cur.fetchall()]
    if "package_type" not in rcols:
        cur.execute("ALTER TABLE repos ADD COLUMN package_type TEXT")

    # files
    cur.execute("""
        CREATE TABLE IF NOT EXISTS files (
            id INTEGER PRIMARY KEY,
            repo_id INTEGER,
            path TEXT,
            UNIQUE(repo_id, path)
        )
    """)

    # folder_queue
    cur.execute("""
        CREATE TABLE IF NOT EXISTS folder_queue (
            id INTEGER PRIMARY KEY,
            repo_id INTEGER,
            path TEXT,
            processed INTEGER DEFAULT 0,
            UNIQUE(repo_id, path)
        )
    """)

    # latest_versions cache
    cur.execute("""
        CREATE TABLE IF NOT EXISTS latest_versions (
            id INTEGER PRIMARY KEY,
            server_id INTEGER,
            repo_id INTEGER,
            base_path TEXT,            -- artifact root (no version segment)
            latest_version TEXT,
            source TEXT,               -- 'metadata' | 'path'
            updated_at INTEGER,        -- epoch seconds
            UNIQUE(repo_id, base_path)
        )
    """)

    conn.commit()
    return conn

def save_server(conn, url, version, header):
    with DB_LOCK:
        cur = conn.cursor()
        cur.execute("INSERT OR IGNORE INTO servers(url, version, header) VALUES (?, ?, ?)", (url, version, header))
        conn.commit()
        cur.execute("SELECT id FROM servers WHERE url=?", (url,))
        row = cur.fetchone()
        return row[0] if row else None

def get_server_if_exists(conn, url):
    with DB_LOCK:
        cur = conn.cursor()
        cur.execute("SELECT id FROM servers WHERE url=?", (url,))
        row = cur.fetchone()
        return row[0] if row else None

def set_server_flags(conn, server_id, repos_enumerated=None, files_completed=None):
    with DB_LOCK:
        cur = conn.cursor()
        if repos_enumerated is not None:
            cur.execute("UPDATE servers SET repos_enumerated=? WHERE id=?", (1 if repos_enumerated else 0, server_id))
        if files_completed is not None:
            cur.execute("UPDATE servers SET files_completed=? WHERE id=?", (1 if files_completed else 0, server_id))
        conn.commit()

def save_repo(conn, server_id, repo_key, repo_type, package_type):
    with DB_LOCK:
        cur = conn.cursor()
        cur.execute("""
            INSERT OR IGNORE INTO repos(server_id, repo_key, repo_type, package_type)
            VALUES (?, ?, ?, ?)
        """, (server_id, repo_key, repo_type, package_type))
        conn.commit()
        # ensure package_type is updated (repo existed before)
        cur.execute("""
            UPDATE repos SET package_type=COALESCE(?, package_type)
            WHERE server_id=? AND repo_key=?
        """, (package_type, server_id, repo_key))
        conn.commit()
        cur.execute("SELECT id, listed FROM repos WHERE server_id=? AND repo_key=?", (server_id, repo_key))
        row = cur.fetchone()
        return (row[0] if row else None), (row[1] if row else 0)

def mark_repo_complete(conn, repo_id):
    with DB_LOCK:
        cur = conn.cursor()
        cur.execute("UPDATE repos SET listed=1 WHERE id=?", (repo_id,))
        conn.commit()

def repo_is_complete(conn, repo_id):
    with DB_LOCK:
        cur = conn.cursor()
        # Complete if listed=1 and no pending folders
        cur.execute("SELECT listed FROM repos WHERE id=?", (repo_id,))
        listed = cur.fetchone()
        if not listed:
            return False
        listed = listed[0]
        cur.execute("SELECT COUNT(*) FROM folder_queue WHERE repo_id=? AND processed=0", (repo_id,))
        pend = cur.fetchone()[0]
        return listed == 1 and pend == 0

def save_file(conn, repo_id, path):
    with DB_LOCK:
        cur = conn.cursor()
        cur.execute("INSERT OR IGNORE INTO files(repo_id, path) VALUES (?, ?)", (repo_id, path))
        conn.commit()

def enqueue_folder(conn, repo_id, path):
    with DB_LOCK:
        cur = conn.cursor()
        cur.execute("INSERT OR IGNORE INTO folder_queue(repo_id, path, processed) VALUES (?, ?, 0)", (repo_id, path))
        conn.commit()

def claim_next_folder(conn, repo_id):
    """Atomically claim one unprocessed folder for this repo. Returns path or None."""
    with DB_LOCK:
        cur = conn.cursor()
        cur.execute("SELECT id, path FROM folder_queue WHERE repo_id=? AND processed=0 LIMIT 1", (repo_id,))
        row = cur.fetchone()
        if not row:
            return None
        qid, path = row
        cur.execute("UPDATE folder_queue SET processed=1 WHERE id=?", (qid,))
        conn.commit()
        return path

def unprocessed_count(conn, repo_id):
    with DB_LOCK:
        cur = conn.cursor()
        cur.execute("SELECT COUNT(*) FROM folder_queue WHERE repo_id=? AND processed=0", (repo_id,))
        return cur.fetchone()[0]

def server_stats(conn, server_id):
    with DB_LOCK:
        cur = conn.cursor()
        cur.execute("SELECT COUNT(*), SUM(CASE WHEN listed=1 THEN 1 ELSE 0 END) FROM repos WHERE server_id=?", (server_id,))
        rc, rc_done = cur.fetchone()
        cur.execute("""
            SELECT COUNT(*)
            FROM files f
            JOIN repos r ON f.repo_id = r.id
            WHERE r.server_id=?
        """, (server_id,))
        file_count = cur.fetchone()[0]
        cur.execute("""
            SELECT COUNT(*)
            FROM folder_queue fq
            JOIN repos r ON fq.repo_id = r.id
            WHERE r.server_id=? AND fq.processed=0
        """, (server_id,))
        pending_folders = cur.fetchone()[0]
        return (rc or 0), (rc_done or 0), (file_count or 0), (pending_folders or 0)

def upsert_latest(conn, server_id, repo_id, base_path, latest_version, source):
    with DB_LOCK:
        cur = conn.cursor()
        cur.execute("""
            INSERT INTO latest_versions(server_id, repo_id, base_path, latest_version, source, updated_at)
            VALUES (?, ?, ?, ?, ?, ?)
            ON CONFLICT(repo_id, base_path) DO UPDATE SET
                latest_version=excluded.latest_version,
                source=excluded.source,
                updated_at=excluded.updated_at
        """, (server_id, repo_id, base_path, latest_version, source, int(time.time())))
        conn.commit()

def get_cached_latest(conn, repo_id, base_path, cache_ttl):
    with DB_LOCK:
        cur = conn.cursor()
        cur.execute("""
            SELECT latest_version, source, updated_at
            FROM latest_versions
            WHERE repo_id=? AND base_path=?
        """, (repo_id, base_path))
        row = cur.fetchone()
        if not row:
            return None, None, None
        version, source, updated_at = row
        if cache_ttl and cache_ttl > 0:
            if int(time.time()) - int(updated_at) > cache_ttl:
                return None, None, None
        return version, source, updated_at

# ============================================================
# Utils
# ============================================================

def _try_version(s):
    try:
        return Version(s)
    except InvalidVersion:
        return None

SEMVERISH_RE = re.compile(r"^(?:v)?\d+(?:\.\d+){0,3}(?:[-_].+)?$")

def looks_like_version(s: str) -> bool:
    if _try_version(s) is not None:
        return True
    # lenient generic matcher
    return bool(SEMVERISH_RE.match(s))

def first_version_index(parts):
    """
    Heuristic: find the first segment that looks like a version.
    Keeps behavior compatible with your earlier script.
    """
    for i, p in enumerate(parts):
        if looks_like_version(p):
            return i
    return None

def pick_max_version_str(candidates):
    """
    Given a set/list of version strings, pick the "max" using PEP440 if possible,
    otherwise fall back to lexicographic.
    """
    parsed = []
    fallback = []
    for c in candidates:
        v = _try_version(c)
        if v is not None:
            parsed.append((v, c))
        else:
            fallback.append(c)
    if parsed:
        parsed.sort(key=lambda x: x[0])
        return parsed[-1][1]
    if fallback:
        return sorted(fallback)[-1]
    return None

def parse_maven_metadata(xml_text):
    """
    Very small parser: prefer <release>; if missing, use max of <versions><version>.
    """
    try:
        import xml.etree.ElementTree as ET
        root = ET.fromstring(xml_text)
        ns = ""  # usually not namespaced
        # try <versioning><release>
        rel = root.find("./versioning/release")
        if rel is not None and rel.text:
            return rel.text.strip()
        # else max of versions/version
        versions = [e.text.strip() for e in root.findall("./versioning/versions/version") if e.text]
        return pick_max_version_str(versions)
    except Exception:
        return None

# ============================================================
# Results / output
# ============================================================

def dump_results(conn, outfile, latest_only=False, use_maven_metadata=False, cache_ttl=0):
    """
    Dump files to output; optionally only latest version per artifact.
    For Maven repos, optionally consult maven-metadata.xml (cached in DB).
    """
    cur = conn.cursor()
    cur.execute("""
        SELECT s.id, s.url, r.id, r.repo_key, r.repo_type, r.package_type, f.path
        FROM files f
        JOIN repos r ON f.repo_id = r.id
        JOIN servers s ON r.server_id = s.id
        ORDER BY s.url, r.repo_key, f.path
    """)
    rows = cur.fetchall()

    if not latest_only:
        with open(outfile, "w") as f:
            for sid, url, rid, repo, rtype, pkg, path in rows:
                f.write(f"{url}/artifactory/{repo}/{path}\n")
        return

    # Build groups: (server_id, repo_id, base_path) -> info
    groups = {}
    # Also note if we saw maven-metadata.xml under base_path to avoid extra fetches
    for sid, url, rid, repo, rtype, pkg, path in rows:
        parts = path.strip("/").split("/")
        v_idx = first_version_index(parts)
        if v_idx is None:
            # no version-like segment; treat the entire path as its own "artifact"
            base = "/".join(parts)
            version_str = None
        else:
            base = "/".join(parts[:v_idx])
            version_str = parts[v_idx]

        key = (sid, rid, base)
        g = groups.get(key)
        if g is None:
            groups[key] = g = {
                "server_id": sid,
                "repo_id": rid,
                "server_url": url,
                "repo_key": repo,
                "repo_type": rtype,
                "package_type": (pkg or "").lower(),
                "versions": set(),
                "files_by_version": {},     # v -> one representative path
                "saw_metadata_file": False  # saw base/maven-metadata.xml as a file listing
            }

        # detect metadata presence from listing (no extra request)
        if path.endswith("maven-metadata.xml"):
            # should belong to exactly one base; for maven structure it will be base/maven-metadata.xml
            if base and (path.strip("/").startswith(base) or path == f"{base}/maven-metadata.xml"):
                g["saw_metadata_file"] = True

        if version_str:
            g["versions"].add(version_str)
            # store a representative file path for this version (prefer shortest stable filename)
            prev = g["files_by_version"].get(version_str)
            if prev is None or len(path) < len(prev):
                g["files_by_version"][version_str] = path
        else:
            # versionless: treat as its own "latest"
            g["versions"].add("__NOVERSION__")
            g["files_by_version"]["__NOVERSION__"] = path

    # Prepare a session with retries for optional metadata fetch
    session = requests.Session()
    retry_strategy = Retry(
        total=3,
        backoff_factor=0.5,
        status_forcelist=[429, 500, 502, 503, 504],
        allowed_methods=["GET"]
    )
    adapter = HTTPAdapter(max_retries=retry_strategy)
    session.mount("http://", adapter)
    session.mount("https://", adapter)

    def decide_latest_for_group(gkey, ginfo):
        sid = ginfo["server_id"]
        rid = ginfo["repo_id"]
        url = ginfo["server_url"]
        repo = ginfo["repo_key"]
        pkg = ginfo["package_type"]
        saw_meta = ginfo["saw_metadata_file"]

        # 1) cache?
        cached_v, cached_src, _ = get_cached_latest(conn, rid, gkey[2], cache_ttl)
        if cached_v:
            return cached_v, cached_src

        # 2) Maven metadata path: if we have it or user asked to use it and this repo is maven-like
        chosen_version = None
        source = None

        should_try_metadata = False
        if use_maven_metadata and (pkg == "maven" or saw_meta):
            should_try_metadata = True

        if should_try_metadata:
            meta_url = f"{url}/artifactory/{repo}/{gkey[2]}/maven-metadata.xml".rstrip("/")
            try:
                resp = session.get(meta_url, verify=False, timeout=10)
                if resp.status_code == 200 and resp.text:
                    v = parse_maven_metadata(resp.text)
                    if v:
                        chosen_version = v
                        source = "metadata"
                # 404 or malformed -> fall back below
            except requests.RequestException:
                pass

        # 3) Fallback to path-based max
        if not chosen_version:
            # handle versionless
            if "__NOVERSION__" in ginfo["versions"]:
                chosen_version = "__NOVERSION__"
            else:
                chosen_version = pick_max_version_str(ginfo["versions"])
            source = source or "path"

        # save to cache
        upsert_latest(conn, sid, rid, gkey[2], chosen_version, source)
        return chosen_version, source

    # compute latest per group (with caching)
    latest_map = {}
    for gkey, ginfo in groups.items():
        latest_ver, _src = decide_latest_for_group(gkey, ginfo)
        latest_map[gkey] = latest_ver

    # Now write only one representative path per group using chosen version
    with open(outfile, "w") as f:
        # Sort for deterministic output
        for (sid, rid, base), version in sorted(latest_map.items(), key=lambda x: (x[0][0], x[0][1], x[0][2])):
            g = groups[(sid, rid, base)]
            if version == "__NOVERSION__":
                path = g["files_by_version"]["__NOVERSION__"]
                f.write(f"{g['server_url']}/artifactory/{g['repo_key']}/{path}\n")
                continue

            # prefer representative file recorded for that version
            rep = g["files_by_version"].get(version)
            if rep:
                f.write(f"{g['server_url']}/artifactory/{g['repo_key']}/{rep}\n")
                continue

            # If somehow not present (e.g., metadata said a version we didn't list), fall back to any file with that version in path
            fallback_written = False
            for v, p in g["files_by_version"].items():
                if v == version:
                    f.write(f"{g['server_url']}/artifactory/{g['repo_key']}/{p}\n")
                    fallback_written = True
                    break

            # If still nothing, skip silently (no matching file paths)
            if not fallback_written:
                # As a last resort, use path-based max actually present
                present = pick_max_version_str(list(g["files_by_version"].keys()))
                if present and present in g["files_by_version"]:
                    f.write(f"{g['server_url']}/artifactory/{g['repo_key']}/{g['files_by_version'][present]}\n")

# ============================================================
# Scanner
# ============================================================

class ArtifactoryScanner:
    HEADERS = {
        "User-Agent": "Mozilla/5.0",
        "Accept": "application/json, text/plain, */*",
        "Content-Type": "application/json",
        "X-Requested-With": "XMLHttpRequest"
    }

    def __init__(self, base_url, conn, fingerprint_only=False,
                 timeout=5, repo_type_filter=None, retries=3, per_repo_workers=10):
        self.conn = conn
        self.timeout = timeout
        self.repo_type_filter = repo_type_filter.upper() if repo_type_filter else None

        parsed = urlparse(base_url)
        if not parsed.scheme:
            parsed = urlparse("http://" + base_url)
        self.base_url = f"{parsed.scheme}://{parsed.netloc}"

        self.fingerprint_only = fingerprint_only
        self.artifactory_dl_base = f"{self.base_url}/artifactory"
        self.major_version = 0
        self.server_id = None
        self.per_repo_workers = max(1, int(per_repo_workers))

        # Session with retry strategy
        self.session = requests.Session()
        self.session.headers.update(self.HEADERS)
        retry_strategy = Retry(
            total=retries,
            backoff_factor=0.5,  # 0.5s, 1s, 2s...
            status_forcelist=[429, 500, 502, 503, 504],
            allowed_methods=["GET", "POST"]
        )
        adapter = HTTPAdapter(max_retries=retry_strategy)
        self.session.mount("http://", adapter)
        self.session.mount("https://", adapter)

    # ------------- fingerprint -------------

    def is_artifactory_server(self):
        test_url = f"{self.base_url}/artifactory/webapp/"
        try:
            resp = self.session.get(test_url, verify=False, timeout=self.timeout)
            server_header = resp.headers.get("Server", "")
            return ("Artifactory" in server_header or "JFrog" in server_header, server_header)
        except requests.RequestException:
            return False, ""

    def get_artifactory_version(self):
        version_url = f"{self.base_url}/artifactory/api/system/version"
        try:
            response = self.session.get(version_url, verify=False, timeout=self.timeout)
            if response.status_code == 200:
                version = response.json().get("version", "")
                if version and version[0].isdigit():
                    self.major_version = int(version.split(".")[0])
                return version
            elif response.status_code == 401:
                return "AUTH_REQUIRED"
            else:
                return None
        except requests.RequestException:
            return None

    # ------------- repo discovery -------------

    def fetch_repos(self):
        api_url = f"{self.base_url}/artifactory/api/repositories"
        try:
            response = self.session.get(api_url, verify=False, timeout=15)
            if response.status_code != 200:
                print(f"[!] Failed to fetch repositories (status {response.status_code})")
                return []

            repos = response.json()
            repo_info = []
            for r in repos:
                repo_key = r.get("key", "unknown")
                repo_type = r.get("type", "unknown").upper()  # LOCAL/REMOTE/VIRTUAL
                # packageType can be 'Maven','Generic','Docker', ...
                package_type = (r.get("packageType") or r.get("pkgType") or "").lower()
                if self.repo_type_filter and repo_type != self.repo_type_filter:
                    continue
                repo_id, listed = save_repo(self.conn, self.server_id, repo_key, repo_type, package_type)
                print(f"[{self.base_url}] Found repo: {repo_key} (Type: {repo_type}, Package: {package_type or 'unknown'}) (listed={listed})")
                repo_info.append((repo_key, repo_id, listed))
            set_server_flags(self.conn, self.server_id, repos_enumerated=True)
            return repo_info
        except requests.RequestException as e:
            print(f"[!] Error fetching repositories: {e}")
            return []

    # ------------- durable listing -------------

    def list_contents(self, repo_key, repo_id):
        """
        Process the durable folder_queue for this repo with worker threads.
        Root '' will be enqueued if missing.
        """
        if unprocessed_count(self.conn, repo_id) == 0:
            enqueue_folder(self.conn, repo_id, "")

        pending = unprocessed_count(self.conn, repo_id)
        with DB_LOCK:
            cur = self.conn.cursor()
            cur.execute("SELECT COUNT(*) FROM files WHERE repo_id=?", (repo_id,))
            files_so_far = cur.fetchone()[0]
        print(f"    [~] {repo_key}: pending folders={pending}, files so far={files_so_far}")

        def worker():
            while True:
                path = claim_next_folder(self.conn, repo_id)
                if path is None:
                    return
                try:
                    if self.major_version < 7:
                        self._process_folder_v6(repo_key, repo_id, path)
                    else:
                        self._process_folder_v7(repo_key, repo_id, path)
                except Exception as e:
                    print(f"[!] Error processing {self.base_url} repo {repo_key} path '{path}': {e}")

        threads = []
        for _ in range(self.per_repo_workers):
            t = threading.Thread(target=worker, daemon=True)
            t.start()
            threads.append(t)
        for t in threads:
            t.join()

        if unprocessed_count(self.conn, repo_id) == 0:
            mark_repo_complete(self.conn, repo_id)
            print(f"    [+] Repo complete: {repo_key}")

    def _process_maven_metadata(self, repo_key, repo_id, base_path):
        meta_url = f"{self.artifactory_dl_base}/{repo_key}/{base_path}/maven-metadata.xml".rstrip("/")
        try:
            resp = self.session.get(meta_url, verify=False, timeout=self.timeout)
            if resp.status_code == 200 and resp.text:
                latest_version = parse_maven_metadata(resp.text)
                if latest_version:
                    upsert_latest(self.conn, self.server_id, repo_id, base_path, latest_version, "metadata")
                    print(f"    [+] Cached Maven latest version for {repo_key}/{base_path}: {latest_version}")
        except requests.RequestException:
            pass

    def _process_folder_v6(self, repo_key, repo_id, path):
        api_url = f"{self.base_url}/artifactory/api/storage/{repo_key}/{quote(path)}".rstrip("/")
        try:
            response = self.session.get(api_url, verify=False, timeout=self.timeout)
            if response.status_code == 200:
                data = response.json()
                children_names = []
                for item in data.get("children", []):
                    name = item.get("uri", "").lstrip("/")
                    children_names.append(name)
                    is_folder = item.get("folder", False)
                    new_path = f"{path}/{name}".strip("/")
                    if is_folder:
                        enqueue_folder(self.conn, repo_id, new_path)
                    else:
                        save_file(self.conn, repo_id, new_path)

                # --- INSERT HERE: process Maven metadata if present ---
                if "maven-metadata.xml" in children_names:
                    self._process_maven_metadata(repo_key, repo_id, path)

            elif response.status_code in (403, 401):
                pass
            else:
                print(f"[!] Error fetching {api_url}: {response.status_code}")
        except requests.RequestException as e:
            print(f"[!] Error during list_contents v6: {e}")

    def _process_folder_v7(self, repo_key, repo_id, path):
        api_url = f"{self.base_url}/ui/api/v1/ui/v2/nativeBrowser/{repo_key}/{quote(path)}?recordNum=0"
        try:
            resp = self.session.get(api_url, verify=False, timeout=self.timeout)
            if resp.status_code == 200:
                payload = resp.json()
                children_names = []
                for item in payload.get("data", []):
                    item_name = item["name"]
                    children_names.append(item_name)
                    is_folder = item["folder"]
                    new_path = f"{path}/{item_name}".strip("/")
                    if is_folder:
                        enqueue_folder(self.conn, repo_id, new_path)
                    else:
                        save_file(self.conn, repo_id, new_path)

                # --- INSERT HERE: process Maven metadata if present ---
                if "maven-metadata.xml" in children_names:
                    self._process_maven_metadata(repo_key, repo_id, path)

            elif resp.status_code in (403, 401):
                pass
            else:
                print(f"[!] Error fetching {api_url}: {resp.status_code}")
        except requests.RequestException as e:
            print(f"[!] Error during list_contents v7: {e}")


    # ------------- run -------------

    def run(self, list_repos_only=False, specific_repo=None):
        existing_id = get_server_if_exists(self.conn, self.base_url)
        if existing_id:
            rc, rc_done, fc, pend = server_stats(self.conn, existing_id)
            print(f"[=] Resuming server in DB: {self.base_url} "
                  f"(repos total={rc}, complete={rc_done}, files={fc}, pending_folders={pend})")

        detected, server_header = self.is_artifactory_server()
        if not detected:
            print(f"[-] {self.base_url} does not appear to be an Artifactory server")
            return

        version_info = self.get_artifactory_version()
        if version_info == "AUTH_REQUIRED":
            banner = f"[+] {self.base_url} requires authentication"
        elif version_info:
            banner = f"[+] {self.base_url} (Version: {version_info})"
        else:
            banner = f"[+] {self.base_url} (Version unknown)"
        print(banner)

        self.server_id = save_server(self.conn, self.base_url, version_info, server_header)
        if self.fingerprint_only:
            return

        repos = self.fetch_repos()
        for repo_key, repo_id, listed in repos:
            if list_repos_only:
                continue
            if specific_repo and repo_key != specific_repo:
                continue
            if listed == 1 and unprocessed_count(self.conn, repo_id) == 0:
                with DB_LOCK:
                    cur = self.conn.cursor()
                    cur.execute("SELECT COUNT(*) FROM files WHERE repo_id=?", (repo_id,))
                    fcnt = cur.fetchone()[0]
                print(f"[*] Repo already complete: {repo_key} (files={fcnt}) — skipping")
                continue

            print(f"[*] Scanning repo: {repo_key}")
            self.list_contents(repo_key, repo_id)

        rc, rc_done, fc, pend = server_stats(self.conn, self.server_id)
        set_server_flags(self.conn, self.server_id,
                         repos_enumerated=True,
                         files_completed=(pend == 0 and rc == rc_done))
        if pend == 0 and rc == rc_done:
            print(f"[+] Server completed: {self.base_url} (repos={rc_done}/{rc}, files={fc})")
        else:
            print(f"[~] Server partial: {self.base_url} (repos complete={rc_done}/{rc}, files={fc}, pending_folders={pend})")

# ============================================================
# CLI
# ============================================================

def main():
    parser = argparse.ArgumentParser(description="JFrog Artifactory recursive file lister (durable resume + latest cache)")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("-u", "--url", help="Base URL of the Artifactory instance")
    group.add_argument("-U", "--url-list", help="File containing list of URLs (one per line)")
    parser.add_argument("-o", "--output", required=True, help="Output file to save results")
    parser.add_argument("-f", "--fingerprint", action="store_true", help="Only fingerprint the server")
    parser.add_argument("--type", choices=["LOCAL", "REMOTE, VIRTUAL".split(", ")[0], "VIRTUAL"], help="Only scan repos of this type")
    parser.add_argument("--timeout", type=int, default=5, help="Request timeout in seconds")
    parser.add_argument("--retries", type=int, default=3, help="Number of retries for failed requests")
    parser.add_argument("--list-repos-only", action="store_true", help="List repos but not files")
    parser.add_argument("--repo", help="Specify a single repo to list files from")
    parser.add_argument("--threads", type=int, default=5, help="Number of concurrent threads for URLs")
    parser.add_argument("--fresh", action="store_true", help="Start fresh (delete DB)")
    parser.add_argument("--resume", action="store_true", help="Resume from existing DB (default)")
    parser.add_argument("--latest-only", action="store_true", help="Only list latest version per artifact")
    parser.add_argument("--use-maven-metadata", action="store_true",
                        help="When --latest-only, consult maven-metadata.xml for Maven repos (cached in DB)")
    parser.add_argument("--cache-ttl", type=int, default=0,
                        help="Seconds before cached latest_versions entries expire (0 = no expiry)")
    args = parser.parse_args()

    # Resume is default behavior; --fresh overrides
    conn = init_db(fresh=args.fresh)

    urls = [args.url] if args.url else [line.strip() for line in open(args.url_list) if line.strip()]

    def scan_url(url):
        scanner = ArtifactoryScanner(
            url,
            conn=conn,
            fingerprint_only=args.fingerprint,
            timeout=args.timeout,
            repo_type_filter=args.type,
            retries=args.retries,
            per_repo_workers=max(2, args.threads)  # reuse threads for per-repo parallelism
        )
        scanner.run(list_repos_only=args.list_repos_only, specific_repo=args.repo)

    with ThreadPoolExecutor(max_workers=args.threads) as executor:
        futures = {executor.submit(scan_url, url): url for url in urls}
        for future in as_completed(futures):
            try:
                future.result()
            except Exception as e:
                print(f"[!] Error scanning {futures[future]}: {e}")

    dump_results(
        conn,
        args.output,
        latest_only=args.latest_only,
        use_maven_metadata=args.use_maven_metadata,
        cache_ttl=args.cache_ttl
    )
    conn.close()

if __name__ == "__main__":
    main()
