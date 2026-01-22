#!/usr/bin/env python3
"""
mwdb-feeder: Multi-source malware sample aggregator for MWDB.

Polls various "in the wild" malware sources and uploads samples to MWDB
for analysis via the Karton pipeline.

Supported sources:
- URLhaus (abuse.ch) - Malicious URLs and payloads
- ThreatFox (abuse.ch) - IOCs and malware samples

Author: Claude AI (automated malware analysis pipeline)
Version: 1.0.0
"""

import os
import sys
import time
import sqlite3
import logging
import hashlib
import json
import zipfile
import io
import threading
from queue import Queue, Empty
from datetime import datetime, timezone
from dataclasses import dataclass
from pathlib import Path
from typing import Optional, List, Dict, Any

import requests
from dotenv import load_dotenv

# Optional: websocket for ANY.RUN public feed
try:
    import websocket
    WEBSOCKET_AVAILABLE = True
except ImportError:
    WEBSOCKET_AVAILABLE = False

# Optional: mwdblib for upload
try:
    from mwdblib import MWDB
    MWDB_AVAILABLE = True
except ImportError:
    MWDB_AVAILABLE = False
    print("Warning: mwdblib not available, will use REST API")

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s %(levelname)-8s %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
log = logging.getLogger(__name__)


@dataclass
class Config:
    """Configuration from environment variables."""
    # MWDB
    mwdb_url: str
    mwdb_api_key: str

    # URLhaus
    urlhaus_enabled: bool
    urlhaus_url: str
    urlhaus_auth_key: str
    urlhaus_poll_seconds: int
    urlhaus_zip_password: str

    # ThreatFox
    threatfox_enabled: bool
    threatfox_url: str
    threatfox_auth_key: str
    threatfox_poll_seconds: int

    # Hybrid Analysis (Falcon Sandbox)
    hybrid_analysis_enabled: bool
    hybrid_analysis_api_key: str
    hybrid_analysis_poll_seconds: int

    # ANY.RUN (API Key or Web Scraping)
    anyrun_enabled: bool
    anyrun_api_key: str  # Preferred: API key from paid plan
    anyrun_username: str  # Fallback: email for DDP login
    anyrun_password: str  # Fallback: password for DDP login
    anyrun_poll_seconds: int

    # General
    work_dir: str
    state_db: str
    report_path: str
    max_mb_per_file: int


def load_config() -> Config:
    """Load configuration from environment variables."""
    load_dotenv()

    return Config(
        # MWDB
        mwdb_url=os.getenv('MWDB_URL', 'http://127.0.0.1:8081/api'),
        mwdb_api_key=os.getenv('MWDB_API_KEY', ''),

        # URLhaus
        urlhaus_enabled=os.getenv('URLHAUS_ENABLED', 'false').lower() == 'true',
        urlhaus_url=os.getenv('URLHAUS_URL', 'https://urlhaus-api.abuse.ch/v1/'),
        urlhaus_auth_key=os.getenv('URLHAUS_AUTH_KEY', ''),
        urlhaus_poll_seconds=int(os.getenv('URLHAUS_POLL_SECONDS', '300')),
        urlhaus_zip_password=os.getenv('URLHAUS_ZIP_PASSWORD', 'infected'),

        # ThreatFox
        threatfox_enabled=os.getenv('THREATFOX_ENABLED', 'false').lower() == 'true',
        threatfox_url=os.getenv('THREATFOX_URL', 'https://threatfox-api.abuse.ch/api/v1/'),
        threatfox_auth_key=os.getenv('THREATFOX_AUTH_KEY', ''),
        threatfox_poll_seconds=int(os.getenv('THREATFOX_POLL_SECONDS', '300')),

        # Hybrid Analysis (Falcon Sandbox)
        hybrid_analysis_enabled=os.getenv('HYBRID_ANALYSIS_ENABLED', 'false').lower() == 'true',
        hybrid_analysis_api_key=os.getenv('HYBRID_ANALYSIS_API_KEY', ''),
        hybrid_analysis_poll_seconds=int(os.getenv('HYBRID_ANALYSIS_POLL_SECONDS', '900')),

        # ANY.RUN (API Key or Web Scraping)
        anyrun_enabled=os.getenv('ANYRUN_ENABLED', 'false').lower() == 'true',
        anyrun_api_key=os.getenv('ANYRUN_API_KEY', ''),
        anyrun_username=os.getenv('ANYRUN_USERNAME', ''),
        anyrun_password=os.getenv('ANYRUN_PASSWORD', ''),
        anyrun_poll_seconds=int(os.getenv('ANYRUN_POLL_SECONDS', '600')),

        # General
        work_dir=os.getenv('WORK_DIR', '/work'),
        state_db=os.getenv('STATE_DB', '/work/state.db'),
        report_path=os.getenv('REPORT_PATH', '/work/reports/mwdb-feeder.jsonl'),
        max_mb_per_file=int(os.getenv('MAX_MB_PER_FILE', '50'))
    )


def init_database(db_path: str) -> sqlite3.Connection:
    """Initialize SQLite database for tracking processed samples."""
    conn = sqlite3.connect(db_path)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("""
        CREATE TABLE IF NOT EXISTS processed (
            sha256 TEXT PRIMARY KEY,
            source TEXT,
            processed_at TEXT,
            mwdb_uploaded INTEGER DEFAULT 0,
            filename TEXT,
            file_type TEXT
        )
    """)
    conn.execute("""
        CREATE INDEX IF NOT EXISTS idx_source ON processed(source)
    """)
    conn.commit()
    return conn


def is_processed(conn: sqlite3.Connection, sha256: str) -> bool:
    """Check if a sample has already been processed."""
    cur = conn.execute("SELECT 1 FROM processed WHERE sha256 = ?", (sha256,))
    return cur.fetchone() is not None


def mark_processed(conn: sqlite3.Connection, sha256: str, source: str,
                   filename: str = None, file_type: str = None, uploaded: bool = True):
    """Mark a sample as processed."""
    conn.execute("""
        INSERT OR REPLACE INTO processed (sha256, source, processed_at, mwdb_uploaded, filename, file_type)
        VALUES (?, ?, ?, ?, ?, ?)
    """, (sha256, source, datetime.now(timezone.utc).isoformat(), 1 if uploaded else 0, filename, file_type))
    conn.commit()


def log_event(report_path: str, event: Dict[str, Any]):
    """Append event to JSONL report file."""
    event['timestamp'] = datetime.now(timezone.utc).isoformat()
    Path(report_path).parent.mkdir(parents=True, exist_ok=True)
    with open(report_path, 'a') as f:
        f.write(json.dumps(event) + '\n')


class MWDBUploader:
    """Handle uploads to MWDB."""

    def __init__(self, cfg: Config):
        self.cfg = cfg
        self.mwdb = None

        if MWDB_AVAILABLE and cfg.mwdb_api_key:
            try:
                self.mwdb = MWDB(api_url=cfg.mwdb_url, api_key=cfg.mwdb_api_key)
                log.info(f"MWDB client initialized: {cfg.mwdb_url}")
            except Exception as e:
                log.error(f"Failed to initialize MWDB client: {e}")

    def upload(self, content: bytes, filename: str, sha256: str,
               source: str, tags: List[str] = None) -> bool:
        """Upload sample to MWDB."""
        if not self.mwdb:
            log.warning("MWDB client not available")
            return False

        try:
            # Check if already exists
            try:
                existing = self.mwdb.query_file(sha256)
                if existing:
                    log.info(f"Sample {sha256[:16]}... already exists in MWDB")
                    # Add source tag if not present
                    if f"source:{source}" not in [t.tag for t in existing.tags]:
                        existing.add_tag(f"source:{source}")
                    return True
            except Exception:
                pass  # Not found, proceed with upload

            # Upload new sample
            all_tags = tags or []
            all_tags.append(f"source:{source}")
            all_tags.append("mwdb-feeder")

            result = self.mwdb.upload_file(filename, content)

            # Add tags
            for tag in all_tags:
                try:
                    result.add_tag(tag)
                except Exception:
                    pass

            log.info(f"Uploaded {sha256[:16]}... to MWDB ({filename})")
            return True

        except Exception as e:
            log.error(f"Failed to upload {sha256[:16]}... to MWDB: {e}")
            return False


class URLhausSource:
    """URLhaus malware feed source."""

    def __init__(self, cfg: Config):
        self.cfg = cfg
        self.session = requests.Session()
        if cfg.urlhaus_auth_key:
            self.session.headers['Auth-Key'] = cfg.urlhaus_auth_key

    def fetch_recent(self, limit: int = 50) -> List[Dict]:
        """Fetch recent payloads from URLhaus."""
        if not self.cfg.urlhaus_enabled:
            return []

        try:
            # URLhaus API: GET request with Auth-Key header
            resp = self.session.get(
                f"https://urlhaus-api.abuse.ch/v1/payloads/recent/?limit={limit}",
                timeout=30
            )
            resp.raise_for_status()
            data = resp.json()

            if data.get('query_status') != 'ok':
                log.warning(f"URLhaus query failed: {data.get('query_status')}")
                return []

            payloads = data.get('payloads', [])
            log.info(f"URLhaus: fetched {len(payloads)} recent payloads")
            return payloads

        except Exception as e:
            log.error(f"URLhaus fetch error: {e}")
            return []

    def download_payload(self, sha256: str) -> Optional[bytes]:
        """Download payload by SHA256 hash.

        URLhaus serves samples as encrypted ZIP files with password 'infected'.
        """
        try:
            resp = self.session.get(
                f"https://urlhaus-api.abuse.ch/v1/download/{sha256}/",
                timeout=60
            )

            if resp.status_code != 200:
                log.warning(f"URLhaus download failed: {resp.status_code}")
                return None

            # URLhaus serves encrypted ZIP files with password "infected"
            try:
                zip_content = io.BytesIO(resp.content)
                with zipfile.ZipFile(zip_content, 'r') as zf:
                    # Extract with password
                    file_list = zf.namelist()
                    if not file_list:
                        log.warning(f"Empty ZIP for {sha256[:16]}...")
                        return None

                    # Extract the first file (malware sample)
                    content = zf.read(file_list[0], pwd=self.cfg.urlhaus_zip_password.encode())

                    # Verify hash
                    if hashlib.sha256(content).hexdigest().lower() == sha256.lower():
                        return content
                    else:
                        log.warning(f"Hash mismatch for {sha256[:16]}... after extraction")
                        return None

            except zipfile.BadZipFile:
                # Not a ZIP file - might be raw content
                if hashlib.sha256(resp.content).hexdigest().lower() == sha256.lower():
                    return resp.content
                log.warning(f"Invalid ZIP and hash mismatch for {sha256[:16]}...")
                return None

        except Exception as e:
            log.error(f"URLhaus download error for {sha256[:16]}...: {e}")
            return None


class ThreatFoxSource:
    """ThreatFox IOC and malware feed source."""

    def __init__(self, cfg: Config):
        self.cfg = cfg
        self.session = requests.Session()
        if cfg.threatfox_auth_key:
            self.session.headers['Auth-Key'] = cfg.threatfox_auth_key

    def fetch_recent(self, days: int = 1) -> List[Dict]:
        """Fetch recent IOCs with malware samples from ThreatFox."""
        if not self.cfg.threatfox_enabled:
            return []

        try:
            # ThreatFox API: POST with Auth-Key header
            resp = self.session.post(
                "https://threatfox-api.abuse.ch/api/v1/",
                json={"query": "get_iocs", "days": days},
                headers={"Content-Type": "application/json"},
                timeout=30
            )
            resp.raise_for_status()
            data = resp.json()

            if data.get('query_status') != 'ok':
                log.warning(f"ThreatFox query failed: {data.get('query_status')}")
                return []

            iocs = data.get('data', [])
            # Filter to only malware samples with hashes
            samples = [
                ioc for ioc in iocs
                if ioc.get('ioc_type') in ('md5_hash', 'sha256_hash')
                and ioc.get('malware_printable')
            ]

            log.info(f"ThreatFox: fetched {len(samples)} malware IOCs")
            return samples

        except Exception as e:
            log.error(f"ThreatFox fetch error: {e}")
            return []


class HybridAnalysisSource:
    """Hybrid Analysis (Falcon Sandbox) malware feed source."""

    def __init__(self, cfg: Config):
        self.cfg = cfg
        self.session = requests.Session()
        self.session.headers['api-key'] = cfg.hybrid_analysis_api_key
        self.session.headers['User-Agent'] = 'Falcon Sandbox'

    def fetch_recent(self, limit: int = 50) -> List[Dict]:
        """Fetch recent public samples from Hybrid Analysis feed."""
        if not self.cfg.hybrid_analysis_enabled:
            return []

        if not self.cfg.hybrid_analysis_api_key:
            log.warning("Hybrid Analysis API key not configured")
            return []

        try:
            # Get latest public feed
            resp = self.session.get(
                "https://www.hybrid-analysis.com/api/v2/feed/latest",
                timeout=30
            )
            resp.raise_for_status()
            data = resp.json()

            if not isinstance(data, list):
                data = data.get('data', [])

            log.info(f"Hybrid Analysis: fetched {len(data)} recent samples")
            return data[:limit]

        except Exception as e:
            log.error(f"Hybrid Analysis fetch error: {e}")
            return []

    def download_sample(self, sha256: str) -> Optional[bytes]:
        """Download sample by SHA256 hash."""
        try:
            resp = self.session.get(
                f"https://www.hybrid-analysis.com/api/v2/overview/{sha256}/sample",
                timeout=120
            )

            if resp.status_code == 200:
                content = resp.content
                # Verify hash
                if hashlib.sha256(content).hexdigest().lower() == sha256.lower():
                    return content
                else:
                    # Might be gzip compressed
                    try:
                        import gzip
                        decompressed = gzip.decompress(content)
                        if hashlib.sha256(decompressed).hexdigest().lower() == sha256.lower():
                            return decompressed
                    except Exception:
                        pass
                    log.warning(f"Hash mismatch for HA sample {sha256[:16]}...")
                    return None
            elif resp.status_code == 404:
                log.debug(f"Sample not available for download: {sha256[:16]}...")
                return None
            else:
                log.warning(f"Hybrid Analysis download failed: {resp.status_code}")
                return None

        except Exception as e:
            log.error(f"Hybrid Analysis download error for {sha256[:16]}...: {e}")
            return None


class AnyRunSource:
    """ANY.RUN malware samples via official API.

    Requires an API key from ANY.RUN (paid plan: Searcher or above).
    Generate your API key at: https://app.any.run/profile -> API & Limits

    Note: Web scraping / DDP login is blocked by Cloudflare protections.
    """

    API_BASE = "https://api.any.run"

    def __init__(self, cfg: Config):
        self.cfg = cfg
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'Accept': 'application/json',
        })

        # Use API key authentication
        if cfg.anyrun_api_key:
            self.session.headers['Authorization'] = f'API-Key {cfg.anyrun_api_key}'
            self.authenticated = True
            log.info("ANY.RUN using API key authentication")
        else:
            self.authenticated = False
            log.warning("ANY.RUN API key not configured - source will be limited")

    def fetch_recent(self, limit: int = 50) -> List[Dict]:
        """Fetch recent malicious public submissions from ANY.RUN."""
        if not self.authenticated:
            log.warning("ANY.RUN: no API key configured, skipping fetch")
            return []

        try:
            # Use TI Lookup API to get recent malicious samples
            # Endpoint: GET /v1/analysis with filters
            resp = self.session.get(
                f"{self.API_BASE}/v1/analysis",
                params={
                    "skip": 0,
                    "limit": limit,
                    "isPublic": "true",
                    "verdict": "malicious"
                },
                timeout=60
            )

            if resp.status_code == 200:
                data = resp.json()
                tasks = data.get('data', data.get('tasks', data if isinstance(data, list) else []))
                if isinstance(tasks, list):
                    log.info(f"ANY.RUN: fetched {len(tasks)} malicious submissions")
                    return tasks
                return []

            elif resp.status_code == 401:
                log.error("ANY.RUN: API key invalid or expired")
                return []

            elif resp.status_code == 403:
                log.error("ANY.RUN: API access forbidden - check your subscription plan")
                return []

            else:
                log.warning(f"ANY.RUN fetch failed: {resp.status_code} - {resp.text[:100]}")
                return []

        except Exception as e:
            log.error(f"ANY.RUN fetch error: {e}")
            return []

    def download_sample(self, task_id: str, sha256: str) -> Optional[bytes]:
        """Download sample from ANY.RUN task."""
        if not task_id or not self.authenticated:
            return None

        try:
            # Try official API sample download
            download_urls = [
                f"{self.API_BASE}/v1/analysis/{task_id}/sample",
                f"https://content.any.run/tasks/{task_id}/download/files/{sha256}"
            ]

            for download_url in download_urls:
                resp = self.session.get(download_url, timeout=120)

                if resp.status_code == 200 and len(resp.content) > 0:
                    content = resp.content

                    # Check if it's the actual file
                    if hashlib.sha256(content).hexdigest().lower() == sha256.lower():
                        return content

                    # Might be a ZIP with password
                    try:
                        zip_content = io.BytesIO(content)
                        with zipfile.ZipFile(zip_content, 'r') as zf:
                            for name in zf.namelist():
                                try:
                                    extracted = zf.read(name, pwd=b'infected')
                                    if hashlib.sha256(extracted).hexdigest().lower() == sha256.lower():
                                        return extracted
                                except Exception:
                                    pass
                    except zipfile.BadZipFile:
                        pass

            return None

        except Exception as e:
            log.debug(f"ANY.RUN download error for {sha256[:16]}...: {e}")
            return None


def main():
    """Main entry point."""
    log.info("mwdb-feeder v1.0.0 starting...")

    cfg = load_config()

    # Validate configuration
    if not cfg.mwdb_api_key:
        log.error("MWDB_API_KEY is required")
        sys.exit(1)

    # Initialize components
    Path(cfg.work_dir).mkdir(parents=True, exist_ok=True)
    conn = init_database(cfg.state_db)
    uploader = MWDBUploader(cfg)

    # Initialize sources
    sources = {}
    if cfg.urlhaus_enabled:
        sources['urlhaus'] = URLhausSource(cfg)
        log.info("URLhaus source enabled")
    if cfg.threatfox_enabled:
        sources['threatfox'] = ThreatFoxSource(cfg)
        log.info("ThreatFox source enabled")
    if cfg.hybrid_analysis_enabled:
        sources['hybrid_analysis'] = HybridAnalysisSource(cfg)
        log.info("Hybrid Analysis source enabled")
    if cfg.anyrun_enabled:
        if cfg.anyrun_api_key:
            sources['anyrun'] = AnyRunSource(cfg)
            log.info("ANY.RUN source enabled (API key)")
        else:
            log.warning("ANY.RUN enabled but API key not configured")
            log.warning("Generate API key at: https://app.any.run/profile -> API & Limits")

    if not sources:
        log.warning("No sources enabled! Enable at least one source in .env")

    # Track last poll times
    last_poll = {name: 0 for name in sources}

    log.info("Entering main loop...")

    while True:
        now = time.time()

        # Poll URLhaus
        if 'urlhaus' in sources:
            if now - last_poll['urlhaus'] >= cfg.urlhaus_poll_seconds:
                last_poll['urlhaus'] = now
                urlhaus = sources['urlhaus']

                for payload in urlhaus.fetch_recent(limit=50):
                    sha256 = payload.get('sha256_hash', '').lower()
                    if not sha256:
                        continue

                    if is_processed(conn, sha256):
                        continue

                    # Check file size
                    file_size = int(payload.get('file_size', 0))
                    if file_size > cfg.max_mb_per_file * 1024 * 1024:
                        log.info(f"Skipping {sha256[:16]}...: too large ({file_size} bytes)")
                        mark_processed(conn, sha256, 'urlhaus', uploaded=False)
                        continue

                    # Download payload
                    content = urlhaus.download_payload(sha256)
                    if not content:
                        continue

                    filename = payload.get('filename') or f"{sha256[:16]}.bin"
                    file_type = payload.get('file_type', 'unknown')

                    # Determine tags
                    tags = ['urlhaus']
                    if payload.get('signature'):
                        tags.append(f"malware:{payload['signature']}")

                    # Upload to MWDB
                    uploaded = uploader.upload(content, filename, sha256, 'urlhaus', tags)
                    mark_processed(conn, sha256, 'urlhaus', filename, file_type, uploaded)

                    log_event(cfg.report_path, {
                        'source': 'urlhaus',
                        'sha256': sha256,
                        'filename': filename,
                        'file_type': file_type,
                        'uploaded': uploaded,
                        'signature': payload.get('signature')
                    })

        # Poll ThreatFox
        if 'threatfox' in sources:
            if now - last_poll['threatfox'] >= cfg.threatfox_poll_seconds:
                last_poll['threatfox'] = now
                threatfox = sources['threatfox']

                for ioc in threatfox.fetch_recent(days=1):
                    # ThreatFox provides hashes but not direct downloads
                    # We log the IOC but can't download without additional sources
                    sha256 = None
                    if ioc.get('ioc_type') == 'sha256_hash':
                        sha256 = ioc.get('ioc', '').lower()

                    if not sha256:
                        continue

                    if is_processed(conn, sha256):
                        continue

                    # Log the IOC (no download available from ThreatFox directly)
                    mark_processed(conn, sha256, 'threatfox',
                                   ioc.get('malware_printable'),
                                   ioc.get('ioc_type'),
                                   uploaded=False)

                    log_event(cfg.report_path, {
                        'source': 'threatfox',
                        'sha256': sha256,
                        'malware': ioc.get('malware_printable'),
                        'ioc_type': ioc.get('ioc_type'),
                        'uploaded': False,
                        'note': 'ThreatFox IOC logged (no direct download)'
                    })

        # Poll Hybrid Analysis
        if 'hybrid_analysis' in sources:
            if now - last_poll['hybrid_analysis'] >= cfg.hybrid_analysis_poll_seconds:
                last_poll['hybrid_analysis'] = now
                ha = sources['hybrid_analysis']

                for sample in ha.fetch_recent(limit=50):
                    sha256 = sample.get('sha256', '').lower()
                    if not sha256:
                        continue

                    if is_processed(conn, sha256):
                        continue

                    # Check file size (if available)
                    file_size = int(sample.get('size', 0))
                    if file_size > cfg.max_mb_per_file * 1024 * 1024:
                        log.info(f"Skipping HA {sha256[:16]}...: too large ({file_size} bytes)")
                        mark_processed(conn, sha256, 'hybrid_analysis', uploaded=False)
                        continue

                    # Download sample
                    content = ha.download_sample(sha256)
                    if not content:
                        # Sample not available for download, just log it
                        mark_processed(conn, sha256, 'hybrid_analysis',
                                       sample.get('type_short'),
                                       sample.get('verdict'),
                                       uploaded=False)
                        continue

                    filename = sample.get('submit_name') or f"{sha256[:16]}.bin"
                    verdict = sample.get('verdict', 'unknown')

                    # Determine tags
                    tags = ['hybrid-analysis']
                    if sample.get('verdict'):
                        tags.append(f"verdict:{sample['verdict']}")
                    if sample.get('vx_family'):
                        tags.append(f"malware:{sample['vx_family']}")

                    # Upload to MWDB
                    uploaded = uploader.upload(content, filename, sha256, 'hybrid_analysis', tags)
                    mark_processed(conn, sha256, 'hybrid_analysis', filename, verdict, uploaded)

                    log_event(cfg.report_path, {
                        'source': 'hybrid_analysis',
                        'sha256': sha256,
                        'filename': filename,
                        'verdict': verdict,
                        'vx_family': sample.get('vx_family'),
                        'uploaded': uploaded
                    })

        # Poll ANY.RUN
        if 'anyrun' in sources:
            if now - last_poll['anyrun'] >= cfg.anyrun_poll_seconds:
                last_poll['anyrun'] = now
                anyrun = sources['anyrun']

                for task in anyrun.fetch_recent(limit=30):
                    # Extract task info - ANY.RUN API returns various formats
                    task_id = task.get('uuid') or task.get('taskId') or task.get('_id', '')
                    hashes = task.get('hashes', {})
                    sha256 = (hashes.get('sha256') or task.get('sha256', '')).lower()

                    if not sha256 or not task_id:
                        continue

                    if is_processed(conn, sha256):
                        continue

                    # Download sample
                    content = anyrun.download_sample(task_id, sha256)
                    if not content:
                        # Mark as processed but not uploaded
                        mark_processed(conn, sha256, 'anyrun',
                                       task.get('name'),
                                       task.get('verdict'),
                                       uploaded=False)
                        continue

                    filename = task.get('name') or f"{sha256[:16]}.bin"
                    verdict = task.get('verdict', 'malicious')

                    # Determine tags
                    tags = ['anyrun']
                    if verdict:
                        tags.append(f"verdict:{verdict}")
                    # Extract malware family if available
                    main_obj = task.get('mainObject', {})
                    if isinstance(main_obj, dict):
                        info = main_obj.get('info', {})
                        if isinstance(info, dict) and info.get('meta'):
                            tags.append(f"malware:{info['meta']}")
                    # Add task tags
                    for tag in task.get('tags', []):
                        if isinstance(tag, str) and tag:
                            tags.append(f"anyrun:{tag}")

                    # Upload to MWDB
                    uploaded = uploader.upload(content, filename, sha256, 'anyrun', tags)
                    mark_processed(conn, sha256, 'anyrun', filename, verdict, uploaded)

                    log_event(cfg.report_path, {
                        'source': 'anyrun',
                        'sha256': sha256,
                        'filename': filename,
                        'verdict': verdict,
                        'uploaded': uploaded
                    })

        # Sleep before next iteration
        time.sleep(30)


if __name__ == "__main__":
    main()
