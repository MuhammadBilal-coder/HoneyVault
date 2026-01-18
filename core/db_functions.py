from __future__ import annotations

import hashlib
import json
import os
import re
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from core.db_mysql import get_connection


LOGS_FOLDER = "logs"
LOG_FILE_NAME = "activity_log.txt"


def _utc_iso() -> str:
    """UTC timestamp in ISO-8601 (Z) for consistent evidence logs."""
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _sha256_hex(data: str) -> str:
    return hashlib.sha256(data.encode("utf-8", errors="replace")).hexdigest()


def _log_file_path() -> str:
    os.makedirs(LOGS_FOLDER, exist_ok=True)
    return os.path.join(LOGS_FOLDER, LOG_FILE_NAME)


def _read_last_hash(log_path: str) -> str:
    """Get last entry's hash (supports legacy non-JSON lines)."""
    if not os.path.exists(log_path):
        return "0" * 64

    try:
        with open(log_path, "rb") as f:
            f.seek(0, os.SEEK_END)
            size = f.tell()
            block = 8192
            start = max(0, size - block)
            f.seek(start)
            tail = f.read().decode("utf-8", errors="replace")
    except Exception:
        return "0" * 64

    lines = [ln for ln in tail.splitlines() if ln.strip()]
    if not lines:
        return "0" * 64

    last = lines[-1]
    try:
        obj = json.loads(last)
        h = obj.get("hash")
        if isinstance(h, str) and len(h) == 64:
            return h
    except Exception:
        pass

    return _sha256_hex(last)


def _canonical_string(entry: Dict[str, Any]) -> str:
    # IMPORTANT: keep stable order for hashing
    return "|".join(
        [
            str(entry.get("timestamp", "")),
            str(entry.get("user_ip", "")),
            str(entry.get("action", "")),
            str(entry.get("filename", "")),
            str(entry.get("result", "")),
            str(entry.get("message", "")),
            str(entry.get("prev_hash", "")),
        ]
    )


def _append_hashchained_log(entry: Dict[str, Any]) -> Dict[str, Any]:
    """Append entry to text log with hash-chain fields."""
    log_path = _log_file_path()
    prev_hash = _read_last_hash(log_path)
    entry["prev_hash"] = prev_hash

    canonical = _canonical_string(entry)
    entry["hash"] = _sha256_hex(canonical)

    with open(log_path, "a", encoding="utf-8") as f:
        f.write(json.dumps(entry, ensure_ascii=False, separators=(",", ":")) + "\n")

    return entry



def add_file_record(original_name, encrypted_name, time_lock, uploaded_to_server):
    """Insert file record into file_records table."""
    conn = get_connection()
    cursor = conn.cursor()

    query = """
        INSERT INTO file_records (original_name, encrypted_name, upload_time, time_lock, uploaded_to_server)
        VALUES (%s, %s, NOW(), %s, %s)
    """

    time_lock_value = time_lock if time_lock else None
    values = (original_name, encrypted_name, time_lock_value, uploaded_to_server)
    cursor.execute(query, values)

    conn.commit()
    last_id = cursor.lastrowid
    conn.close()

    return last_id


def add_key_record(file_id, k1, k2, k3):
    """Insert key records."""
    conn = get_connection()
    cursor = conn.cursor()

    query = """
        INSERT INTO key_records (file_id, key_part_1, key_part_2, key_part_3)
        VALUES (%s, %s, %s, %s)
    """

    values = (file_id, k1, k2, k3)
    cursor.execute(query, values)

    conn.commit()
    conn.close()




def add_log(
    event: Optional[str] = None,
    *,
    action: Optional[str] = None,
    filename: Optional[str] = None,
    result: Optional[str] = None,
    user_ip: Optional[str] = None,
    extra: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """
    Add a log entry with required evidence fields:
      timestamp, user/ip, action, filename, result
    Plus a hash-chain (prev_hash + hash).

    Backward compatible:
      - old calls like add_log("Encrypted file: x") still work.

    NOTE: DB schema stays untouched; we store JSON string in logs.event.
    """

    entry: Dict[str, Any] = {
        "timestamp": _utc_iso(),
        "user_ip": user_ip or "unknown",
        "action": action or "EVENT",
        "filename": filename or "",
        "result": result or "OK",
        "message": event or "",
    }
    if extra and isinstance(extra, dict):
        entry.update(extra)

    # 1) TEXT FILE (tamper-evident chain)
    try:
        entry = _append_hashchained_log(entry)
    except Exception:
        pass

    # 2) DATABASE LOG (JSON)
    try:
        conn = get_connection()
        cursor = conn.cursor()
        query = """
            INSERT INTO logs (event, time)
            VALUES (%s, NOW())
        """
        cursor.execute(query, (json.dumps(entry, ensure_ascii=False),))
        conn.commit()
        conn.close()
    except Exception:
        pass

    return entry



_LEGACY_RE = re.compile(r"^\[(?P<ts>[^\]]+)\]\s*(?P<msg>.*)$")


def _infer_from_legacy_message(msg: str) -> Dict[str, str]:
    """
    Infer action/result/filename from old messages like:
      "Encrypted file: abc.docx"
      "Decrypted file: abc.docx.enc"
      "Decryption failed: abc.docx.enc"
      "Created honey trap files: a.txt, b.txt"
    """
    s = (msg or "").strip()

    # defaults
    action = "LEGACY"
    result = "OK"
    filename = ""

    lower = s.lower()

    if "decryption failed:" in lower:
        action = "DECRYPT"
        result = "FAILED"
        filename = s.split(":", 1)[-1].strip()
    elif "decrypted file:" in lower:
        action = "DECRYPT"
        result = "OK"
        filename = s.split(":", 1)[-1].strip()
    elif "encrypted file:" in lower:
        action = "ENCRYPT"
        result = "OK"
        filename = s.split(":", 1)[-1].strip()
    elif "created honey trap files:" in lower:
        action = "HONEY_INIT"
        result = "OK"
        filename = s.split(":", 1)[-1].strip()
    elif "intrusion" in lower:
        action = "INTRUSION"
        result = "ALERT"

    return {"action": action, "result": result, "filename": filename}


def _verify_log_chain(log_path: str) -> List[Dict[str, Any]]:
    """Verify entire log file chain and return parsed entries with integrity flag."""
    if not os.path.exists(log_path):
        return []

    parsed: List[Dict[str, Any]] = []
    with open(log_path, "r", encoding="utf-8", errors="replace") as f:
        for line in f:
            ln = line.strip()
            if not ln:
                continue
            try:
                obj = json.loads(ln)
                if isinstance(obj, dict):
                    parsed.append(obj)
                    continue
            except Exception:
                pass

            # legacy plaintext
            ts = ""
            msg = ln
            m = _LEGACY_RE.match(ln)
            if m:
                ts = (m.group("ts") or "").strip()
                msg = (m.group("msg") or "").strip()

            inferred = _infer_from_legacy_message(msg)
            parsed.append(
                {
                    "timestamp": ts,  # keep original legacy timestamp as-is
                    "user_ip": "unknown",
                    "action": inferred["action"],
                    "filename": inferred["filename"],
                    "result": inferred["result"],
                    "message": msg,
                    "prev_hash": None,
                    "hash": _sha256_hex(ln),  # legacy hash = hash(line)
                }
            )

    # verify chain
    prev_hash = "0" * 64
    for obj in parsed:
        # LEGACY entries: accept their stored hash but still chain order
        if obj.get("action") in ("LEGACY", "ENCRYPT", "DECRYPT", "HONEY_INIT", "INTRUSION") and obj.get("prev_hash") is None:
            obj["integrity_ok"] = True
            obj["prev_hash"] = prev_hash
            prev_hash = obj.get("hash")
            continue

        expected_prev = obj.get("prev_hash")
        canonical = _canonical_string(obj)
        expected_hash = _sha256_hex(canonical)

        ok = True
        if expected_prev != prev_hash:
            ok = False
        if obj.get("hash") != expected_hash:
            ok = False

        obj["integrity_ok"] = ok
        prev_hash = obj.get("hash")

    return parsed



def get_all_files():
    """Get all encrypted files."""
    conn = get_connection()
    cursor = conn.cursor(dictionary=True)

    query = """
        SELECT id, original_name, encrypted_name, upload_time,
               time_lock, uploaded_to_server
        FROM file_records
        ORDER BY upload_time DESC
    """

    cursor.execute(query)
    files = cursor.fetchall()
    conn.close()
    return files


def get_recent_logs(limit: int = 10):
    """
    Read recent logs from the hash-chained text file (preferred),
    fallback to DB if file missing.
    """
    log_path = _log_file_path()
    entries = _verify_log_chain(log_path)
    if entries:
        return list(reversed(entries[-limit:]))

    conn = get_connection()
    cursor = conn.cursor(dictionary=True)

    query = """
        SELECT event, time
        FROM logs
        ORDER BY time DESC
        LIMIT %s
    """
    cursor.execute(query, (limit,))
    rows = cursor.fetchall()
    conn.close()

    out = []
    for r in rows:
        ev = r.get("event")
        try:
            obj = json.loads(ev)
            if isinstance(obj, dict):
                out.append(obj)
                continue
        except Exception:
            pass
        out.append(
            {
                "timestamp": (r.get("time") or ""),
                "user_ip": "unknown",
                "action": "EVENT",
                "filename": "",
                "result": "OK",
                "message": str(ev or ""),
                "prev_hash": "",
                "hash": "",
                "integrity_ok": None,
            }
        )
    return out


def get_statistics():
    """Get statistics."""
    conn = get_connection()
    cursor = conn.cursor(dictionary=True)

    cursor.execute("SELECT COUNT(*) as total FROM file_records")
    total_files = cursor.fetchone()["total"]

    cursor.execute("SELECT COUNT(*) as total FROM file_records WHERE uploaded_to_server = 1")
    server_uploads = cursor.fetchone()["total"]

    cursor.execute("SELECT COUNT(*) as total FROM logs WHERE event LIKE 'Decrypted%'")
    decryptions = cursor.fetchone()["total"]

    cursor.execute(
        "SELECT COUNT(*) as total FROM file_records WHERE time_lock IS NOT NULL AND time_lock > NOW()"
    )
    active_locks = cursor.fetchone()["total"]

    conn.close()
    return {
        "total_files": total_files,
        "server_uploads": server_uploads,
        "decryptions": decryptions,
        "active_locks": active_locks,
    }


def get_key_info(file_id):
    """Get key info for a file."""
    conn = get_connection()
    cursor = conn.cursor(dictionary=True)

    query = "SELECT key_part_1, key_part_2, key_part_3 FROM key_records WHERE file_id = %s"
    cursor.execute(query, (file_id,))
    result = cursor.fetchone()
    conn.close()
    return result
