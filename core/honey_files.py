import os
import time
import uuid
import hashlib


def list_real_files(folder: str):
    """Ignore hidden/desktop.ini, return real files only."""
    if not os.path.exists(folder):
        return []
    out = []
    for f in os.listdir(folder):
        if f.startswith("."):
            continue
        if f.lower() == "desktop.ini":
            continue
        p = os.path.join(folder, f)
        if os.path.isfile(p):
            out.append(f)
    return out


def _sha256_file(path: str) -> str:
    """Return SHA-256 hex digest of file content (streaming, safe for big files)."""
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def create_honey_files(honey_dir: str, count: int = 5):
    """
    Default honey decoy txt files making.
    return: created filenames list
    """
    os.makedirs(honey_dir, exist_ok=True)

    created = []
    now = time.strftime("%Y-%m-%d %H:%M:%S")

    existing = set(list_real_files(honey_dir))
    i = 0
    while len(created) < count:
        i += 1
        token = uuid.uuid4().hex[:8]
        filename = f"honey_decoy_{i}_{token}.txt"
        if filename in existing:
            continue

        path = os.path.join(honey_dir, filename)
        with open(path, "w", encoding="utf-8") as f:
            f.write(
                "HONEY TRAP FILE (DECOY)\n"
                f"Created: {now}\n"
                f"Token: {token}\n"
                "This is NOT a real file.\n"
            )
        created.append(filename)

    # ✅ baseline refresh (hash-based)
    _save_baseline(honey_dir)
    return created


def create_honey_copy(src_path: str, honey_dir: str):
    """
    will make garbage/decoy copy of Uploaded file in honey_dir.
    - same extension
    - same size random bytes
    return: created honey filename
    """
    os.makedirs(honey_dir, exist_ok=True)

    if not os.path.exists(src_path):
        raise FileNotFoundError(f"Source file not found: {src_path}")

    base = os.path.basename(src_path)
    name, ext = os.path.splitext(base)
    token = uuid.uuid4().hex[:10]

    honey_name = f"{name}_HONEY_{token}{ext}"
    honey_path = os.path.join(honey_dir, honey_name)

    size = os.path.getsize(src_path)
    garbage = os.urandom(size if size > 0 else 256)

    with open(honey_path, "wb") as f:
        f.write(garbage)

    # ✅ baseline refresh (hash-based)
    _save_baseline(honey_dir)
    return honey_name


def check_honey_access(honey_dir: str, log_callback=None):
  
    os.makedirs(honey_dir, exist_ok=True)

    baseline_path = os.path.join(honey_dir, ".honey_baseline")

    # first run -> baseline create only
    if not os.path.exists(baseline_path):
        _save_baseline(honey_dir)
        return []

    baseline = _read_baseline(baseline_path)

    current_files = list_real_files(honey_dir)
    current_set = set(current_files)
    baseline_set = set(baseline.keys())

    suspicious = []

    # 1) Deleted honey files
    for fn in sorted(baseline_set - current_set):
        suspicious.append(fn)
        if log_callback:
            log_callback(f"⚠️ Honey file DELETED: {fn}")

    # 2) New unexpected files (not in baseline)
    for fn in sorted(current_set - baseline_set):
        suspicious.append(fn)
        if log_callback:
            log_callback(f"⚠️ Honey NEW/UNKNOWN file found: {fn}")

    # 3) Hash changed => content changed
    for fn in sorted(current_set & baseline_set):
        p = os.path.join(honey_dir, fn)
        try:
            current_hash = _sha256_file(p)
        except Exception:
            continue

        old_hash = baseline.get(fn, {}).get("sha256", "")
        if old_hash and current_hash != old_hash:
            suspicious.append(fn)
            if log_callback:
                log_callback(f"⚠️ Honey file HASH CHANGED (MODIFIED): {fn}")


    return suspicious


def _save_baseline(honey_dir: str):
    """
    Save baseline as:
      filename|sha256
    """
    baseline_path = os.path.join(honey_dir, ".honey_baseline")
    data = {}

    for fn in list_real_files(honey_dir):
        p = os.path.join(honey_dir, fn)
        try:
            data[fn] = _sha256_file(p)
        except Exception:
            pass

    with open(baseline_path, "w", encoding="utf-8") as f:
        for k, sha in data.items():
            f.write(f"{k}|{sha}\n")


def _read_baseline(path: str):
    """
    Supports old + new formats:

    Old formats (from earlier versions):
      - filename|mtime_seconds
      - filename|mtime_ns|atime_ns|size

    New format (hash-based):
      - filename|sha256

    For old formats, we keep compatibility but they won't be used for detection anymore.
    """
    data = {}
    try:
        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line or "|" not in line:
                    continue

                parts = line.split("|")

                # New hash format: name|sha256
                if len(parts) == 2 and len(parts[1]) == 64:
                    k = parts[0]
                    data[k] = {"sha256": parts[1]}
                    continue

                # Old format: name|mtime_seconds
                if len(parts) == 2:
                    k = parts[0]
                    data[k] = {"sha256": ""}  # unknown hash
                    continue

                # Old format: name|mtime_ns|atime_ns|size
                if len(parts) >= 4:
                    k = parts[0]
                    data[k] = {"sha256": ""}  # unknown hash
                    continue
    except Exception:
        pass

    return data
