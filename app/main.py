import os
import shutil
from flask import Flask, render_template, request, send_file
from werkzeug.utils import secure_filename
from core.aes_encrypt import encrypt_file
from core.aes_decrypt import decrypt_file
from core.split_key import split_key
from core.combine_key import combine_shares
from core.timelock import is_time_allowed
from core.keyshare_crypto import encrypt_share_text, decrypt_share_text_if_needed
from core.honey_files import create_honey_files, create_honey_copy, check_honey_access, list_real_files

from core.db_functions import (
    add_file_record, add_key_record, add_log,
    get_all_files, get_recent_logs, get_statistics
)

app = Flask(__name__)

# Max upload size (bytes). Change if you want (e.g., 25 * 1024 * 1024 for 25MB)
MAX_UPLOAD_BYTES = 10 * 1024 * 1024  # 10 MB
app.config["MAX_CONTENT_LENGTH"] = MAX_UPLOAD_BYTES

# Allowed extensions for file to upload
ALLOWED_EXTENSIONS = {
    "txt", "pdf", "doc", "docx",
    "xls", "xlsx", "ppt", "pptx",
    "png", "jpg", "jpeg"
}


def _allowed_file(filename: str) -> bool:
    if not filename or "." not in filename:
        return False
    ext = filename.rsplit(".", 1)[1].lower().strip()
    return ext in ALLOWED_EXTENSIONS


def _unique_filename(base_dir: str, filename: str) -> str:
    """Avoid overwriting existing files by adding _1, _2, ..."""
    name, ext = os.path.splitext(filename)
    candidate = filename
    i = 1
    while os.path.exists(os.path.join(base_dir, candidate)):
        candidate = f"{name}_{i}{ext}"
        i += 1
    return candidate


@app.errorhandler(413)
def _file_too_large(_err):
    mb = MAX_UPLOAD_BYTES / (1024 * 1024)
    return (
        f"❌ File too large! Max allowed size is {mb:.0f}MB. "
        "<br><a href='/'>Go Back</a>",
        413,
    )

#  Project root
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
UPLOAD_FOLDER = os.path.join(PROJECT_ROOT, "uploads")
ENCRYPTED_FOLDER = os.path.join(PROJECT_ROOT, "encrypted_files")
DECRYPTED_FOLDER = os.path.join(PROJECT_ROOT, "decrypted_files")
KEY_SHARE_FOLDER = os.path.join(PROJECT_ROOT, "key_shares")
SERVER_FILES_FOLDER = os.path.join(PROJECT_ROOT, "server_files")
SERVER_KEYS_FOLDER = os.path.join(PROJECT_ROOT, "server_keys")
LOGS_FOLDER = os.path.join(PROJECT_ROOT, "logs")
HONEY_FILES_FOLDER = os.path.join(PROJECT_ROOT, "honey_files")

for folder in [
    UPLOAD_FOLDER, ENCRYPTED_FOLDER, DECRYPTED_FOLDER, KEY_SHARE_FOLDER,
    SERVER_FILES_FOLDER, SERVER_KEYS_FOLDER, LOGS_FOLDER, HONEY_FILES_FOLDER
]:
    os.makedirs(folder, exist_ok=True)


def _ensure_dir(path: str):
    os.makedirs(path, exist_ok=True)


def _safe_join(base_dir: str, user_path: str) -> str:
    """
    Prevent path traversal. Allows subfolders inside base_dir only.
    user_path may look like: 'file_17/key_part_1.txt'
    """
    base_abs = os.path.abspath(base_dir)
    target_abs = os.path.abspath(os.path.join(base_dir, user_path))
    if not (target_abs == base_abs or target_abs.startswith(base_abs + os.sep)):
        raise ValueError("Invalid path")
    return target_abs


def _file_key_dir(file_id: int) -> str:
    return os.path.join(KEY_SHARE_FOLDER, f"file_{file_id}")


def _client_ip() -> str:
    """
    Basic client ip. Works locally too.
    If behind proxy, X-Forwarded-For may exist.
    """
    try:
        xff = request.headers.get("X-Forwarded-For", "")
        if xff:
            return xff.split(",")[0].strip()
        return request.remote_addr or "unknown"
    except Exception:
        return "unknown"


existing = list_real_files(HONEY_FILES_FOLDER)
if len(existing) < 5:
    created = create_honey_files(HONEY_FILES_FOLDER, count=(5 - len(existing)))
    add_log(
        f"Created honey trap files: {', '.join(created)}",
        action="HONEY_INIT",
        filename=", ".join(created),
        result="OK",
        user_ip="system"
    )

@app.route("/")
def index():
    return render_template("upload.html")


@app.route("/dashboard")
def dashboard():
    stats = get_statistics()
    files = get_all_files()
    logs = get_recent_logs(15)

    for f in files:
        enc_name = f.get("encrypted_name") or ""
        f["file_exists"] = os.path.exists(os.path.join(ENCRYPTED_FOLDER, enc_name))

        f["is_locked"] = False
        if f.get("time_lock"):
            try:
                lock_str = (
                    f["time_lock"]
                    if isinstance(f["time_lock"], str)
                    else f["time_lock"].strftime("%Y-%m-%dT%H:%M")
                )
                f["is_locked"] = not is_time_allowed(lock_str)
            except Exception:
                pass

        count = 0
        try:
            file_id = f.get("id")
            if file_id is not None:
                kd = _file_key_dir(int(file_id))
                if os.path.isdir(kd):
                    for i in (1, 2, 3):
                        if os.path.isfile(os.path.join(kd, f"key_part_{i}.txt")):
                            count += 1
                else:
                    # legacy fallback (best-effort)
                    for i in (1, 2, 3):
                        if os.path.isfile(os.path.join(KEY_SHARE_FOLDER, f"key_part_{i}.txt")):
                            count += 1
        except Exception:
            count = 0

        f["keys_available"] = f"{count}/3"

    return render_template("dashboard.html", stats=stats, files=files, logs=logs)


@app.route("/check_intrusion")
def check_intrusion():
    ip = _client_ip()

    # wrap callback so honey monitor logs are also structured
    def _honey_log(msg: str):
       
        fn = ""
        try:
            if ":" in msg:
                fn = msg.split(":", 1)[1].strip()
        except Exception:
            fn = ""
        add_log(msg, action="HONEY_MONITOR", filename=fn, result="OK", user_ip=ip)

    suspicious = check_honey_access(HONEY_FILES_FOLDER, log_callback=_honey_log)

    if suspicious:
        add_log(
            "⚠️ INTRUSION ALERT! Honey files touched: " + ", ".join(suspicious),
            action="INTRUSION",
            filename=", ".join(suspicious),
            result="ALERT",
            user_ip=ip
        )
        return f"""
        <div style="padding:40px;font-family:Arial;background:#ff2b2b;color:white;border-radius:12px;margin:20px;">
            <h1>⚠️ INTRUSION DETECTED</h1>
            <h3>Honey files touched:</h3>
            <ul>{"".join([f"<li>{x}</li>" for x in suspicious])}</ul>
            <p><b>Action:</b> Event logged in dashboard.</p>
            <a href="/dashboard" style="color:white;text-decoration:underline;">Go to Dashboard</a>
        </div>
        """

    return """
    <div style="padding:40px;font-family:Arial;background:#20c997;color:white;border-radius:12px;margin:20px;">
        <h1> No Intrusion</h1>
        <p>Honey files safe no changing detected in them.</p>
        <a href="/dashboard" style="color:white;text-decoration:underline;">Go to Dashboard</a>
    </div>
    """


@app.route("/encrypt_file", methods=["POST"])
def encrypt_file_route():
    ip = _client_ip()

    file = request.files.get("file")
    if not file or not file.filename:
        return "❌ Error: No file selected"

    #  1) filename sanitize (path traversal na ho: ../../)
    #  2) allowed extensions whitelist
    #  3) max size limit (DoS avoid)
    original_name = file.filename
    safe_name = secure_filename(original_name)
    if not safe_name:
        return "❌ Error: Invalid filename"
    if not _allowed_file(safe_name):
        allowed = ", ".join(sorted(ALLOWED_EXTENSIONS))
        return f"❌ Error: File type not allowed. Allowed: {allowed}"

    # Flask already enforces MAX_CONTENT_LENGTH, but we also double-check.
    if request.content_length is not None and request.content_length > MAX_UPLOAD_BYTES:
        mb = MAX_UPLOAD_BYTES / (1024 * 1024)
        return f"❌ File too large! Max allowed size is {mb:.0f}MB. <br><a href='/'>Go Back</a>"

    time_lock = request.form.get("time_lock", "")
    upload_to_server = request.form.get("upload_server")
    upload_keys_to_server = request.form.get("upload_keys")

    if not time_lock or time_lock.strip() == "":
        time_lock = None

    #  Save upload into ROOT uploads/ (safe name + no overwrite)
    final_name = _unique_filename(UPLOAD_FOLDER, safe_name)
    filepath = _safe_join(UPLOAD_FOLDER, final_name)
    file.save(filepath)

    #  Honey garbage/decoy copy for every upload
    try:
        honey_name = create_honey_copy(filepath, HONEY_FILES_FOLDER)
        add_log(
            f"Honey copy created: {honey_name}",
            action="HONEY_COPY",
            filename=honey_name,
            result="OK",
            user_ip=ip
        )
    except Exception as e:
        add_log(
            f"Honey copy creation failed for {original_name}: {str(e)}",
            action="HONEY_COPY",
            filename=original_name,
            result="FAILED",
            user_ip=ip
        )

    try:
        #  IMPORTANT: wrap_key (16 bytes)
        encrypted_path, wrap_key = encrypt_file(final_name)

        #  split works
        shares = split_key(wrap_key)
    except Exception as e:
        add_log(
            f"Encryption error: {str(e)}",
            action="ENCRYPT",
            filename=original_name,
            result="FAILED",
            user_ip=ip
        )
        return f"❌ Encryption error: {str(e)}"

    #  Create DB record early so we can generate per-file key folder.
    file_id = add_file_record(
        original_name=original_name,
        encrypted_name=os.path.basename(encrypted_path),
        time_lock=time_lock,
        uploaded_to_server=1 if upload_to_server else 0
    )

    key_dir = _file_key_dir(file_id)
    _ensure_dir(key_dir)

    for idx, s in enumerate(shares, start=1):
        key_filename = f"key_part_{idx}.txt"
        key_path = os.path.join(key_dir, key_filename)

        #  Encrypt share BEFORE saving
        enc_share = encrypt_share_text(s)
        with open(key_path, "w", encoding="utf-8") as f:
            f.write(enc_share)

    #  time-lock file also per-file folder (not critical secret, keep plaintext)
    if time_lock:
        unlock_path = os.path.join(key_dir, "unlock_time.txt")
        with open(unlock_path, "w", encoding="utf-8") as f:
            f.write(time_lock)

    #  optional manifest
    try:
        with open(os.path.join(key_dir, "manifest.txt"), "w", encoding="utf-8") as f:
            f.write(f"file_id={file_id}\n")
            f.write(f"original_name={original_name}\n")
            f.write(f"saved_as={final_name}\n")
            f.write(f"encrypted_name={os.path.basename(encrypted_path)}\n")
            f.write(f"time_lock={time_lock or ''}\n")
            f.write("shares=ENCRYPTED_AT_REST\n")
    except Exception:
        pass

    if upload_to_server:
        server_enc_path = os.path.join(SERVER_FILES_FOLDER, os.path.basename(encrypted_path))
        shutil.copy(encrypted_path, server_enc_path)
        add_log(
            f"Uploaded encrypted file to server: {original_name}",
            action="SERVER_UPLOAD",
            filename=original_name,
            result="OK",
            user_ip=ip
        )

    if upload_keys_to_server:
        # Copy the entire per-file folder to server_keys/file_<id>/
        server_key_dir = os.path.join(SERVER_KEYS_FOLDER, f"file_{file_id}")
        _ensure_dir(server_key_dir)

        for fname in os.listdir(key_dir):
            src = os.path.join(key_dir, fname)
            dst = os.path.join(server_key_dir, fname)
            if os.path.isfile(src):
                shutil.copy(src, dst)

        add_log(
            f"Uploaded keys to server for: {original_name}",
            action="SERVER_KEYS",
            filename=original_name,
            result="OK",
            user_ip=ip
        )

    # DB record stores original shares – keep as-is for compatibility
    add_key_record(file_id, shares[0], shares[1], shares[2])

    add_log(
        f"Encrypted file: {original_name}",
        action="ENCRYPT",
        filename=original_name,
        result="OK",
        user_ip=ip
    )

    return render_template(
        "encrypt_result.html",
        filename=original_name,
        enc_filename=os.path.basename(encrypted_path),
        shares=shares,
        upload_to_server=bool(upload_to_server),
        keys_to_server=bool(upload_keys_to_server)
    )


@app.route("/decrypt_page")
def decrypt_page():
    enc_files = []
    if os.path.exists(ENCRYPTED_FOLDER):
        enc_files = [f for f in os.listdir(ENCRYPTED_FOLDER) if f.endswith(".enc")]

    #  Build key files list:
    # 1) New scheme: key_shares/file_<id>/key_part_*.txt  (store relative paths)
    # 2) Legacy scheme: key_shares/key_part_*.txt (plaintext or encrypted supported)
    key_files = []

    if os.path.exists(KEY_SHARE_FOLDER):
        # New scheme folders
        for entry in sorted(os.listdir(KEY_SHARE_FOLDER)):
            folder_path = os.path.join(KEY_SHARE_FOLDER, entry)
            if os.path.isdir(folder_path) and entry.startswith("file_"):
                for f in sorted(os.listdir(folder_path)):
                    if f.startswith("key_part_") and f.endswith(".txt"):
                        rel = f"{entry}/{f}"  # shown in dropdown
                        key_files.append(rel)

        # Legacy root files (backward compatible)
        for f in sorted(os.listdir(KEY_SHARE_FOLDER)):
            full = os.path.join(KEY_SHARE_FOLDER, f)
            if os.path.isfile(full) and f.startswith("key_part_") and f.endswith(".txt"):
                key_files.append(f)

    return render_template("decrypt.html", enc_files=enc_files, key_files=key_files)


@app.route("/decrypt_file", methods=["POST"])
def decrypt_file_route():
    ip = _client_ip()

    enc_file = request.form.get("enc_file")
    share1_file = request.form.get("share1_file")
    share2_file = request.form.get("share2_file")

    if not enc_file or not share1_file or not share2_file:
        return "❌ Error: Missing selection(s)"

    try:
        share1_path = _safe_join(KEY_SHARE_FOLDER, share1_file)
        share2_path = _safe_join(KEY_SHARE_FOLDER, share2_file)
    except Exception:
        return "❌ Error: Invalid key file path"

    with open(share1_path, "r", encoding="utf-8") as f:
        raw1 = f.read().strip()
    with open(share2_path, "r", encoding="utf-8") as f:
        raw2 = f.read().strip()

    #  Decrypt shares if they are encrypted, else legacy plaintext pass-through
    try:
        key1 = decrypt_share_text_if_needed(raw1)
        key2 = decrypt_share_text_if_needed(raw2)
    except Exception as e:
        add_log(
            f"Share decrypt failed for: {enc_file}",
            action="KEY_SHARE",
            filename=enc_file,
            result="FAILED",
            user_ip=ip
        )
        return f"❌ Key-share decrypt failed: {str(e)}<br><a href='/decrypt_page'>Go Back</a>"

    #  combined_key 16 bytes
    combined_key = combine_shares([key1, key2])

    #  Time-lock check:
    unlock_candidates = []
    share1_dir = os.path.dirname(share1_path)
    share2_dir = os.path.dirname(share2_path)

    if share1_dir == share2_dir:
        unlock_candidates.append(os.path.join(share1_dir, "unlock_time.txt"))
    else:
        unlock_candidates.append(os.path.join(share1_dir, "unlock_time.txt"))
        unlock_candidates.append(os.path.join(share2_dir, "unlock_time.txt"))

    # Legacy fallback
    unlock_candidates.append(os.path.join(KEY_SHARE_FOLDER, "unlock_time.txt"))

    for unlock_path in unlock_candidates:
        if os.path.exists(unlock_path):
            with open(unlock_path, "r", encoding="utf-8") as f:
                unlock_str = f.read().strip()
            if unlock_str and not is_time_allowed(unlock_str):
                add_log(
                    f"Time-lock prevented decryption: {enc_file}",
                    action="TIMELOCK",
                    filename=enc_file,
                    result="DENIED",
                    user_ip=ip
                )
                return f"❌ Time-lock active! Decrypt after: {unlock_str}<br><a href='/decrypt_page'>Go Back</a>"
            break

    try:
        dec_path = decrypt_file(enc_file, combined_key)
    except Exception as e:
        add_log(
            f"Decryption failed: {enc_file}",
            action="DECRYPT",
            filename=enc_file,
            result="FAILED",
            user_ip=ip
        )
        return f"❌ Decryption failed: {str(e)}<br><a href='/decrypt_page'>Go Back</a>"

    add_log(
        f"Decrypted file: {enc_file}",
        action="DECRYPT",
        filename=enc_file,
        result="OK",
        user_ip=ip
    )
    return send_file(dec_path, as_attachment=True)


if __name__ == "__main__":
    app.run(debug=True)
