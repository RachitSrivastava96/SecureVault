import os
import uuid
import magic
import logging
import json
from datetime import datetime
from cryptography.fernet import Fernet
from dotenv import load_dotenv
from flask import Flask, render_template, request, redirect, flash, Response, abort

# ── Load environment variables from .env ──
load_dotenv()

app = Flask(__name__)
app.secret_key = "supersecretkey"

UPLOAD_FOLDER    = "uploads"
LOG_FILE         = "upload_log.txt"
REGISTRY_FILE    = "file_registry.json"

ALLOWED_EXTENSIONS   = {"png", "jpg", "jpeg", "pdf"}
ALLOWED_MIME_TYPES   = {"image/jpeg", "image/png", "application/pdf"}
DANGEROUS_EXTENSIONS = {"exe", "php", "js", "sh", "bat", "cmd", "py", "rb", "pl"}
MAX_FILE_SIZE = 5 * 1024 * 1024  # 5MB

app.config["UPLOAD_FOLDER"]      = UPLOAD_FOLDER
app.config["MAX_CONTENT_LENGTH"] = MAX_FILE_SIZE

# ── Load encryption key from .env ──
# This key never appears in code — it lives only in .env
ENCRYPTION_KEY = os.getenv("ENCRYPTION_KEY")
if not ENCRYPTION_KEY:
    raise RuntimeError("ENCRYPTION_KEY not found in .env — run setup instructions first!")
fernet = Fernet(ENCRYPTION_KEY.encode())

# ── Create uploads folder if it doesn't exist ──
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

# ── Create registry file if it doesn't exist ──
if not os.path.exists(REGISTRY_FILE):
    with open(REGISTRY_FILE, "w") as f:
        json.dump({}, f)

# ── Logging setup ──
logging.basicConfig(
    filename=LOG_FILE,
    level=logging.INFO,
    format="%(asctime)s | %(levelname)s | %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S"
)

# ────────────────────────────────────────────
#  Registry helpers
# ────────────────────────────────────────────
def load_registry():
    with open(REGISTRY_FILE, "r") as f:
        return json.load(f)

def save_registry(registry):
    with open(REGISTRY_FILE, "w") as f:
        json.dump(registry, f, indent=2)

# ────────────────────────────────────────────
#  Validation helpers
# ────────────────────────────────────────────
def get_ip():
    return request.headers.get("X-Forwarded-For", request.remote_addr)

def allowed_file(filename):
    return "." in filename and \
           filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS

def has_dangerous_extension(filename):
    parts = filename.lower().split(".")
    return any(part in DANGEROUS_EXTENSIONS for part in parts)

def allowed_mime(file):
    mime = magic.from_buffer(file.read(2048), mime=True)
    file.seek(0)
    return mime in ALLOWED_MIME_TYPES

# ────────────────────────────────────────────
#  Encryption helpers
# ────────────────────────────────────────────
def encrypt_and_save(file, save_path):
    """Read file bytes, encrypt them, write to disk."""
    raw_bytes      = file.read()
    encrypted_bytes = fernet.encrypt(raw_bytes)
    with open(save_path, "wb") as f:
        f.write(encrypted_bytes)

def decrypt_to_bytes(save_path):
    """Read encrypted file from disk, decrypt to raw bytes in memory."""
    with open(save_path, "rb") as f:
        encrypted_bytes = f.read()
    return fernet.decrypt(encrypted_bytes)


# ────────────────────────────────────────────
#  ROUTE 1: Upload page
# ────────────────────────────────────────────
@app.route("/", methods=["GET", "POST"])
def home():
    if request.method == "POST":
        ip = get_ip()

        if "file" not in request.files:
            logging.warning(f"IP={ip} | No file part in request")
            flash("No file part!", "error")
            return redirect("/")

        file = request.files["file"]

        if file.filename == "":
            logging.warning(f"IP={ip} | Empty filename submitted")
            flash("No file selected!", "error")
            return redirect("/")

        if has_dangerous_extension(file.filename):
            logging.warning(f"IP={ip} | BLOCKED dangerous extension | filename='{file.filename}'")
            flash("Dangerous file detected!", "error")
            return redirect("/")

        if not allowed_file(file.filename):
            logging.warning(f"IP={ip} | BLOCKED invalid extension | filename='{file.filename}'")
            flash("Invalid file type!", "error")
            return redirect("/")

        if not allowed_mime(file):
            logging.warning(f"IP={ip} | BLOCKED MIME mismatch | filename='{file.filename}'")
            flash("File content doesn't match its extension!", "error")
            return redirect("/")

        # ── All checks passed — encrypt and save ──
        original_name = file.filename
        ext           = original_name.rsplit(".", 1)[1].lower()
        new_filename  = str(uuid.uuid4()) + "." + ext
        save_path     = os.path.join(app.config["UPLOAD_FOLDER"], new_filename)

        encrypt_and_save(file, save_path)   # ← encrypted write, not plain file.save()

        # ── Record in registry with timestamp ──
        uploaded_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        registry = load_registry()
        registry[new_filename] = {
            "original_name": original_name,
            "uploaded_at":   uploaded_at,
        }
        save_registry(registry)

        file_size = os.path.getsize(save_path)
        logging.info(
            f"IP={ip} | SUCCESS | ENCRYPTED | "
            f"original='{original_name}' | "
            f"saved_as='{new_filename}' | "
            f"size={file_size} bytes"
        )

        flash(f"'{original_name}' uploaded securely!", "success")
        return redirect("/files")

    return render_template("upload.html")


# ────────────────────────────────────────────
#  ROUTE 2: File browser
# ────────────────────────────────────────────
@app.route("/files")
def file_list():
    registry = load_registry()

    files = []
    for uuid_name, meta in registry.items():
        path = os.path.join(UPLOAD_FOLDER, uuid_name)
        if os.path.exists(path):
            size_kb = round(os.path.getsize(path) / 1024, 1)
            files.append({
                "uuid_name":     uuid_name,
                "original_name": meta["original_name"],
                "uploaded_at":   meta["uploaded_at"],
                "size_kb":       size_kb,
            })

    # Newest first
    files.sort(key=lambda x: x["uploaded_at"], reverse=True)

    return render_template("files.html", files=files)


# ────────────────────────────────────────────
#  ROUTE 3: Secure download (decrypts on the fly)
# ────────────────────────────────────────────
@app.route("/download/<uuid_name>")
def download_file(uuid_name):
    registry = load_registry()

    if uuid_name not in registry:
        abort(404)

    meta          = registry[uuid_name]
    original_name = meta["original_name"]
    save_path     = os.path.join(UPLOAD_FOLDER, uuid_name)

    # Decrypt in memory — never write decrypted bytes to disk
    decrypted_bytes = decrypt_to_bytes(save_path)

    ext_to_mime = {
        "pdf":  "application/pdf",
        "png":  "image/png",
        "jpg":  "image/jpeg",
        "jpeg": "image/jpeg",
    }
    ext      = original_name.rsplit(".", 1)[1].lower()
    mimetype = ext_to_mime.get(ext, "application/octet-stream")

    return Response(
        decrypted_bytes,
        mimetype=mimetype,
        headers={
            "Content-Disposition": f'attachment; filename="{original_name}"'
        }
    )


# ────────────────────────────────────────────
#  ROUTE 4: Delete file
# ────────────────────────────────────────────
@app.route("/delete/<uuid_name>", methods=["POST"])
def delete_file(uuid_name):
    ip       = get_ip()
    registry = load_registry()

    if uuid_name not in registry:
        abort(404)

    meta          = registry[uuid_name]
    original_name = meta["original_name"]
    file_path     = os.path.join(UPLOAD_FOLDER, uuid_name)

    # Remove from disk
    if os.path.exists(file_path):
        os.remove(file_path)

    # Remove from registry
    del registry[uuid_name]
    save_registry(registry)

    logging.info(f"IP={ip} | DELETED | original='{original_name}' | uuid='{uuid_name}'")
    flash(f"'{original_name}' deleted.", "success")
    return redirect("/files")


# ────────────────────────────────────────────
#  Run
#  For HTTPS locally: set ssl_context to a cert/key pair
#  For HTTP locally: set ssl_context to None or remove it
# ────────────────────────────────────────────
if __name__ == "__main__":
    app.run(
        debug=True,
        use_reloader=False,
        # ssl_context=("cert.pem", "key.pem")
    )