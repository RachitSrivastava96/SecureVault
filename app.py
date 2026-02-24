import os
import uuid
import magic
import logging
import json
from flask import Flask, render_template, request, redirect, flash, send_from_directory, abort

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

# ── Registry helpers ──
def load_registry():
    with open(REGISTRY_FILE, "r") as f:
        return json.load(f)

def save_registry(registry):
    with open(REGISTRY_FILE, "w") as f:
        json.dump(registry, f, indent=2)

# ── Validation helpers ──
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

        # ── All checks passed ──
        original_name = file.filename
        ext           = original_name.rsplit(".", 1)[1].lower()
        new_filename  = str(uuid.uuid4()) + "." + ext
        save_path     = os.path.join(app.config["UPLOAD_FOLDER"], new_filename)
        file.save(save_path)

        registry = load_registry()
        registry[new_filename] = original_name
        save_registry(registry)

        file_size = os.path.getsize(save_path)
        logging.info(
            f"IP={ip} | SUCCESS | "
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
    for uuid_name, original_name in registry.items():
        path = os.path.join(UPLOAD_FOLDER, uuid_name)
        if os.path.exists(path):
            size_kb = round(os.path.getsize(path) / 1024, 1)
            files.append({
                "uuid_name":     uuid_name,
                "original_name": original_name,
                "size_kb":       size_kb,
            })

    return render_template("files.html", files=files)


# ────────────────────────────────────────────
#  ROUTE 3: Secure download
# ────────────────────────────────────────────
@app.route("/download/<uuid_name>")
def download_file(uuid_name):
    registry = load_registry()

    if uuid_name not in registry:
        abort(404)

    original_name = registry[uuid_name]

    return send_from_directory(
        app.config["UPLOAD_FOLDER"],
        uuid_name,
        as_attachment=True,
        download_name=original_name
    )


if __name__ == "__main__":
    app.run(debug=True)