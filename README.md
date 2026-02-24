# SecureVault — Secure File Upload System

A Flask-based file upload web application with layered server-side security. Users can upload, browse, download, and delete files through a clean UI. All validation and encryption happens invisibly on the server — the user just uploads and gets their file back.

---

## How it works

Every uploaded file goes through a validation pipeline before anything is saved:

1. File size is checked — anything over 5MB is rejected
2. The filename is scanned for dangerous extensions (including double extensions like `photo.jpg.exe`)
3. The extension is checked against a whitelist — only PNG, JPG, JPEG, and PDF are accepted
4. The actual file bytes are inspected to confirm the file is really what it claims to be
5. The file is renamed to a random UUID so the original filename never touches disk
6. The file is encrypted before being written to storage
7. The upload is logged with a timestamp and the uploader's IP

When downloading, the file is decrypted in memory and served back with the original filename restored. Decrypted bytes never touch disk.

---

## Project Structure

```
project/
├── app.py                  # Main Flask application
├── .env                    # Encryption key (not committed)
├── requirements.txt        # Python dependencies
├── file_registry.json      # Maps UUIDs → original filenames + timestamps (auto-created)
├── upload_log.txt          # Upload attempt log (auto-created)
├── uploads/                # Encrypted file storage (auto-created)
└── templates/
    ├── upload.html         # Upload page
    └── files.html          # File browser
```

---

## Setup

**1. Install dependencies**
```bash
pip install -r requirements.txt
```

> On Mac/Linux replace `python-magic-bin` with `python-magic` in `requirements.txt`

**2. Generate an encryption key**

Run this once in Python:
```python
from cryptography.fernet import Fernet
print(Fernet.generate_key().decode())
```

**3. Create a `.env` file in the project root and paste the key in:**
```
ENCRYPTION_KEY=your-generated-key-here
```

**4. Run the app**
```bash
python app.py
```

Visit `http://127.0.0.1:5000`

The `uploads/` folder, `file_registry.json`, and `upload_log.txt` are all created automatically on first run.

> **Important:** if you lose your `ENCRYPTION_KEY`, any files already uploaded become unrecoverable.