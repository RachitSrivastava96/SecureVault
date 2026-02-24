import os
import uuid
from flask import Flask, render_template, request, redirect

app = Flask(__name__)

UPLOAD_FOLDER = "uploads"
ALLOWED_EXTENSIONS = {"png", "jpg", "jpeg", "pdf"}
MAX_FILE_SIZE = 5 * 1024 * 1024  # 5MB

app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER
app.config["MAX_CONTENT_LENGTH"] = MAX_FILE_SIZE

# Create uploads folder if not exists
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

def allowed_file(filename):
    return "." in filename and \
           filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route("/", methods=["GET", "POST"])
def home():
    if request.method == "POST":
        if "file" not in request.files:
            return "No file part"

        file = request.files["file"]

        if file.filename == "":
            return "No selected file"

        if file and allowed_file(file.filename):
            # Secure rename using UUID
            ext = file.filename.rsplit(".", 1)[1].lower()
            new_filename = str(uuid.uuid4()) + "." + ext

            file.save(os.path.join(app.config["UPLOAD_FOLDER"], new_filename))
            return "File uploaded securely!"

        else:
            return "Invalid file type!"

    return render_template("upload.html")

if __name__ == "__main__":
    app.run(debug=True)