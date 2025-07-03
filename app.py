import os
import sys
import json
import logging
from datetime import datetime, timedelta
from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session, jsonify, url_for, send_from_directory
from flask_session import Session
from werkzeug.security import check_password_hash, generate_password_hash
from flask_login import LoginManager, login_user, login_required, UserMixin, current_user, logout_user
from werkzeug.utils import secure_filename
from urllib.parse import unquote
from git import Repo, GitCommandError

# --- LOGGING SETUP ---
logging.basicConfig(
    level=logging.DEBUG,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
def log(msg):
    print(f"[LOG] {msg}", flush=True)
    logging.debug(msg)

# Disable stdout buffering for Render
sys.stdout.reconfigure(line_buffering=True)

# Database setup
db = SQL("sqlite:///logins.db")

# Constants
GLOBAL_CHAT_KEY = "1000"
UPLOAD_BASE = os.path.join(os.getcwd(), "IMAGES")
DOWNLOADS_FOLDER = os.path.join(os.getcwd(), "DOWNLOADS")
ALLOWED_EXTENSIONS = {"gb"}
HARDCODED_PASSWORD_HASH = generate_password_hash("PocketMonstersShine123!")  # Use a secure password!

# Downloadable files metadata
DOWNLOADS_META = [
    {"filename": "shine v0.0.1.gb", "display": "Shine v0.0.1", "description": "First public alpha build."},
    {"filename": "shine v0.0.2.gb", "display": "Shine v0.0.2", "description": "Minor bugfixes and improvements."},
    {"filename": "shine v0.0.5.gb", "display": "Shine v0.0.5", "description": "Added new features and optimized performance."},
    {"filename": "shine v0.0.6.gb", "display": "Shine v0.0.6", "description": "Improved controls and fixed save bug."},
    {"filename": "shine v0.0.7.gb", "display": "Shine v0.0.7", "description": "New map area and music update."},
    {"filename": "shine v0.0.8.gb", "display": "Shine v0.0.8", "description": "Gameplay balancing and minor graphical overhaul."},
    {"filename": "shine v0.0.9.gb", "display": "Shine v0.0.9", "description": "Beta milestone: most major features present."},
    {"filename": "shine v0.1.0.gb", "display": "Shine v0.1.0", "description": "First full release candidate."},
    {"filename": "shine v0.1.1.gb", "display": "Shine v0.1.1", "description": "Latest patch: fixes, polish, and performance!"},
]

# Flask setup
app = Flask(__name__)
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
app.config['UPLOADS_FOLDER'] = DOWNLOADS_FOLDER
Session(app)

# Login manager
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"

class User(UserMixin):
    pass

@login_manager.user_loader
def load_user(user_id):
    user = db.execute("SELECT * FROM users WHERE id = ?", user_id)
    if user:
        user_obj = User()
        user_obj.id = user[0]['id']
        user_obj.username = user[0]['username']
        user_obj.emoji = user[0].get('emoji', '🙂')
        return user_obj
    return None

@app.after_request
def after_request(response):
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        password = request.form.get("password")
        if not password or not check_password_hash(HARDCODED_PASSWORD_HASH, password):
            return render_template("login.html", error="Incorrect password.")
        session["password_ok"] = True
        return redirect(url_for("choose_username"))
    return render_template("login.html")

@app.route("/logout")
def logout():
    logout_user()
    session.clear()
    return redirect("/login")

@app.route("/choose_username", methods=["GET", "POST"])
def choose_username():
    if not session.get("password_ok"):
        return redirect(url_for("login"))
    if request.method == "POST":
        username = request.form.get("username")
        if username not in ["h", "olivia"]:
            return render_template("choose_username.html", error="Please choose a valid username.")
        rows = db.execute("SELECT * FROM users WHERE username = ?", username)
        if not rows:
            db.execute("INSERT INTO users (username, hash, emoji) VALUES (?, ?, ?)", username, generate_password_hash("placeholder"), "🙂")
            rows = db.execute("SELECT * FROM users WHERE username = ?", username)
        user = User()
        user.id = rows[0]["id"]
        user.username = rows[0]["username"]
        user.emoji = rows[0].get("emoji", "🙂")
        login_user(user)
        session.pop("password_ok", None)
        return redirect(url_for("index"))
    return render_template("choose_username.html")

@app.route("/", methods=["GET"])
@login_required
def index():
    chat_group = db.execute("SELECT * FROM group_chats WHERE id = ?", GLOBAL_CHAT_KEY)
    if not chat_group:
        db.execute("INSERT INTO group_chats (id) VALUES (?)", GLOBAL_CHAT_KEY)
    uploaded = load_uploaded_meta()
    all_downloads = DOWNLOADS_META + uploaded
    return render_template("chat_room.html", key=GLOBAL_CHAT_KEY, downloads=all_downloads)

@app.route("/messages/<key>")
@login_required
def get_messages(key):
    try:
        if not os.path.exists("messages.json"):
            with open("messages.json", "w") as file:
                json.dump({}, file)
        with open("messages.json", "r") as file:
            data = json.load(file)
        return jsonify({"messages": data.get(key, [])})
    except Exception as e:
        log(f"Error reading messages.json: {e}")
        return jsonify({"error": str(e)}), 500

@app.route("/chat_room/<key>", methods=['POST'])
@login_required
def post_message(key):
    message = request.json.get('message', '')
    image_url = request.json.get('image_url', None)
    if not message and not image_url:
        return jsonify({"error": "Message cannot be empty."}), 400
    try:
        if not os.path.exists("messages.json"):
            with open("messages.json", "w") as file:
                json.dump({}, file)
        with open("messages.json", "r") as file:
            data = json.load(file)
        if key not in data:
            data[key] = []
        msg_data = {
            "username": current_user.username,
            "emoji": current_user.emoji,
            "timestamp": datetime.now().isoformat()
        }
        if message:
            msg_data["message"] = message
        if image_url:
            msg_data["image_url"] = image_url
        data[key].append(msg_data)
        with open("messages.json", "w") as file:
            json.dump(data, file)
        log(f"Posted message: {msg_data}")
        return jsonify({"success": True}), 200
    except Exception as e:
        log(f"Error posting message: {e}")
        return jsonify({"error": str(e)}), 500

UPLOADED_META_FILE = os.path.join(DOWNLOADS_FOLDER, "downloads_uploaded.json")

def load_uploaded_meta():
    if not os.path.exists(UPLOADED_META_FILE):
        log("No uploaded meta file found.")
        return []
    try:
        with open(UPLOADED_META_FILE, "r") as f:
            data = json.load(f)
            log(f"Loaded uploaded meta: {data}")
            return data
    except Exception as e:
        log(f"Error loading uploaded meta: {e}")
        return []

def save_uploaded_meta(meta_list):
    try:
        with open(UPLOADED_META_FILE, "w") as f:
            json.dump(meta_list, f, indent=2)
        log(f"Saved uploaded meta: {meta_list}")
    except Exception as e:
        log(f"Error saving uploaded meta: {e}")

def git_push_downloads(commit_message="Update downloads"):
    repo_dir = os.getcwd()
    log(f"git_push_downloads called from dir: {repo_dir}")
    log(f"Files in cwd: {os.listdir(repo_dir)}")
    log(f".git exists? {os.path.isdir(os.path.join(repo_dir, '.git'))}")
    log(f"DOWNLOADS exists? {os.path.isdir(DOWNLOADS_FOLDER)} - contents: {os.listdir(DOWNLOADS_FOLDER) if os.path.isdir(DOWNLOADS_FOLDER) else 'N/A'}")
    github_token = os.environ.get("GITHUB_TOKEN")
    github_user = os.environ.get("GITHUB_USER", "Arh48")
    repo_name = "con2"
    REMOTE_NAME = "autopush"

    if not github_token:
        log("GITHUB_TOKEN environment variable not set. Skipping git push.")
        return False, "GITHUB_TOKEN not set"
    remote_url = f"https://{github_token}@github.com/{github_user}/{repo_name}.git"
    try:
        repo = Repo(repo_dir)
        remotes = [remote.name for remote in repo.remotes]
        log(f"Existing remotes: {remotes}")
        if REMOTE_NAME in remotes:
            repo.delete_remote(repo.remote(REMOTE_NAME))
            log(f"Deleted existing remote: {REMOTE_NAME}")
        repo.create_remote(REMOTE_NAME, remote_url)
        log(f"Added remote: {REMOTE_NAME} -> {remote_url}")
        repo.git.add('DOWNLOADS')
        log(f"Staged DOWNLOADS for commit. Status:\n{repo.git.status()}")
        try:
            commit = repo.index.commit(commit_message)
            log(f"Commit made: {commit.hexsha} - {commit_message}")
        except GitCommandError as e:
            log(f"Git commit error: {e}")
            if "nothing to commit" in str(e):
                return True, "Nothing new to commit."
            return False, f"Git commit error: {e}"
        log(f"Last 3 commits:\n{repo.git.log('--oneline', max_count=3)}")
        push_result = repo.remote(REMOTE_NAME).push('main')
        log(f"Push result: {push_result}")
        return True, "Pushed to git successfully."
    except Exception as e:
        log(f"Git error: {e}")
        return False, f"Git error: {e}"
@app.route("/admin")
@login_required
def admin():
    users = db.execute("SELECT * FROM users")
    group_chats = db.execute("SELECT * FROM group_chats")
    # Load both static and uploaded downloads
    downloads = []
    # Assume you have DOWNLOADS_META as a global (static downloads)
    if 'DOWNLOADS_META' in globals():
        downloads += DOWNLOADS_META
    downloads += load_uploaded_meta()
    # Images: Load /IMAGES content as {folder: [images]}
    image_folders = {}
    images_base = os.path.join(os.getcwd(), "IMAGES")
    if os.path.exists(images_base):
        for folder in os.listdir(images_base):
            folder_path = os.path.join(images_base, folder)
            if os.path.isdir(folder_path):
                image_folders[folder] = [img for img in os.listdir(folder_path) if not img.startswith('.')]
    return render_template(
        "admin.html",
        users=users,
        group_chats=group_chats,
        downloads=downloads,
        image_folders=image_folders
    )

@app.route("/upload", methods=["GET", "POST"])
@login_required
def upload():
    log(f"Entered /upload route with method {request.method}")
    if request.method == "POST":
        if 'file' not in request.files:
            log("No file part in request.files")
            flash('No file part in the request.', 'danger')
            return redirect(request.url)
        file = request.files['file']
        description = request.form.get('description', '').strip()
        log(f"POST upload: filename={file.filename}, description={description}")
        if file.filename == '':
            log("No selected file.")
            flash('No selected file.', 'danger')
            return redirect(request.url)
        if not allowed_file(file.filename):
            log("File extension not allowed.")
            flash('Only .gb files are allowed.', 'danger')
            return redirect(request.url)
        if not description:
            log("Description not provided.")
            flash('Description required.', 'danger')
            return redirect(request.url)
        filename = secure_filename(file.filename)
        save_path = os.path.join(app.config['UPLOADS_FOLDER'], filename)
        log(f"Saving file to: {save_path}")
        file.save(save_path)
        meta_list = load_uploaded_meta()
        meta_list = [m for m in meta_list if m['filename'] != filename]
        meta_list.append({
            "filename": filename,
            "display": filename,
            "description": description
        })
        save_uploaded_meta(meta_list)
        # --- GIT PUSH STEP ---
        success, msg = git_push_downloads(f"User {current_user.username} uploaded {filename}")
        log(f"Git push result: success={success}, msg={msg}")
        if not success:
            flash('File uploaded, but git push failed: ' + msg, 'danger')
        else:
            flash('File uploaded and pushed to git! ' + msg, 'success')
        return redirect(request.url)
    return render_template("upload.html")

@app.route("/download/<filename>")
@login_required
def download_file(filename):
    uploaded = load_uploaded_meta()
    all_filenames = {meta["filename"] for meta in (DOWNLOADS_META + uploaded)}
    if filename not in all_filenames:
        log(f"Download requested for missing file: {filename}")
        return "File not found.", 404
    log(f"Serving download: {filename}")
    return send_from_directory(DOWNLOADS_FOLDER, filename, as_attachment=True)

@app.route("/delete_download/<filename>", methods=["POST"])
@login_required
def delete_download(filename):
    # Remove file from DOWNLOADS folder
    filepath = os.path.join(DOWNLOADS_FOLDER, filename)
    if os.path.exists(filepath):
        os.remove(filepath)
    # Remove from uploaded meta
    meta_list = load_uploaded_meta()
    new_meta_list = [m for m in meta_list if m['filename'] != filename]
    if len(new_meta_list) != len(meta_list):
        save_uploaded_meta(new_meta_list)
    flash(f"Deleted {filename} from downloads.", "success")
    return redirect(url_for('admin'))

@app.route("/delete_downloads", methods=["POST"])
@login_required
def delete_downloads():
    data = request.get_json()
    filenames = data.get("filenames", [])
    meta_list = load_uploaded_meta()
    new_meta_list = meta_list[:]
    for filename in filenames:
        filepath = os.path.join(DOWNLOADS_FOLDER, filename)
        if os.path.exists(filepath):
            os.remove(filepath)
        new_meta_list = [m for m in new_meta_list if m['filename'] != filename]
    save_uploaded_meta(new_meta_list)
    return jsonify({"success": True})

if __name__ == "__main__":
    log("App starting up...")
    if not os.path.exists(UPLOAD_BASE):
        os.makedirs(UPLOAD_BASE)
        log(f"Created UPLOAD_BASE: {UPLOAD_BASE}")
    if not os.path.exists(DOWNLOADS_FOLDER):
        os.makedirs(DOWNLOADS_FOLDER)
        log(f"Created DOWNLOADS_FOLDER: {DOWNLOADS_FOLDER}")
    chat_group = db.execute("SELECT * FROM group_chats WHERE id = ?", GLOBAL_CHAT_KEY)
    if not chat_group:
        db.execute("INSERT INTO group_chats (id) VALUES (?)", GLOBAL_CHAT_KEY)
        log(f"Created initial group chat: {GLOBAL_CHAT_KEY}")
    app.run(debug=True)
