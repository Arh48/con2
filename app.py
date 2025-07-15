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
import shutil
import requests
import threading
import uuid # For unique IDs for image submissions

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
IMAGES_SUBMISSION_FOLDER = os.path.join(os.getcwd(), "IMAGE_SUBMISSIONS") # New folder for image submissions
IMAGE_SUBMISSIONS_META_FILE = os.path.join(os.getcwd(), "image_submissions.json") # New meta file

ALLOWED_EXTENSIONS = {"gb", "gbc", "gba", "png", "jpg", "jpeg", "gif"} # Updated to allow image extensions
HARDCODED_PASSWORD_HASH = generate_password_hash("PocketMonstersShine123!")  # Use a secure password!
CASSIE = generate_password_hash("ilovedoingthisart123!")

# Define the username for CASSIE's password at the module level
USERNAME_FOR_CASSIE = "cassie_user" # Renamed to uppercase for consistency with constants

# GitHub repo details for image submissions
IMAGESUB_REPO_OWNER = "Arh48"
IMAGESUB_REPO_NAME = "imagesub"
IMAGESUB_REPO_FILE = "image_submissions.json" # The meta file within the repo
# IMAGESUB_REPO_BRANCH = "main" # Removed this, will determine dynamically

# Constants for image submission repo path
IMAGE_SUBMISSIONS_CLONE_DIR = "/tmp/image_submissions_repo"


# Downloadable files metadata
DOWNLOADS_META = [
    {"filename": "shine v0.0.1.gb", "display": "Shine v0.0.1", "description": "First alpha build."},
    {"filename": "shine v0.0.2.gb", "display": "Shine v0.0.2", "description": "Added first map."},
    {"filename": "shine v0.0.5.gb", "display": "Shine v0.0.5", "description": "Added new features."},
    {"filename": "shine v0.0.6.gb", "display": "Shine v0.0.6", "description": "Added new features."},
    {"filename": "shine v0.0.7.gb", "display": "Shine v0.0.7", "description": "Added new features."},
    {"filename": "shine v0.0.8.gb", "display": "Shine v0.0.8", "description": "Added new features."},
    {"filename": "shine v0.0.9.gb", "display": "Shine v0.0.9", "description": "Introduced Passwords: Password is 5972"},
    {"filename": "shine v0.1.0.gb", "display": "Shine v0.1.0", "description": "Test of transition between scenes: Password is 8304"},
    {"filename": "shine v0.1.1.gb", "display": "Shine v0.1.1", "description": "Smooth transition! Password is 7608"},
]

# Flask setup
app = Flask(__name__)
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
app.config['UPLOADS_FOLDER'] = DOWNLOADS_FOLDER # This is for game ROMs, not general images
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

# --- COMBINED AND CORRECTED LOGIN ROUTE ---
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        password = request.form.get("password")
        if not password:
            return render_template("login.html", error="Incorrect password.")

        # Check for HARDCODED_PASSWORD_HASH
        if check_password_hash(HARDCODED_PASSWORD_HASH, password):
            session["password_ok"] = True
            return redirect(url_for("choose_username"))
        # Check for CASSIE password
        elif check_password_hash(CASSIE, password):
            session["password_ok"] = True # This might be redundant if auto-login succeeds, but kept for consistency.

            # Use the globally defined username for CASSIE's password
            username_to_login = USERNAME_FOR_CASSIE

            # Check if the user exists in the database
            rows = db.execute("SELECT * FROM users WHERE username = ?", username_to_login)
            if not rows:
                # If the user does not exist, insert them into the database.
                db.execute("INSERT INTO users (username, hash, emoji) VALUES (?, ?, ?)", username_to_login, generate_password_hash("placeholder"), "🙂")
                # Re-query to get the newly inserted user's data
                rows = db.execute("SELECT * FROM users WHERE username = ?", username_to_login)
            
            # Create a User object and log the user in using Flask-Login
            user = User()
            user.id = rows[0]["id"]
            user.username = rows[0]["username"]
            user.emoji = rows[0].get("emoji", "🙂") # Get emoji, default to 🙂 if not found
            login_user(user) # Log the user in
            
            session.pop("password_ok", None) # Remove the session flag after successful login

            # Redirect to /hello as per previous instruction for CASSIE's password
            return redirect("/") # Or url_for("hello_route_name") if you have a named route
        else:
            # If neither password matches
            return render_template("login.html", error="Incorrect password.")
    return render_template("login.html")
# --- END OF COMBINED LOGIN ROUTE ---

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
        if username not in ["h", "olivia", USERNAME_FOR_CASSIE]: # Added USERNAME_FOR_CASSIE to valid usernames
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

        # --------- FIX: Always checkout main branch first ----------
        # If 'main' does not exist, fallback to 'master'
        try:
            repo.git.checkout('main')
            log("Checked out 'main' branch")
        except GitCommandError:
            try:
                repo.git.checkout('master')
                log("Checked out 'master' branch (fallback)")
            except GitCommandError:
                log("ERROR: Neither 'main' nor 'master' branch exists!")
                return False, "No main/master branch to push to!"
        # ----------------------------------------------------------

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
        # --------- FIX: push to main/master branch ----------
        try:
            repo.remote(REMOTE_NAME).push('main')
            log("Pushed to remote 'main' branch")
        except GitCommandError as e:
            log(f"Push to 'main' failed: {e}, trying 'master'")
            try:
                repo.remote(REMOTE_NAME).push('master')
                log("Pushed to remote 'master' branch")
            except Exception as e:
                log(f"Push to 'master' also failed: {e}")
                return False, f"Push failed: {e}"
        # ---------------------------------------------------
        return True, "Pushed to git successfully."
    except Exception as e:
        log(f"Git error: {e}")
        return False, f"Git error: {e}"
    
# --- Git Push for Image Submissions (now operates on the cloned repo) ---
def git_push_image_submissions(commit_message="Update image submissions"):
    log(f"git_push_image_submissions called for repo at: {IMAGE_SUBMISSIONS_CLONE_DIR}")
    
    github_token = os.environ.get("GITHUB_TOKEN")
    if not github_token:
        log("GITHUB_TOKEN environment variable not set. Skipping git push for image submissions.")
        return False, "GITHUB_TOKEN not set"

    remote_url = f"https://{github_token}@github.com/{IMAGESUB_REPO_OWNER}/{IMAGESUB_REPO_NAME}.git"
    REMOTE_NAME = "imagesub_autopush" # Unique remote name for this repo

    try:
        # Ensure the repo exists and is up-to-date before pushing
        if not os.path.isdir(IMAGE_SUBMISSIONS_CLONE_DIR) or not os.path.isdir(os.path.join(IMAGE_SUBMISSIONS_CLONE_DIR, '.git')):
            log(f"Image submissions repo not found or invalid at {IMAGE_SUBMISSIONS_CLONE_DIR}. Attempting to re-clone.")
            sync_success, sync_msg = sync_image_submissions_local_from_github()
            if not sync_success:
                return False, f"Failed to prepare repo for push: {sync_msg}"

        repo = Repo(IMAGE_SUBMISSIONS_CLONE_DIR)

        # Determine the correct branch (main or master)
        target_branch = None
        try:
            repo.git.checkout('main')
            target_branch = 'main'
            log("Checked out 'main' branch for image submissions push")
        except GitCommandError:
            try:
                repo.git.checkout('master')
                target_branch = 'master'
                log("Checked out 'master' branch (fallback) for image submissions push")
            except GitCommandError:
                log("ERROR: Neither 'main' nor 'master' branch exists in cloned repo for push!")
                return False, "No main/master branch to push to in cloned repo!"

        remotes = [remote.name for remote in repo.remotes]
        if REMOTE_NAME in remotes:
            repo.delete_remote(repo.remote(REMOTE_NAME))
            log(f"Deleted existing remote: {REMOTE_NAME}")
        repo.create_remote(REMOTE_NAME, remote_url)
        log(f"Added remote: {REMOTE_NAME} -> {remote_url}")

        # --- PULL BEFORE PUSH (on the cloned repo) ---
        try:
            origin = repo.remote(REMOTE_NAME)
            origin.pull(target_branch)
            log(f"Pulled latest changes from '{target_branch}' for image submissions before push.")
        except GitCommandError as e:
            log(f"WARNING: Git pull failed for image submissions before push: {e}. Proceeding with push.")
        # --- END PULL BEFORE PUSH ---

        # Copy the latest local files to the cloned repo before adding/committing
        # This is crucial: Ensure the files in the *cloned repo* are what we want to push.
        # Copy image_submissions.json
        shutil.copyfile(IMAGE_SUBMISSIONS_META_FILE, os.path.join(IMAGE_SUBMISSIONS_CLONE_DIR, IMAGESUB_REPO_FILE))
        log(f"Copied app's local {IMAGESUB_REPO_FILE} to cloned repo.")

        # Copy all image submission subfolders/files from app's local to cloned repo
        if os.path.exists(IMAGES_SUBMISSION_FOLDER):
            dest_images_dir_in_cloned_repo = os.path.join(IMAGE_SUBMISSIONS_CLONE_DIR, "IMAGE_SUBMISSIONS")
            # Ensure the destination directory exists and is empty for a clean copy
            if os.path.exists(dest_images_dir_in_cloned_repo):
                shutil.rmtree(dest_images_dir_in_cloned_repo) 
            shutil.copytree(IMAGES_SUBMISSION_FOLDER, dest_images_dir_in_cloned_repo, dirs_exist_ok=True)
            log(f"Copied app's local {IMAGES_SUBMISSION_FOLDER} to cloned repo.")
        else:
            log(f"WARNING: App's local {IMAGES_SUBMISSION_FOLDER} not found, nothing to copy to cloned repo.")


        # Add the image submissions folder and the meta file within the cloned repo
        repo.git.add(IMAGESUB_REPO_FILE)
        if os.path.isdir(os.path.join(IMAGE_SUBMISSIONS_CLONE_DIR, "IMAGE_SUBMISSIONS")):
            repo.git.add("IMAGE_SUBMISSIONS")
            log(f"Staged IMAGE_SUBMISSIONS folder in cloned repo.")
        
        log(f"Image submission git status in cloned repo:\n{repo.git.status()}")

        try:
            commit = repo.index.commit(commit_message)
            log(f"Image submission commit made in cloned repo: {commit.hexsha} - {commit_message}")
        except GitCommandError as e:
            log(f"Image submission Git commit error in cloned repo: {e}")
            if "nothing to commit" in str(e):
                return True, "Nothing new to commit for image submissions."
            return False, f"Image submission Git commit error: {e}"

        repo.remote(REMOTE_NAME).push(target_branch)
        log(f"Pushed to remote '{target_branch}' branch for image submissions successfully.")
        return True, "Pushed image submissions to git successfully."

    except Exception as e:
        log(f"Image submission Git error during push: {e}")
        return False, f"Image submission Git error during push: {e}"

# --- New function to sync local image submissions from GitHub ---
def sync_image_submissions_local_from_github():
    log("Attempting to sync image submissions from GitHub...")
    github_token = os.environ.get("GITHUB_TOKEN")
    if not github_token:
        log("GITHUB_TOKEN environment variable not set. Skipping sync for image submissions.")
        return False, "GITHUB_TOKEN not set"

    remote_url = f"https://{github_token}@github.com/{IMAGESUB_REPO_OWNER}/{IMAGESUB_REPO_NAME}.git"

    try:
        # Check if the temporary repo already exists and is a valid Git repo
        if os.path.isdir(IMAGE_SUBMISSIONS_CLONE_DIR) and os.path.isdir(os.path.join(IMAGE_SUBMISSIONS_CLONE_DIR, '.git')):
            repo = Repo(IMAGE_SUBMISSIONS_CLONE_DIR)
            origin = repo.remote()
            # Try pulling 'main' first, then 'master'
            try:
                origin.pull('main')
                log(f"Pulled latest image submissions from 'main' branch.")
            except GitCommandError as e_pull_main:
                log(f"Pulling 'main' failed: {e_pull_main}. Trying 'master' branch.")
                try:
                    origin.pull('master')
                    log(f"Pulled latest image submissions from 'master' branch.")
                except GitCommandError as e_pull_master:
                    log(f"Pulling 'master' also failed: {e_pull_master}. Assuming repo might be empty or inaccessible.")
                    # If pull fails on both, it might be an empty repo or a new one.
                    # We'll proceed to ensure local files are initialized.
        else:
            # Clean up if a partial/failed clone exists
            if os.path.exists(IMAGE_SUBMISSIONS_CLONE_DIR):
                shutil.rmtree(IMAGE_SUBMISSIONS_CLONE_DIR)
                log(f"Cleaned up existing non-Git or incomplete repo at {IMAGE_SUBMISSIONS_CLONE_DIR}.")

            # Attempt to clone. This will clone the default branch if one exists.
            try:
                Repo.clone_from(remote_url, IMAGE_SUBMISSIONS_CLONE_DIR)
                log(f"Cloned {IMAGESUB_REPO_NAME} to {IMAGE_SUBMISSIONS_CLONE_DIR} (default branch).")
            except GitCommandError as e_clone:
                if "Remote branch" in str(e_clone) and "not found" in str(e_clone) and "upstream origin" in str(e_clone):
                    log(f"WARNING: Cloning failed because no remote branch found. This often means the repo is empty: {e_clone}")
                    # If the repo is truly empty (no initial commit), the clone will fail like this.
                    # We proceed by ensuring local directories/files exist.
                    if not os.path.exists(IMAGES_SUBMISSION_FOLDER): # This is the app's local folder
                        os.makedirs(IMAGES_SUBMISSION_FOLDER)
                    if not os.path.exists(IMAGE_SUBMISSIONS_META_FILE): # This is the app's local meta file
                        with open(IMAGE_SUBMISSIONS_META_FILE, 'w') as f:
                            json.dump([], f)
                    return True, "Image submissions repo is empty on GitHub, initialized locally."
                else:
                    log(f"ERROR: Unexpected Git clone error: {e_clone}")
                    return False, f"Failed to clone image submissions repo: {e_clone}"
            except Exception as e:
                log(f"ERROR: General error during initial clone: {e}")
                return False, f"General error during initial clone: {e}"

        # If we reached here, a clone or pull was successful (or it was an empty repo handled above)
        # Copy image_submissions.json from cloned repo to app's local file
        source_meta_file_in_cloned_repo = os.path.join(IMAGE_SUBMISSIONS_CLONE_DIR, IMAGESUB_REPO_FILE)
        if os.path.exists(source_meta_file_in_cloned_repo):
            shutil.copyfile(source_meta_file_in_cloned_repo, IMAGE_SUBMISSIONS_META_FILE)
            log(f"Copied {IMAGESUB_REPO_FILE} from cloned repo to app's local.")
        else:
            log(f"WARNING: {IMAGESUB_REPO_FILE} not found in cloned repo. Initializing empty app's local meta file.")
            if not os.path.exists(IMAGE_SUBMISSIONS_META_FILE):
                with open(IMAGE_SUBMISSIONS_META_FILE, 'w') as f:
                    json.dump([], f)

        # Copy image files from the cloned repo's IMAGES_SUBMISSIONS folder to app's local IMAGES_SUBMISSION_FOLDER
        source_images_dir_in_cloned_repo = os.path.join(IMAGE_SUBMISSIONS_CLONE_DIR, "IMAGE_SUBMISSIONS") # Assuming this structure in the git repo
        if os.path.isdir(source_images_dir_in_cloned_repo):
            if os.path.exists(IMAGES_SUBMISSION_FOLDER):
                # Remove existing app's local image submissions to ensure a clean sync
                shutil.rmtree(IMAGES_SUBMISSION_FOLDER)
                os.makedirs(IMAGES_SUBMISSION_FOLDER) # Recreate empty folder
                log(f"Cleaned app's local {IMAGES_SUBMISSION_FOLDER}.")

            # Copy all contents from source_images_dir_in_cloned_repo to app's local IMAGES_SUBMISSION_FOLDER
            for item in os.listdir(source_images_dir_in_cloned_repo):
                s = os.path.join(source_images_dir_in_cloned_repo, item)
                d = os.path.join(IMAGES_SUBMISSION_FOLDER, item)
                if os.path.isdir(s):
                    shutil.copytree(s, d, dirs_exist_ok=True)
                else:
                    shutil.copy2(s, d)
            log(f"Copied image files from cloned repo to app's local {IMAGES_SUBMISSION_FOLDER}.")
        else:
            log(f"WARNING: 'IMAGE_SUBMISSIONS' directory not found in cloned repo at {source_images_dir_in_cloned_repo}. Ensuring app's local folder exists.")
            if not os.path.exists(IMAGES_SUBMISSION_FOLDER):
                os.makedirs(IMAGES_SUBMISSION_FOLDER)

        return True, "Image submissions synced successfully."

    except Exception as e:
        log(f"Error syncing image submissions from GitHub: {e}")
        return False, f"Error syncing image submissions from GitHub: {e}"

# --- Image Submission Metadata Management ---
def load_image_submissions_meta():
    # Ensure local data is up-to-date from GitHub before loading
    # This call needs to be carefully managed to avoid infinite recursion if it's called too often.
    # For now, it's placed here to ensure the latest data is always loaded.
    # In a production environment, you might want a separate background sync process or a webhook.
    sync_image_submissions_local_from_github() 

    if not os.path.exists(IMAGE_SUBMISSIONS_META_FILE):
        log("No image submissions meta file found locally after sync attempt. Creating empty list.")
        # If after sync, the file still doesn't exist, create an empty one.
        with open(IMAGE_SUBMISSIONS_META_FILE, 'w') as f:
            json.dump([], f)
        return []
    try:
        with open(IMAGE_SUBMISSIONS_META_FILE, "r") as f:
            data = json.load(f)
            log(f"Loaded image submissions meta: {data}")
            return data
    except json.JSONDecodeError as e:
        log(f"Error decoding image_submissions.json: {e}. File might be corrupt or empty. Reinitializing.")
        # If JSON is invalid, reinitialize it as an empty list
        with open(IMAGE_SUBMISSIONS_META_FILE, 'w') as f:
            json.dump([], f)
        return []
    except Exception as e:
        log(f"Error loading image submissions meta: {e}")
        return []

def save_image_submissions_meta(meta_list):
    try:
        with open(IMAGE_SUBMISSIONS_META_FILE, "w") as f:
            json.dump(meta_list, f, indent=2)
        log(f"Saved image submissions meta: {meta_list}")
    except Exception as e:
        log(f"Error saving image submissions meta: {e}")

# --- New Routes for Image Submission and Feedback ---
@app.route("/submit_image", methods=["POST"])
@login_required
def submit_image():
    if current_user.username != USERNAME_FOR_CASSIE:
        return jsonify({"error": "Unauthorized"}), 403

    if 'image' not in request.files:
        return jsonify({"error": "No image file part"}), 400
    file = request.files['image']
    description = request.form.get('description', '').strip()

    if file.filename == '':
        return jsonify({"error": "No selected image file"}), 400
    if not description:
        return jsonify({"error": "Description is required"}), 400
    
    # Check if allowed extension (already covered by ALLOWED_EXTENSIONS)
    if not allowed_file(file.filename):
        return jsonify({"error": "File type not allowed."}), 400

    filename = secure_filename(file.filename)
    # Generate a unique ID for the submission
    submission_id = str(uuid.uuid4())
    
    # Create a subfolder for each submission to keep files organized
    submission_folder = os.path.join(IMAGES_SUBMISSION_FOLDER, submission_id)
    os.makedirs(submission_folder, exist_ok=True)
    
    save_path = os.path.join(submission_folder, filename)
    file.save(save_path)
    log(f"Saved image submission to: {save_path}")

    # Store metadata
    meta_list = load_image_submissions_meta() # Load current state (which now includes sync)
    new_submission = {
        "id": submission_id,
        "filename": filename,
        "description": description,
        "uploader": current_user.username,
        "timestamp": datetime.now().isoformat(),
        "image_url": url_for('serve_image_submission', submission_id=submission_id, filename=filename),
        "feedback": {
            "h": "",
            "olivia": ""
        }
    }
    meta_list.append(new_submission)
    save_image_submissions_meta(meta_list) # Save updated state

    # Asynchronously push to GitHub
    threading.Thread(target=git_push_image_submissions, args=(f"Cassie submitted new image: {filename}",)).start()

    return jsonify({"success": True, "message": "Image submitted successfully."})

@app.route("/get_image_submissions", methods=["GET"])
@login_required
def get_image_submissions():
    submissions = load_image_submissions_meta()
    # Sort by timestamp, newest first
    submissions.sort(key=lambda x: x.get("timestamp", ""), reverse=True)
    return jsonify({"submissions": submissions})

@app.route("/submit_feedback/<submission_id>", methods=["POST"])
@login_required
def submit_feedback(submission_id):
    if current_user.username not in ["h", "olivia"]:
        return jsonify({"error": "Unauthorized"}), 403

    feedback_text = request.json.get('feedback', '').strip()
    
    meta_list = load_image_submissions_meta() # Load current state (which now includes sync)
    found = False
    for submission in meta_list:
        if submission.get("id") == submission_id:
            submission["feedback"][current_user.username] = feedback_text
            found = True
            break
    
    if not found:
        return jsonify({"error": "Submission not found"}), 404

    save_image_submissions_meta(meta_list) # Save updated state
    
    # Asynchronously push to GitHub
    threading.Thread(target=git_push_image_submissions, args=(f"Feedback from {current_user.username} for submission {submission_id}",)).start()

    return jsonify({"success": True, "message": "Feedback submitted successfully."})

@app.route("/IMAGE_SUBMISSIONS/<submission_id>/<filename>")
def serve_image_submission(submission_id, filename):
    return send_from_directory(os.path.join(IMAGES_SUBMISSION_FOLDER, submission_id), filename)

# --- New routes for deleting image submissions ---
@app.route("/delete_image_submission/<submission_id>", methods=["POST"])
@login_required
def delete_image_submission(submission_id):
    if current_user.username != "h": # Only 'h' can delete submissions
        return jsonify({"error": "Unauthorized"}), 403

    meta_list = load_image_submissions_meta()
    original_len = len(meta_list)
    
    # Find and remove the submission from the list
    submission_to_delete = None
    new_meta_list = []
    for submission in meta_list:
        if submission.get("id") == submission_id:
            submission_to_delete = submission
        else:
            new_meta_list.append(submission)

    if submission_to_delete is None:
        return jsonify({"error": "Image submission not found"}), 404

    # Delete the corresponding folder and its contents locally
    submission_folder_path = os.path.join(IMAGES_SUBMISSION_FOLDER, submission_id)
    if os.path.exists(submission_folder_path) and os.path.isdir(submission_folder_path):
        try:
            shutil.rmtree(submission_folder_path)
            log(f"Deleted local image submission folder: {submission_folder_path}")
        except Exception as e:
            log(f"Error deleting local image submission folder {submission_folder_path}: {e}")
            return jsonify({"error": f"Failed to delete local files: {e}"}), 500
    else:
        log(f"Local image submission folder not found: {submission_folder_path}")

    # Save the updated metadata list
    save_image_submissions_meta(new_meta_list)

    # Asynchronously push changes to GitHub
    threading.Thread(target=git_push_image_submissions, args=(f"Deleted image submission: {submission_id} by {current_user.username}",)).start()

    return jsonify({"success": True, "message": "Image submission deleted successfully."})

@app.route("/delete_image_submissions", methods=["POST"])
@login_required
def delete_image_submissions():
    if current_user.username != "h": # Only 'h' can delete submissions
        return jsonify({"error": "Unauthorized"}), 403

    data = request.get_json()
    submission_ids = data.get("submission_ids", [])
    
    meta_list = load_image_submissions_meta()
    original_len = len(meta_list)
    
    deleted_count = 0
    new_meta_list = []
    deleted_ids = []

    for submission in meta_list:
        if submission.get("id") in submission_ids:
            # Delete local files/folder for this submission
            submission_folder_path = os.path.join(IMAGES_SUBMISSION_FOLDER, submission.get("id"))
            if os.path.exists(submission_folder_path) and os.path.isdir(submission_folder_path):
                try:
                    shutil.rmtree(submission_folder_path)
                    log(f"Deleted local image submission folder: {submission_folder_path}")
                    deleted_count += 1
                    deleted_ids.append(submission.get("id"))
                except Exception as e:
                    log(f"Error deleting local image submission folder {submission_folder_path}: {e}")
                    # Don't fail the whole bulk operation for one file, just log
            else:
                log(f"Local image submission folder not found during bulk delete: {submission_folder_path}")
        else:
            new_meta_list.append(submission)
    
    if deleted_count > 0:
        save_image_submissions_meta(new_meta_list)
        # Asynchronously push changes to GitHub
        threading.Thread(target=git_push_image_submissions, args=(f"Bulk deleted image submissions: {', '.join(deleted_ids)} by {current_user.username}",)).start()
        return jsonify({"success": True, "message": f"Deleted {deleted_count} image submissions."})
    else:
        return jsonify({"success": False, "message": "No matching image submissions found for deletion."}), 404

# --- End new routes for deleting image submissions ---


@app.route("/admin")
@login_required
def admin():
    users = db.execute("SELECT * FROM users")
    group_chats = db.execute("SELECT * FROM group_chats")
    downloads = []
    if 'DOWNLOADS_META' in globals():
        downloads += DOWNLOADS_META
    downloads += load_uploaded_meta()
    image_folders = {}
    images_base = os.path.join(os.getcwd(), "IMAGES")
    if os.path.exists(images_base):
        for folder in os.listdir(images_base):
            folder_path = os.path.join(images_base, folder)
            if os.path.isdir(folder_path):
                image_folders[folder] = [img for img in os.listdir(folder_path) if not img.startswith('.')]
    
    image_submissions = load_image_submissions_meta() # Load image submissions for admin page
    
    return render_template(
        "admin.html",
        users=users,
        group_chats=group_chats,
        downloads=downloads,
        image_folders=image_folders,
        image_submissions=image_submissions # Pass to admin template
    )

@app.route("/delete_user/<username>", methods=["POST"])
@login_required
def delete_user(username):
    db.execute("DELETE FROM users WHERE username = ?", username)
    flash(f"User {username} deleted.", "success")
    return redirect(url_for('admin'))

@app.route("/delete_users", methods=["POST"])
@login_required
def delete_users():
    data = request.get_json()
    usernames = data.get("users", [])
    for username in usernames:
        db.execute("DELETE FROM users WHERE username = ?", username)
    return jsonify({"success": True})

@app.route("/delete_chat/<chatid>", methods=["POST"])
@login_required
def delete_chat(chatid):
    db.execute("DELETE FROM group_chats WHERE id = ?", chatid)
    flash(f"Chat {chatid} deleted.", "success")
    return redirect(url_for('admin'))

@app.route("/delete_chats", methods=["POST"])
@login_required
def delete_chats():
    data = request.get_json()
    chats = data.get("chats", [])
    for chat_id in chats:
        db.execute("DELETE FROM group_chats WHERE id = ?", chat_id)
    return jsonify({"success": True})

@app.route("/reset_messages", methods=["POST"])
@login_required
def reset_messages():
    try:
        with open("messages.json", "w") as f:
            json.dump({}, f)
        flash("All messages have been reset.", "success")
        return jsonify({"success": True})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/delete_download/<filename>", methods=["POST"])
@login_required
def delete_download(filename):
    filepath = os.path.join(DOWNLOADS_FOLDER, filename)
    if os.path.exists(filepath):
        os.remove(filepath)
    meta_list = load_uploaded_meta()
    new_meta_list = [m for m in meta_list if m['filename'] != filename]
    if len(new_meta_list) != len(meta_list):
        save_uploaded_meta(new_meta_list)
    # --- GIT PUSH STEP ---
    success, msg = git_push_downloads(f"User {current_user.username} deleted {filename}")
    log(f"Git push result (delete): success={success}, msg={msg}")
    if not success:
        flash('File deleted, but git push failed: ' + msg, 'danger')
    else:
        flash(f"Deleted {filename} from downloads and pushed to git.", "success")
    return redirect(url_for('admin'))

@app.route("/delete_downloads", methods=["POST"])
@login_required
def delete_downloads():
    data = request.get_json()
    filenames = data.get("filenames", [])
    meta_list = load_uploaded_meta()
    new_meta_list = meta_list[:]
    actually_deleted = []
    for filename in filenames:
        filepath = os.path.join(DOWNLOADS_FOLDER, filename)
        if os.path.exists(filepath):
            os.remove(filepath)
            actually_deleted.append(filename)
        new_meta_list = [m for m in new_meta_list if m['filename'] != filename]
    save_uploaded_meta(new_meta_list)
    # --- GIT PUSH STEP ---
    if actually_deleted:
        success, msg = git_push_downloads(f"User {current_user.username} deleted {', '.join(actually_deleted)}")
        log(f"Git push result (bulk delete): success={success}, msg={msg}")
    else:
        success = True
        msg = "No files actually deleted."
    return jsonify({"success": success, "msg": msg})

@app.route("/delete_images_folder/<key>", methods=["POST"])
@login_required
def delete_images_folder(key):
    images_base = os.path.join(os.getcwd(), "IMAGES")
    folder_path = os.path.join(images_base, key)
    if os.path.exists(folder_path) and os.path.isdir(folder_path):
        for img in os.listdir(folder_path):
            img_path = os.path.join(folder_path, img)
            if os.path.isfile(img_path):
                os.remove(img_path)
        os.rmdir(folder_path)
    flash(f"Deleted folder /IMAGES/{key}.", "success")
    return redirect(url_for('admin'))

@app.route("/delete_images_folders", methods=["POST"])
@login_required
def delete_images_folders():
    data = request.get_json()
    keys = data.get("keys", [])
    images_base = os.path.join(os.getcwd(), "IMAGES")
    for key in keys:
        folder_path = os.path.join(images_base, key)
        if os.path.exists(folder_path) and os.path.isdir(folder_path):
            for img in os.listdir(folder_path):
                img_path = os.path.join(folder_path, img)
                if os.path.isfile(img_path):
                    os.remove(img_path)
            os.rmdir(folder_path)
    return jsonify({"success": True})

@app.route("/delete_image/<key>/<img>", methods=["POST"])
@login_required
def delete_image(key, img):
    images_base = os.path.join(os.getcwd(), "IMAGES")
    img_path = os.path.join(images_base, key, img)
    if os.path.exists(img_path):
        os.remove(img_path)
    flash(f"Deleted image {img} from /IMAGES/{key}.", "success")
    return redirect(url_for('admin'))

@app.route("/delete_images", methods=["POST"])
@login_required
def delete_images():
    data = request.get_json()
    images = data.get("images", [])
    images_base = os.path.join(os.getcwd(), "IMAGES")
    for entry in images:
        key = entry.get("key")
        img = entry.get("image")
        if key and img:
            img_path = os.path.join(images_base, key, img)
            if os.path.exists(img_path):
                os.remove(img_path)
    return jsonify({"success": True})
    
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
            log("Description required.")
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
TODO_FILE = "todo.json"

TODO_FILE = "todo.json"
TODO_REPO_OWNER = "Arh48"
TODO_REPO_NAME = "todo"
TODO_REPO_FILE = "todo.json"
TODO_REPO_BRANCH = "main"

def fetch_todo_from_github():
    """Fetch todo.json from the GitHub repo and save locally."""
    url = f"https://raw.githubusercontent.com/{TODO_REPO_OWNER}/{TODO_REPO_NAME}/{TODO_REPO_BRANCH}/{TODO_REPO_FILE}"
    try:
        r = requests.get(url)
        if r.status_code == 200:
            todo = r.json()
            with open(TODO_FILE, "w") as f:
                json.dump(todo, f, indent=2)
            return todo
    except Exception as e:
        print(f"Error fetching todo from GitHub: {e}")
    return []

def load_todo():
    if not os.path.exists(TODO_FILE):
        return fetch_todo_from_github()
    try:
        with open(TODO_FILE, "r") as f:
            return json.load(f)
    except Exception:
        return []

def save_todo(todo_list):
    with open(TODO_FILE, "w") as f:
        json.dump(todo_list, f, indent=2)
    github_token = os.environ.get("GITHUB_TOKEN")
    if not github_token:
        print("GITHUB_TOKEN not set, skipping remote push for todo.")
        return
    repo_dir = "/tmp/todo_repo"
    remote_url = f"https://{github_token}@github.com/{TODO_REPO_OWNER}/{TODO_REPO_NAME}.git"
    if not os.path.isdir(repo_dir):
        if os.path.exists(repo_dir):
            shutil.rmtree(repo_dir)
        Repo.clone_from(remote_url, repo_dir, branch=TODO_REPO_BRANCH)
    repo = Repo(repo_dir)
    # Always pull first to avoid non-fast-forward error
    origin = repo.remote()
    origin.pull(TODO_REPO_BRANCH)
    shutil.copyfile(TODO_FILE, os.path.join(repo_dir, TODO_REPO_FILE))
    repo.git.add(TODO_REPO_FILE)
    try:
        repo.index.commit(f"Update todo.json from chat app (by {getattr(current_user, 'username', 'unknown')})")
    except GitCommandError as e:
        if "nothing to commit" not in str(e):
            print("Git commit error:", e)
            return
    try:
        origin.push()
    except Exception as e:
        print("Git push error:", e)

@app.route("/todo", methods=["GET"])
@login_required
def get_todo():
    return jsonify(load_todo())

@app.route("/todo", methods=["POST"])
@login_required
def update_todo():
    todo_list = request.json.get("todo", [])
    save_todo(todo_list)
    return jsonify({"success": True})


NOTES_FILE = "notes.json"
NOTES_REPO_OWNER = "Arh48"
NOTES_REPO_NAME = "todo"
NOTES_REPO_FILE = "notes.json"
NOTES_REPO_BRANCH = "main"

def fetch_notes_from_github():
    url = f"https://raw.githubusercontent.com/{NOTES_REPO_OWNER}/{NOTES_REPO_NAME}/{NOTES_REPO_BRANCH}/{NOTES_REPO_FILE}"
    try:
        r = requests.get(url)
        if r.status_code == 200:
            notes = r.json()
            with open(NOTES_FILE, "w") as f:
                json.dump(notes, f, indent=2)
            return notes
    except Exception as e:
        print(f"Error fetching notes from GitHub: {e}")
    return ""

def load_notes():
    if not os.path.exists(NOTES_FILE):
        return fetch_notes_from_github()
    try:
        with open(NOTES_FILE, "r") as f:
            return json.load(f)
    except Exception:
        return ""

def save_notes(notes_content):
    with open(NOTES_FILE, "w") as f:
        json.dump(notes_content, f, indent=2)
    github_token = os.environ.get("GITHUB_TOKEN")
    if not github_token:
        print("GITHUB_TOKEN not set, skipping remote push for notes.")
        return
    repo_dir = "/tmp/notes_repo"
    remote_url = f"https://{github_token}@github.com/{NOTES_REPO_OWNER}/{NOTES_REPO_NAME}.git"
    if not os.path.isdir(repo_dir):
        if os.path.exists(repo_dir):
            shutil.rmtree(repo_dir)
        Repo.clone_from(remote_url, repo_dir, branch=NOTES_REPO_BRANCH)
    repo = Repo(repo_dir)
    origin = repo.remote()
    # Always pull first to avoid non-fast-forward error
    try:
        origin.pull(NOTES_REPO_BRANCH)
    except Exception as e:
        print("Git pull error on notes:", e)
    shutil.copyfile(NOTES_FILE, os.path.join(repo_dir, NOTES_REPO_FILE))
    repo.git.add(NOTES_REPO_FILE)
    try:
        repo.index.commit(f"Update notes.json from chat app (by {getattr(current_user, 'username', 'unknown')})")
    except GitCommandError as e:
        if "nothing to commit" not in str(e):
            print("Git commit error:", e)
            return
    try:
        origin.push()
    except Exception as e:
        print("Git push error:", e)


@app.route("/notes", methods=["GET"])
@login_required
def get_notes():
    return jsonify(load_notes())

@app.route("/notes", methods=["POST"])
@login_required
def update_notes():
    notes_content = request.json.get("notes", "")
    save_notes(notes_content)
    return jsonify({"success": True})

def get_directory_size(path):
    """Recursively get the total size (in bytes) of all files under `path`, following symlinks."""
    total = 0
    for dirpath, dirnames, filenames in os.walk(path, followlinks=True):
        for f in filenames:
            fp = os.path.join(dirpath, f)
            try:
                if os.path.isfile(fp):
                    total += os.path.getsize(fp)
            except Exception as e:
                print(f"Could not access: {fp}: {e}")
    return total

@app.route("/storage_usage")
@login_required
def storage_usage():
    # Use the directory of your app.py, which should include venv, static, settings, etc.
    base_dir = os.path.dirname(os.path.abspath(__file__))
    # For debugging: print subfolder sizes
    for folder in os.listdir(base_dir):
        folder_path = os.path.join(base_dir, folder)
        if os.path.isdir(folder_path):
            print(f"{folder}/: {get_directory_size(folder_path) / (1024*1024):.2f} MB")
    # Calculate total size
    total_size = get_directory_size(base_dir)
    return jsonify({
        "used_bytes": total_size,
        "total_bytes": 1073741824  # 1GB
    })


UPLOAD_BASE = os.path.join(os.getcwd(), "IMAGES")

def delete_file_later(path, seconds=300):
    def remove():
        try:
            os.remove(path)
            # Optionally also remove empty group folder if no files left
            group_folder = os.path.dirname(path)
            if not os.listdir(group_folder):
                os.rmdir(group_folder)
        except Exception as e:
            print(f"Failed to delete {path}: {e}")
    timer = threading.Timer(seconds, remove)
    timer.start()


@app.route("/IMAGES/<key>/", methods=["POST"])
@login_required
def upload_image(key):
    if 'image' not in request.files:
        return jsonify({"error": "No file part"}), 400
    file = request.files['image']
    if file.filename == '':
        return jsonify({"error": "No selected file"}), 400

    filename = secure_filename(file.filename)
    group_path = os.path.join(UPLOAD_BASE, str(key))
    os.makedirs(group_path, exist_ok=True)
    full_path = os.path.join(group_path, filename)
    file.save(full_path)

    # Schedule deletion in 5 minutes (300 seconds)
    delete_file_later(full_path, 300)

    # URL for fetching the image (should match the one used in your JS)
    image_url = url_for('serve_image', key=key, filename=filename)
    return jsonify({"image_url": image_url})

@app.route("/IMAGES/<key>/<filename>")
def serve_image(key, filename):
    return send_from_directory(os.path.join(UPLOAD_BASE, str(key)), filename)

@app.route("/emulator")
def emulator():
    return render_template("index.html")

if __name__ == "__main__":
    log("App starting up...")
    if not os.path.exists(UPLOAD_BASE):
        os.makedirs(UPLOAD_BASE)
        log(f"Created UPLOAD_BASE: {UPLOAD_BASE}")
    if not os.path.exists(DOWNLOADS_FOLDER):
        os.makedirs(DOWNLOADS_FOLDER)
        log(f"Created DOWNLOADS_FOLDER: {DOWNLOADS_FOLDER}")
    if not os.path.exists(IMAGES_SUBMISSION_FOLDER): # Create new folder
        os.makedirs(IMAGES_SUBMISSION_FOLDER)
        log(f"Created IMAGES_SUBMISSION_FOLDER: {IMAGES_SUBMISSION_FOLDER}")

    # --- Sync image submissions on startup ---
    sync_success, sync_msg = sync_image_submissions_local_from_github()
    log(f"Initial image submissions sync result: success={sync_success}, msg={sync_msg}")
    # --- End sync image submissions on startup ---

    chat_group = db.execute("SELECT * FROM group_chats WHERE id = ?", GLOBAL_CHAT_KEY)
    if not chat_group:
        db.execute("INSERT INTO group_chats (id) VALUES (?)", GLOBAL_CHAT_KEY)
        log(f"Created initial group chat: {GLOBAL_CHAT_KEY}")
    app.run(debug=True)
