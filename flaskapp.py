from flask import Flask, render_template, request, redirect, url_for, send_from_directory
import sqlite3
import os
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATABASE = os.path.join(BASE_DIR, "users.db")
UPLOAD_FOLDER = os.path.join(BASE_DIR, "uploads")

os.makedirs(UPLOAD_FOLDER, exist_ok=True)


def get_db():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn


@app.route("/")
def index():
    return render_template("register.html")


@app.route("/register", methods=["POST"])
def register():
    username = request.form["username"]
    password = request.form["password"]
    firstname = request.form["firstname"]
    lastname = request.form["lastname"]
    email = request.form["email"]
    address = request.form["address"]

    uploaded_file = request.files.get("file")

    filename = None
    word_count = 0

    if uploaded_file and uploaded_file.filename:
        original_name = secure_filename(uploaded_file.filename)
        filename = username + "_" + original_name
        file_path = os.path.join(UPLOAD_FOLDER, filename)

        uploaded_file.save(file_path)

        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            text = f.read()
            word_count = len(text.split())

    hashed_password = generate_password_hash(password)

    conn = get_db()

    try:
        conn.execute(
            """
            INSERT INTO users
            (username, password, firstname, lastname, email, address, filename, word_count)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                username,
                hashed_password,
                firstname,
                lastname,
                email,
                address,
                filename,
                word_count,
            ),
        )
        conn.commit()
    except sqlite3.IntegrityError:
        conn.close()
        return "Username already exists. Please choose another username."

    conn.close()

    return redirect(url_for("profile", username=username))


@app.route("/profile/<username>")
def profile(username):
    conn = get_db()
    user = conn.execute(
        "SELECT * FROM users WHERE username = ?",
        (username,),
    ).fetchone()
    conn.close()

    if user is None:
        return "User not found."

    return render_template("profile.html", user=user)


@app.route("/login", methods=["GET", "POST"])
def login():
    error = None

    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]

        conn = get_db()
        user = conn.execute(
            "SELECT * FROM users WHERE username = ?",
            (username,),
        ).fetchone()
        conn.close()

        if user and check_password_hash(user["password"], password):
            return redirect(url_for("profile", username=username))

        error = "Invalid username or password."

    return render_template("login.html", error=error)


@app.route("/download/<username>")
def download_file(username):
    conn = get_db()
    user = conn.execute(
        "SELECT filename FROM users WHERE username = ?",
        (username,),
    ).fetchone()
    conn.close()

    if user is None or not user["filename"]:
        return "No file was uploaded."

    return send_from_directory(
        UPLOAD_FOLDER,
        user["filename"],
        as_attachment=True
    )


if __name__ == "__main__":
    app.run(debug=True)
