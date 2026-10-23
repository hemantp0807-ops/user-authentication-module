import os
import secrets
from datetime import datetime, timedelta
from functools import wraps

import psycopg2
from psycopg2.extras import RealDictCursor
from dotenv import load_dotenv
from flask import Flask, render_template, request, redirect, url_for, flash, session
from werkzeug.security import generate_password_hash, check_password_hash

load_dotenv()

app = Flask(__name__)

SECRET_KEY = os.getenv("SECRET_KEY")
DATABASE_URL = os.getenv("DATABASE_URL")

if not SECRET_KEY:
    raise RuntimeError("SECRET_KEY is missing. Add it to your .env file.")
if not DATABASE_URL:
    raise RuntimeError("DATABASE_URL is missing. Add it to your .env file.")

app.config.update(
    SECRET_KEY=SECRET_KEY,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=os.getenv("COOKIE_SECURE", "0") == "1",
    PERMANENT_SESSION_LIFETIME=timedelta(minutes=30),
)

def get_db():
    """Open a connection to Supabase PostgreSQL."""
    return psycopg2.connect(
        DATABASE_URL,
        cursor_factory=RealDictCursor,
        connect_timeout=10,
        sslmode="require",
    )

def init_db():
    """Create the tables used by this application if they do not exist."""
    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute("""
                CREATE TABLE IF NOT EXISTS users (
                    user_id SERIAL PRIMARY KEY,
                    full_name VARCHAR(100) NOT NULL,
                    email VARCHAR(100) UNIQUE NOT NULL,
                    password_hash VARCHAR(255) NOT NULL,
                    role VARCHAR(255) NOT NULL DEFAULT 'user',
                    status VARCHAR(10) NOT NULL DEFAULT 'inactive'
                        CHECK (status IN ('active', 'inactive')),
                    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
                )
            """)
            cur.execute("""
                CREATE TABLE IF NOT EXISTS email_verifications (
                    user_id INTEGER PRIMARY KEY
                        REFERENCES users(user_id) ON DELETE CASCADE,
                    token VARCHAR(255) UNIQUE NOT NULL,
                    expires_at TIMESTAMP NOT NULL
                )
            """)
            cur.execute("""
                CREATE TABLE IF NOT EXISTS password_resets (
                    user_id INTEGER PRIMARY KEY
                        REFERENCES users(user_id) ON DELETE CASCADE,
                    token VARCHAR(255) UNIQUE NOT NULL,
                    expires_at TIMESTAMP NOT NULL
                )
            """)
        conn.commit()

def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if not session.get("user_id"):
            flash("Please log in first.")
            return redirect(url_for("login"))
        return view(*args, **kwargs)
    return wrapped

def role_required(*roles):
    def decorator(view):
        @wraps(view)
        def wrapped(*args, **kwargs):
            if not session.get("user_id"):
                flash("Please log in first.")
                return redirect(url_for("login"))
            user = current_user()
            if not user or user["status"] != "active":
                session.clear()
                flash("Your account is inactive. Please log in again.")
                return redirect(url_for("login"))
            if user["role"] not in roles:
                flash("You do not have permission to access that page.")
                return redirect(url_for("dashboard"))
            return view(*args, **kwargs)
        return wrapped
    return decorator

def current_user():
    user_id = session.get("user_id")
    if not user_id:
        return None
    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute("""
                SELECT user_id, full_name, email, role, status, created_at
                FROM users
                WHERE user_id = %s
            """, (user_id,))
            return cur.fetchone()

@app.context_processor
def inject_user():
    try:
        return {"logged_in_user": current_user()}
    except psycopg2.Error:
        return {"logged_in_user": None}

@app.route("/")
def index():
    if session.get("user_id"):
        return redirect(url_for("dashboard"))
    return render_template("index.html")

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        full_name = request.form.get("full_name", "").strip()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")

        if not full_name or len(full_name) > 100 or not email or len(email) > 100:
            flash("Enter a valid name and email address.")
            return render_template("register.html")
        if len(password) < 8:
            flash("Password must contain at least 8 characters.")
            return render_template("register.html")

        token = secrets.token_urlsafe(32)
        expires_at = datetime.utcnow() + timedelta(hours=24)
        password_hash = generate_password_hash(password)

        try:
            with get_db() as conn:
                with conn.cursor() as cur:
                    cur.execute("""
                        INSERT INTO users
                            (full_name, email, password_hash, role, status)
                        VALUES (%s, %s, %s, 'user', 'inactive')
                        RETURNING user_id
                    """, (full_name, email, password_hash))
                    user_id = cur.fetchone()["user_id"]
                    cur.execute("""
                        INSERT INTO email_verifications (user_id, token, expires_at)
                        VALUES (%s, %s, %s)
                    """, (user_id, token, expires_at))
                conn.commit()
        except psycopg2.errors.UniqueViolation:
            flash("An account with this email already exists.")
            return render_template("register.html")
        except psycopg2.Error:
            app.logger.exception("Registration database error")
            flash("Database error. Check the server logs and Supabase connection.")
            return render_template("register.html")

        verify_url = url_for("verify_email", token=token, _external=True)
        # Development only: configure an email provider before production use.
        app.logger.warning("Verification link for %s: %s", email, verify_url)
        flash("Registration saved. For development, the verification link is in the server terminal.")
        return redirect(url_for("login"))

    return render_template("register.html")

@app.route("/verify/<token>")
def verify_email(token):
    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute("""
                SELECT user_id, expires_at
                FROM email_verifications
                WHERE token = %s
            """, (token,))
            record = cur.fetchone()

            if not record or record["expires_at"] < datetime.utcnow():
                flash("Verification link is invalid or expired.")
                return redirect(url_for("login"))

            cur.execute(
                "UPDATE users SET status = 'active' WHERE user_id = %s",
                (record["user_id"],),
            )
            cur.execute(
                "DELETE FROM email_verifications WHERE user_id = %s",
                (record["user_id"],),
            )
        conn.commit()

    flash("Email verified. You can now log in.")
    return redirect(url_for("login"))

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")

        with get_db() as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT * FROM users WHERE email = %s", (email,))
                user = cur.fetchone()

        if not user or not check_password_hash(user["password_hash"], password):
            flash("Invalid email or password.")
        elif user["status"] != "active":
            flash("Account is inactive. Verify your email or contact the administrator.")
        else:
            session.clear()
            session.permanent = True
            session["user_id"] = user["user_id"]
            session["email"] = user["email"]
            session["role"] = user["role"]
            return redirect(url_for("dashboard"))

    return render_template("login.html")

@app.route("/forgot-password", methods=["GET", "POST"])
def forgot_password():
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()

        with get_db() as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT user_id FROM users WHERE email = %s", (email,))
                user = cur.fetchone()

                if user:
                    token = secrets.token_urlsafe(32)
                    expires_at = datetime.utcnow() + timedelta(minutes=30)
                    cur.execute("""
                        INSERT INTO password_resets (user_id, token, expires_at)
                        VALUES (%s, %s, %s)
                        ON CONFLICT (user_id) DO UPDATE
                        SET token = EXCLUDED.token,
                            expires_at = EXCLUDED.expires_at
                    """, (user["user_id"], token, expires_at))
                    reset_url = url_for("reset_password", token=token, _external=True)
                    # Development only: configure an email provider before production use.
                    app.logger.warning("Password reset link for %s: %s", email, reset_url)
                conn.commit()

        flash("If the email exists, a reset link has been generated. In development, check the server terminal.")
        return redirect(url_for("login"))

    return render_template("forgot_password.html")

@app.route("/reset-password/<token>", methods=["GET", "POST"])
def reset_password(token):
    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute("""
                SELECT user_id, expires_at
                FROM password_resets
                WHERE token = %s
            """, (token,))
            reset = cur.fetchone()

    if not reset or reset["expires_at"] < datetime.utcnow():
        flash("Password reset link is invalid or expired.")
        return redirect(url_for("forgot_password"))

    if request.method == "POST":
        password = request.form.get("password", "")
        if len(password) < 8:
            flash("Password must contain at least 8 characters.")
            return render_template("reset_password.html")

        with get_db() as conn:
            with conn.cursor() as cur:
                cur.execute("""
                    UPDATE users SET password_hash = %s WHERE user_id = %s
                """, (generate_password_hash(password), reset["user_id"]))
                cur.execute(
                    "DELETE FROM password_resets WHERE user_id = %s",
                    (reset["user_id"],),
                )
            conn.commit()

        flash("Password changed. Please log in.")
        return redirect(url_for("login"))

    return render_template("reset_password.html")

@app.route("/dashboard")
@login_required
def dashboard():
    user = current_user()
    if not user or user["status"] != "active":
        session.clear()
        flash("Your account is inactive.")
        return redirect(url_for("login"))
    return render_template("dashboard.html", user=user)

@app.route("/admin/users")
@role_required("admin")
def admin_users():
    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute("""
                SELECT user_id, full_name, email, role, status, created_at
                FROM users
                ORDER BY created_at DESC
            """)
            users = cur.fetchall()
    return render_template("admin_users.html", users=users)

@app.route("/logout", methods=["POST"])
@login_required
def logout():
    session.clear()
    flash("You have been logged out.")
    return redirect(url_for("login"))

@app.cli.command("init-db")
def init_db_command():
    init_db()
    print("Database tables are ready.")

if __name__ == "__main__":
    init_db()
    app.run(debug=os.getenv("FLASK_DEBUG", "0") == "1")
