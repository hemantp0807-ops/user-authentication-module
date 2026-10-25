import os
from datetime import timedelta
from functools import wraps

import psycopg2
from psycopg2.extras import RealDictCursor
from dotenv import load_dotenv
from flask import (
    Flask, render_template, request, redirect, url_for, flash, session
)
from supabase import create_client

load_dotenv()

app = Flask(__name__)

SECRET_KEY = os.getenv("SECRET_KEY")
DATABASE_URL = os.getenv("DATABASE_URL")
SUPABASE_URL = os.getenv("SUPABASE_URL")
SUPABASE_KEY = os.getenv("SUPABASE_KEY")

if not SECRET_KEY:
    raise RuntimeError("SECRET_KEY is missing. Add it to your .env file.")
if not DATABASE_URL:
    raise RuntimeError("DATABASE_URL is missing. Add it to your .env file.")
if not SUPABASE_URL or not SUPABASE_KEY:
    raise RuntimeError("SUPABASE_URL and SUPABASE_KEY are missing from .env.")

def get_auth_client():
    """Create an isolated Auth client per request to avoid shared user sessions."""
    return create_client(SUPABASE_URL, SUPABASE_KEY)


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
    """Create application profile tables if they do not exist."""
    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute("""
                CREATE TABLE IF NOT EXISTS users (
                    user_id SERIAL PRIMARY KEY,
                    auth_user_id UUID UNIQUE,
                    full_name VARCHAR(100) NOT NULL,
                    email VARCHAR(100) UNIQUE NOT NULL,
                    password_hash VARCHAR(255),
                    role VARCHAR(255) NOT NULL DEFAULT 'user',
                    status VARCHAR(10) NOT NULL DEFAULT 'inactive'
                        CHECK (status IN ('active', 'inactive')),
                    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
                )
            """)
            # Safe migrations for a pre-existing users table.
            cur.execute("ALTER TABLE public.users ADD COLUMN IF NOT EXISTS auth_user_id UUID UNIQUE")
            cur.execute("ALTER TABLE public.users ALTER COLUMN password_hash DROP NOT NULL")
            # Old token tables are retained for data safety but are no longer used.
            cur.execute("""
                CREATE TABLE IF NOT EXISTS email_verifications (
                    user_id INTEGER PRIMARY KEY REFERENCES users(user_id) ON DELETE CASCADE,
                    token VARCHAR(255) UNIQUE NOT NULL,
                    expires_at TIMESTAMP NOT NULL
                )
            """)
            cur.execute("""
                CREATE TABLE IF NOT EXISTS password_resets (
                    user_id INTEGER PRIMARY KEY REFERENCES users(user_id) ON DELETE CASCADE,
                    token VARCHAR(255) UNIQUE NOT NULL,
                    expires_at TIMESTAMP NOT NULL
                )
            """)
        conn.commit()


def current_user():
    user_id = session.get("user_id")
    if not user_id:
        return None
    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute("""
                SELECT user_id, auth_user_id, full_name, email, role, status, created_at
                FROM public.users WHERE user_id = %s
            """, (user_id,))
            return cur.fetchone()


def login_required(view):
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


@app.context_processor
def inject_user():
    try:
        return {"logged_in_user": current_user()}
    except psycopg2.Error:
        app.logger.exception("Could not load current profile")
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

        try:
            # Avoid creating an Auth user when a legacy profile already owns this email.
            with get_db() as conn:
                with conn.cursor() as cur:
                    cur.execute("SELECT user_id FROM public.users WHERE email = %s", (email,))
                    if cur.fetchone():
                        flash("An account with this email already exists. Contact the administrator to migrate it.")
                        return render_template("register.html")

            auth = get_auth_client()
            result = auth.auth.sign_up({
                "email": email,
                "password": password,
                "options": {
                    "data": {"full_name": full_name},
                    "email_redirect_to": url_for("auth_callback", _external=True),
                },
            })

            if not result.user:
                flash("Registration could not be completed. Please try again.")
                return render_template("register.html")

            auth_user_id = str(result.user.id)
            # Supabase handles verification. Keep the app profile inactive until first
            # successful sign-in, which Supabase blocks until email confirmation.
            with get_db() as conn:
                with conn.cursor() as cur:
                    cur.execute("""
                        INSERT INTO public.users
                            (auth_user_id, full_name, email, password_hash, role, status)
                        VALUES (%s, %s, %s, NULL, 'user', 'active')
                    """, (auth_user_id, full_name, email))
                conn.commit()

            flash("Registration submitted. Check your email to verify your account.")
            return redirect(url_for("login"))

        except Exception:
            app.logger.exception("Supabase registration failed")
            flash("Registration failed. Check your email or try again later.")
            return render_template("register.html")

    return render_template("register.html")


@app.route("/auth/callback")
def auth_callback():
    # Supabase completes email confirmation before redirecting here.
    flash("If you have verified your email, you can now log in.")
    return redirect(url_for("login"))


@app.route("/verify/<token>")
def verify_email(token):
    # Legacy route retained to avoid broken old links. New verification is handled by Supabase.
    flash("Email verification is now handled by Supabase. Use the latest verification email.")
    return redirect(url_for("login"))


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")

        try:
            auth = get_auth_client()
            result = auth.auth.sign_in_with_password({"email": email, "password": password})
            if not result.user:
                flash("Invalid email or password.")
                return render_template("login.html")

            auth_user_id = str(result.user.id)
            with get_db() as conn:
                with conn.cursor() as cur:
                    cur.execute("""
                        SELECT user_id, email, role, status
                        FROM public.users WHERE auth_user_id = %s
                    """, (auth_user_id,))
                    user = cur.fetchone()

            if not user:
                try:
                    auth.auth.sign_out()
                except Exception:
                    pass
                flash("Your account profile was not found. Contact the administrator.")
                return render_template("login.html")

            if user["status"] != "active":
                try:
                    auth.auth.sign_out()
                except Exception:
                    pass
                flash("Your account is inactive. Contact the administrator.")
                return render_template("login.html")

            session.clear()
            session.permanent = True
            session["user_id"] = user["user_id"]
            session["email"] = user["email"]
            session["role"] = user["role"]
            session["supabase_user_id"] = auth_user_id
            # Tokens are not placed in the Flask cookie. For this app, the server SDK
            # authenticates the request and Flask keeps its own signed session.
            return redirect(url_for("dashboard"))

        except Exception:
            app.logger.exception("Supabase login failed")
            flash("Login failed. Check your email, password, and email verification.")

    return render_template("login.html")


@app.route("/forgot-password", methods=["GET", "POST"])
def forgot_password():
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        if not email:
            flash("Enter your email address.")
            return render_template("forgot_password.html")
        try:
            get_auth_client().auth.reset_password_for_email(
                email,
                {"redirect_to": url_for("reset_password", _external=True)},
            )
        except Exception:
            # Do not reveal whether an email exists.
            app.logger.exception("Supabase password reset request failed")
        flash("If an account exists for that email, a password reset email will be sent.")
        return redirect(url_for("login"))
    return render_template("forgot_password.html")


@app.route("/reset-password", methods=["GET", "POST"])
def reset_password():
    if request.method == "GET":
        # Supabase sends recovery tokens in the URL fragment. Browser JavaScript in
        # reset_password.html must read the fragment and POST access_token + password.
        return render_template("reset_password.html")

    access_token = request.form.get("access_token", "").strip()
    password = request.form.get("password", "")
    if not access_token:
        flash("The recovery session is missing. Open the latest reset email link again.")
        return render_template("reset_password.html")
    if len(password) < 8:
        flash("Password must contain at least 8 characters.")
        return render_template("reset_password.html")

    try:
        recovery_client = get_auth_client()
        # Supabase recovery links normally provide access_token in the URL fragment.
        # Supply it as the bearer token to the Auth user endpoint via set_session;
        # the template also posts refresh_token when supplied.
        refresh_token = request.form.get("refresh_token", "").strip()
        if not refresh_token:
            flash("The recovery session is incomplete. Open the latest reset email link again.")
            return render_template("reset_password.html")
        recovery_client.auth.set_session(access_token, refresh_token)
        recovery_client.auth.update_user({"password": password})
        flash("Password updated. Please log in with your new password.")
        return redirect(url_for("login"))
    except Exception:
        app.logger.exception("Supabase password update failed")
        flash("Password reset failed or the link expired. Request a new reset email.")
        return render_template("reset_password.html")


@app.route("/dashboard")
@login_required
def dashboard():
    user = current_user()
    if not user:
        session.clear()
        flash("Your profile could not be found. Please log in again.")
        return redirect(url_for("login"))
    return render_template("dashboard.html", user=user)


@app.route("/admin/users")
@role_required("admin")
def admin_users():
    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute("""
                SELECT user_id, full_name, email, role, status, created_at
                FROM public.users ORDER BY created_at DESC
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
