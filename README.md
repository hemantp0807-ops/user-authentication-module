# User Authentication Module (Flask + PostgreSQL)

A Python web application using **Flask (not Django)** and PostgreSQL for registration, email verification, login, password reset, sessions, role checks, and logout.

## Features

- `users` table follows the assignment columns: `user_id`, `full_name`, `email`, `password_hash`, `role`, `status`, `created_at`.
- Passwords are stored as Werkzeug password hashes, never plaintext.
- Public registration creates standard `user` accounts only; users cannot select `admin` during registration.
- Email verification and password reset tokens use separate tables.
- In development, verification/reset links are printed to the server terminal. Configure an email provider before production.
- 30-minute permanent session lifetime, HTTP-only session cookie, role checks, and POST logout.

## Local setup (Windows)

1. Install Python 3.10+ and PostgreSQL.
2. Create a database and database user, e.g. in pgAdmin Query Tool:

   ```sql
   CREATE USER portal_user WITH PASSWORD 'replace-with-a-strong-password';
   CREATE DATABASE secure_user_portal OWNER portal_user;
   ```

3. Open Command Prompt in this project directory and run:

   ```bat
   py -m venv .venv
   .venv\Scripts\activate
   pip install -r requirements.txt
   set DATABASE_URL=postgresql://portal_user:replace-with-a-strong-password@localhost:5432/secure_user_portal
   set SECRET_KEY=replace-with-a-long-random-secret
   python app.py
   ```

4. Open http://127.0.0.1:5000.
5. Register a user. Copy the verification URL from the terminal into the browser. Then log in.
6. For password reset, request a link and copy it from the terminal.

## Create an administrator

Register and verify a user first, then use PostgreSQL/pgAdmin to promote that account:

```sql
UPDATE users SET role = 'admin' WHERE email = 'your-email@example.com';
```

Never expose an admin role selector on public registration.

## Deployment

Set these environment variables on your hosting service:

- `DATABASE_URL`: provider's PostgreSQL connection URL
- `SECRET_KEY`: long random secret
- `FLASK_DEBUG=0`

Start command:

```bash
gunicorn app:app
```

Use a real email provider before production; terminal links are for local development only. Configure HTTPS and secure cookie settings on the host, and review the app before handling real user data.
