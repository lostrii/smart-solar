import os
import sqlite3
import time
import base64
import json
import smtplib
import urllib.request
import urllib.parse
from datetime import datetime, timedelta, timezone
from email.message import EmailMessage
from functools import wraps

from flask import Flask, jsonify, redirect, render_template_string, request, send_from_directory, session, url_for
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.middleware.proxy_fix import ProxyFix
from pymongo import MongoClient, DESCENDING


BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.environ.get("DB_PATH") or os.path.join(BASE_DIR, "leads.db")


def load_dotenv_if_available() -> None:
    """
    Production-friendly: allows local `.env` without hard dependency at runtime.
    """
    try:
        from dotenv import load_dotenv  # type: ignore
    except Exception:
        return

    load_dotenv(os.path.join(BASE_DIR, ".env"))


def get_env(name: str) -> str:
    val = os.environ.get(name)
    if not val:
        raise RuntimeError(f"Missing required environment variable: {name}")
    return val


def init_db(create_leads_table: bool = True) -> None:
    conn = sqlite3.connect(DB_PATH)
    try:
        if create_leads_table:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS leads (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    lead_id INTEGER,
                    name TEXT NOT NULL,
                    phone TEXT NOT NULL,
                    email TEXT,
                    city TEXT NOT NULL,
                    date TEXT NOT NULL,
                    tag TEXT,
                    loan_amount REAL,
                    message TEXT,
                    created_at TEXT NOT NULL DEFAULT (datetime('now'))
                );
                """
            )

            # Migration for existing DBs (older schema without loan/tag/message columns).
            # SQLite doesn't support altering table definitions in-place, so we add missing columns.
            cols = {row[1] for row in conn.execute("PRAGMA table_info(leads)").fetchall()}
            if "tag" not in cols:
                conn.execute("ALTER TABLE leads ADD COLUMN tag TEXT;")
            if "loan_amount" not in cols:
                conn.execute("ALTER TABLE leads ADD COLUMN loan_amount REAL;")
            if "message" not in cols:
                conn.execute("ALTER TABLE leads ADD COLUMN message TEXT;")

        # Tracks failed login attempts to prevent brute-force attacks.
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS login_attempts (
                ip TEXT PRIMARY KEY,
                attempts INTEGER NOT NULL DEFAULT 0,
                first_attempt_ts INTEGER NOT NULL DEFAULT 0,
                last_attempt_ts INTEGER NOT NULL DEFAULT 0,
                locked_until_ts INTEGER NOT NULL DEFAULT 0
            );
            """
        )
        conn.commit()
    finally:
        conn.close()


def create_app() -> Flask:
    load_dotenv_if_available()
    app = Flask(__name__)

    app.secret_key = get_env("SESSION_SECRET")
    app.permanent_session_lifetime = timedelta(hours=6)

    # Cookie hardening (works for local dev too; set SESSION_COOKIE_SECURE=true if desired)
    app.config["SESSION_COOKIE_HTTPONLY"] = True
    app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
    if os.environ.get("SESSION_COOKIE_SECURE", "").lower() == "true":
        app.config["SESSION_COOKIE_SECURE"] = True

    # If you're behind a reverse proxy/load balancer, enable this to trust forwarded headers.
    # Set TRUST_PROXY=true to avoid breaking local dev.
    if os.environ.get("TRUST_PROXY", "").lower() == "true":
        app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_port=1)

    @app.after_request
    def add_security_headers(resp):
        # Minimal, production-safe headers (won't break your inline/CDN setup).
        resp.headers.setdefault("X-Content-Type-Options", "nosniff")
        resp.headers.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")
        resp.headers.setdefault("X-Frame-Options", "SAMEORIGIN")
        resp.headers.setdefault("Permissions-Policy", "geolocation=(), microphone=(), camera=()")
        # CSP kept permissive due to inline React/Babel + external CDNs.
        resp.headers.setdefault(
            "Content-Security-Policy",
            "default-src 'self' https: data:; "
            "script-src 'self' 'unsafe-inline' 'unsafe-eval' https:; "
            "style-src 'self' 'unsafe-inline' https:; "
            "img-src 'self' https: data:; "
            "connect-src 'self' https:; "
            "frame-src https:;",
        )
        return resp

    admin_username = get_env("ADMIN_USERNAME")
    admin_password_hash = os.environ.get("ADMIN_PASSWORD_HASH")

    # Optional fallback: if you only have ADMIN_PASSWORD_PLAIN, we hash it at startup (never write to disk).
    admin_password_plain = os.environ.get("ADMIN_PASSWORD_PLAIN")
    if not admin_password_hash and admin_password_plain:
        admin_password_hash = generate_password_hash(admin_password_plain)

    if not admin_password_hash:
        raise RuntimeError("Set either ADMIN_PASSWORD_HASH or ADMIN_PASSWORD_PLAIN in environment variables.")

    # Leads storage:
    # - If MONGO_URI is configured, store leads in MongoDB Atlas collection `leads`
    # - Otherwise fall back to SQLite (useful for local development)
    mongo_uri = os.environ.get("MONGO_URI", "").strip()
    use_mongo = bool(mongo_uri)
    mongo_client = None
    leads_collection = None

    if use_mongo:
        mongo_db_name = os.environ.get("MONGO_DB_NAME", "").strip() or None
        mongo_client = MongoClient(
            mongo_uri,
            serverSelectionTimeoutMS=5000,
            connectTimeoutMS=5000,
            socketTimeoutMS=10000,
            maxPoolSize=int(os.environ.get("MONGO_MAX_POOL_SIZE", "10")),
        )
        try:
            # Verify connection early (better error than failing later during inserts).
            mongo_client.admin.command("ping")
        except Exception as e:
            raise RuntimeError(f"MongoDB connection failed: {e}")

        mongo_db = mongo_client[mongo_db_name] if mongo_db_name else mongo_client.get_default_database()
        leads_collection = mongo_db["leads"]
        leads_collection.create_index([("timestamp", DESCENDING)], background=True)

        # Best-effort migration to avoid data loss when switching from the legacy SQLite leads table.
        # Can be disabled with: MONGO_MIGRATE_FROM_SQLITE=false
        migrate_from_sqlite = os.environ.get("MONGO_MIGRATE_FROM_SQLITE", "true").lower() == "true"
        if migrate_from_sqlite:
            leads_collection.create_index("legacy_sqlite_id", unique=True, sparse=True)

            def migrate_sqlite_leads_to_mongo() -> None:
                conn = sqlite3.connect(DB_PATH)
                try:
                    # If there's no legacy leads table, nothing to migrate.
                    has_table = conn.execute(
                        "SELECT name FROM sqlite_master WHERE type='table' AND name='leads' LIMIT 1"
                    ).fetchone()
                    if not has_table:
                        return

                    # Ensure legacy columns exist (older DBs may miss tag/loan/message).
                    cols = {row[1] for row in conn.execute("PRAGMA table_info(leads)").fetchall()}
                    if "tag" not in cols:
                        conn.execute("ALTER TABLE leads ADD COLUMN tag TEXT;")
                    if "loan_amount" not in cols:
                        conn.execute("ALTER TABLE leads ADD COLUMN loan_amount REAL;")
                    if "message" not in cols:
                        conn.execute("ALTER TABLE leads ADD COLUMN message TEXT;")
                    conn.commit()

                    rows = conn.execute(
                        """
                        SELECT id, lead_id, name, phone, email, city, date, tag, loan_amount, message, created_at
                        FROM leads
                        ORDER BY id DESC
                        """
                    ).fetchall()

                    for r in rows:
                        legacy_id = r[0]
                        lead_id = r[1]
                        name = r[2]
                        phone = r[3]
                        email = r[4]
                        city = r[5]
                        date = r[6]
                        tag = r[7]
                        loan_amount = r[8]
                        message = r[9]
                        created_at_raw = r[10]

                        if created_at_raw:
                            try:
                                ts_dt = datetime.strptime(created_at_raw, "%Y-%m-%d %H:%M:%S").replace(
                                    tzinfo=timezone.utc
                                )
                            except Exception:
                                ts_dt = datetime.now(timezone.utc)
                        else:
                            ts_dt = datetime.now(timezone.utc)

                        created_at_str = ts_dt.strftime("%Y-%m-%d %H:%M:%S")

                        doc = {
                            "name": name,
                            "phone": phone,
                            "address": city,
                            "system_size": None,
                            "timestamp": ts_dt,
                            "created_at": created_at_str,
                            # Compatibility fields:
                            "email": email,
                            "city": city,
                            "date": date,
                            "tag": tag,
                            "type": tag,
                            "loan_amount": loan_amount,
                            "message": message,
                            "lead_id": lead_id,
                            "legacy_sqlite_id": legacy_id,
                        }
                        leads_collection.update_one(
                            {"legacy_sqlite_id": legacy_id},
                            {"$setOnInsert": doc},
                            upsert=True,
                        )
                finally:
                    conn.close()

            try:
                migrate_sqlite_leads_to_mongo()
            except Exception:
                # Don't block startup if migration fails; backend can still operate with new submissions.
                pass

        init_db(create_leads_table=False)
    else:
        init_db(create_leads_table=True)

    LOGIN_MAX_ATTEMPTS = int(os.environ.get("LOGIN_MAX_ATTEMPTS", "5"))
    LOGIN_WINDOW_SECONDS = int(os.environ.get("LOGIN_WINDOW_SECONDS", "900"))  # 15 minutes
    LOGIN_LOCKOUT_SECONDS = int(os.environ.get("LOGIN_LOCKOUT_SECONDS", "900"))  # 15 minutes
    LOGIN_FAILURE_DELAY_SECONDS = float(os.environ.get("LOGIN_FAILURE_DELAY_SECONDS", "0.2"))

    NOTIFY_TYPES = [t.strip() for t in os.environ.get("NOTIFY_TYPES", "General Inquiry,Loan Request").split(",") if t.strip()]

    def build_notification_text(payload: dict) -> str:
        name = (payload.get("name") or "").strip() or "—"
        phone = (payload.get("phone") or "").strip() or "—"
        req_type = (payload.get("tag") or payload.get("type") or "").strip() or "General Inquiry"
        return f"New form submission\\nType: {req_type}\\nName: {name}\\nPhone: {phone}"

    def notify_email_smtp(payload: dict) -> bool:
        host = os.environ.get("SMTP_HOST")
        user = os.environ.get("SMTP_USER")
        password = os.environ.get("SMTP_PASS")
        to_addr = os.environ.get("SMTP_TO")
        from_addr = os.environ.get("SMTP_FROM") or user
        if not host or not user or not password or not to_addr or not from_addr:
            return False

        port = int(os.environ.get("SMTP_PORT", "587"))
        use_tls = os.environ.get("SMTP_TLS", "true").lower() == "true"

        msg = EmailMessage()
        msg["Subject"] = os.environ.get("SMTP_SUBJECT_PREFIX", "[Smart Solar] ") + "New submission"
        msg["From"] = from_addr
        msg["To"] = to_addr
        msg.set_content(
            "\\n".join(
                [
                    build_notification_text(payload),
                    "",
                    f"Email: {(payload.get('email') or '—')}",
                    f"City: {(payload.get('city') or '—')}",
                    f"Message: {(payload.get('message') or '—')}",
                    f"Timestamp: {(payload.get('created_at') or payload.get('date') or '—')}",
                ]
            )
        )

        try:
            with smtplib.SMTP(host, port, timeout=10) as server:
                server.ehlo()
                if use_tls:
                    server.starttls()
                    server.ehlo()
                server.login(user, password)
                server.send_message(msg)
            return True
        except Exception:
            return False

    def notify_whatsapp_twilio(payload: dict) -> bool:
        """
        WhatsApp via Twilio Messages API.
        Env required:
          - TWILIO_ACCOUNT_SID
          - TWILIO_AUTH_TOKEN
          - TWILIO_WHATSAPP_FROM (e.g. whatsapp:+14155238886)
          - ADMIN_WHATSAPP_TO (e.g. whatsapp:+919876543210)
        """
        sid = os.environ.get("TWILIO_ACCOUNT_SID")
        token = os.environ.get("TWILIO_AUTH_TOKEN")
        wa_from = os.environ.get("TWILIO_WHATSAPP_FROM")
        wa_to = os.environ.get("ADMIN_WHATSAPP_TO")
        if not sid or not token or not wa_from or not wa_to:
            return False

        body = build_notification_text(payload)
        url = f"https://api.twilio.com/2010-04-01/Accounts/{sid}/Messages.json"
        data = urllib.parse.urlencode({"From": wa_from, "To": wa_to, "Body": body}).encode()
        auth = base64.b64encode(f"{sid}:{token}".encode()).decode()
        req = urllib.request.Request(url, data=data, method="POST", headers={"Authorization": f"Basic {auth}"})
        try:
            with urllib.request.urlopen(req, timeout=10) as resp:
                return 200 <= resp.status < 300
        except Exception:
            return False

    def notify_whatsapp_meta(payload: dict) -> bool:
        """
        WhatsApp via Meta WhatsApp Cloud API.

        Env required:
          - META_WA_TOKEN (permanent or long-lived access token)
          - META_WA_PHONE_NUMBER_ID (from WhatsApp Manager / Cloud API setup)
          - META_WA_TO (recipient number in E.164, digits only or with +; we normalize)
        Optional:
          - META_WA_API_VERSION (default v22.0)

        Note: Cloud API policies apply (business-initiated messages may require approved templates).
        """
        token = os.environ.get("META_WA_TOKEN")
        phone_number_id = os.environ.get("META_WA_PHONE_NUMBER_ID")
        to_raw = os.environ.get("META_WA_TO")
        if not token or not phone_number_id or not to_raw:
            return False

        to = "".join([c for c in str(to_raw) if c.isdigit()])
        if not to:
            return False

        version = (os.environ.get("META_WA_API_VERSION") or "v22.0").strip()
        url = f"https://graph.facebook.com/{version}/{phone_number_id}/messages"

        body_text = build_notification_text(payload)
        payload_json = {
            "messaging_product": "whatsapp",
            "to": to,
            "type": "text",
            "text": {"body": body_text},
        }

        req = urllib.request.Request(
            url,
            data=json.dumps(payload_json).encode("utf-8"),
            method="POST",
            headers={
                "Authorization": f"Bearer {token}",
                "Content-Type": "application/json",
            },
        )

        try:
            with urllib.request.urlopen(req, timeout=10) as resp:
                return 200 <= resp.status < 300
        except Exception:
            return False

    def build_whatsapp_wa_me_fallback(payload: dict) -> str | None:
        """
        Fallback link (manual) if WhatsApp API isn't configured.
        Requires ADMIN_WHATSAPP_PHONE_E164 (digits only, country code included; e.g. 918400000810).
        """
        phone = (os.environ.get("ADMIN_WHATSAPP_PHONE_E164") or "").strip()
        if not phone:
            return None
        text = build_notification_text(payload)
        return f"https://wa.me/{phone}?text={urllib.parse.quote(text)}"

    def get_client_ip() -> str:
        # If behind a proxy, prefer X-Forwarded-For (first IP). Otherwise use remote addr.
        fwd = request.headers.get("X-Forwarded-For", "")
        if fwd:
            return fwd.split(",")[0].strip()
        return request.remote_addr or "unknown"

    def get_login_attempt_row(conn: sqlite3.Connection, ip: str):
        return conn.execute(
            """
            SELECT attempts, first_attempt_ts, last_attempt_ts, locked_until_ts
            FROM login_attempts
            WHERE ip = ?
            """,
            (ip,),
        ).fetchone()

    def is_locked(conn: sqlite3.Connection, ip: str, now_ts: int):
        row = get_login_attempt_row(conn, ip)
        if not row:
            return (False, 0)
        _, _, _, locked_until_ts = row
        if locked_until_ts and now_ts < locked_until_ts:
            return (True, int(locked_until_ts - now_ts))
        return (False, 0)

    def record_failed_attempt(conn: sqlite3.Connection, ip: str, now_ts: int) -> None:
        row = get_login_attempt_row(conn, ip)

        if not row:
            attempts = 1
            first_attempt_ts = now_ts
            last_attempt_ts = now_ts
            locked_until_ts = 0
        else:
            attempts, first_attempt_ts, last_attempt_ts, locked_until_ts = row

            # If we're past the window, start a new counting window.
            if not first_attempt_ts or (now_ts - int(first_attempt_ts)) > LOGIN_WINDOW_SECONDS:
                attempts = 1
                first_attempt_ts = now_ts
                last_attempt_ts = now_ts
                locked_until_ts = 0
            else:
                attempts = int(attempts) + 1
                last_attempt_ts = now_ts

            # Lockout once threshold is hit.
            if attempts >= LOGIN_MAX_ATTEMPTS:
                locked_until_ts = now_ts + LOGIN_LOCKOUT_SECONDS

        conn.execute(
            """
            INSERT INTO login_attempts (ip, attempts, first_attempt_ts, last_attempt_ts, locked_until_ts)
            VALUES (?, ?, ?, ?, ?)
            ON CONFLICT(ip) DO UPDATE SET
                attempts=excluded.attempts,
                first_attempt_ts=excluded.first_attempt_ts,
                last_attempt_ts=excluded.last_attempt_ts,
                locked_until_ts=excluded.locked_until_ts
            """,
            (ip, attempts, first_attempt_ts, last_attempt_ts, locked_until_ts),
        )
        conn.commit()

    def reset_failed_attempts(conn: sqlite3.Connection, ip: str) -> None:
        conn.execute("DELETE FROM login_attempts WHERE ip = ?", (ip,))
        conn.commit()

    def require_admin(view):
        @wraps(view)
        def wrapped(*args, **kwargs):
            if not session.get("admin_authed"):
                # For API endpoints we return 401; for pages we redirect.
                if request.path.startswith("/api/"):
                    return jsonify({"error": "unauthorized"}), 401
                return redirect(url_for("login"))
            return view(*args, **kwargs)

        return wrapped

    @app.get("/login")
    def login():
        error = request.args.get("error")
        retry_seconds = request.args.get("retry")
        error_html = ""
        if error == "locked":
            try:
                retry_val = max(0, int(float(retry_seconds or "0")))
            except ValueError:
                retry_val = 0
            error_html = f"""
            <div class="bg-red-50 border border-red-200 text-red-700 px-4 py-3 rounded-lg text-sm mb-4" role="alert">
              Too many failed login attempts. Try again in <span class="font-bold">{retry_val}</span> seconds.
            </div>
            """
        elif error:
            error_html = """
            <div class="bg-red-50 border border-red-200 text-red-700 px-4 py-3 rounded-lg text-sm mb-4" role="alert">
              Invalid username or password.
            </div>
            """

        return render_template_string(
            """
            <!doctype html>
            <html lang="en">
              <head>
                <meta charset="utf-8" />
                <meta name="viewport" content="width=device-width, initial-scale=1" />
                <title>Admin Login</title>
                <script src="https://cdn.tailwindcss.com"></script>
              </head>
              <body class="bg-slate-950 text-white min-h-screen flex items-center justify-center p-4">
                <div class="w-full max-w-md">
                  <div class="flex items-center justify-center mb-6">
                    <img src="./logo.png" alt="SmartSolar" class="h-14 opacity-90" />
                  </div>
                  <div class="bg-white/5 backdrop-blur border border-white/10 rounded-2xl p-6">
                    <h1 class="text-2xl font-extrabold mb-2">Admin Login</h1>
                    <p class="text-slate-300 text-sm mb-6">Enter the owner credentials to access the admin dashboard.</p>
                    {{ error_html | safe }}
                    <form method="post" action="{{ url_for('login_post') }}">
                      <label class="block text-sm font-semibold text-slate-200 mb-1">Username</label>
                      <input name="username" autocomplete="username" required class="w-full bg-white/5 border border-white/10 rounded-xl px-4 py-3 outline-none focus:border-orange-400 focus:ring-2 focus:ring-orange-400/30 mb-4" />

                      <label class="block text-sm font-semibold text-slate-200 mb-1">Password</label>
                      <input name="password" type="password" autocomplete="current-password" required class="w-full bg-white/5 border border-white/10 rounded-xl px-4 py-3 outline-none focus:border-orange-400 focus:ring-2 focus:ring-orange-400/30 mb-6" />

                      <button type="submit" class="w-full bg-orange-500 hover:bg-orange-600 text-white font-extrabold py-3 rounded-xl transition">
                        Sign in
                      </button>
                      <a href="/" class="block text-center text-slate-300 text-sm mt-4 hover:text-white">Back to website</a>
                    </form>
                  </div>
                </div>
              </body>
            </html>
            """,
            error_html=error_html,
        )

    @app.post("/login")
    def login_post():
        username = (request.form.get("username") or "").strip()
        password = request.form.get("password") or ""

        # Basic validation
        if not username or not password:
            return redirect(url_for("login", error=1))

        ip = get_client_ip()
        now_ts = int(time.time())
        conn = sqlite3.connect(DB_PATH)
        try:
            locked, retry_seconds = is_locked(conn, ip, now_ts)
            if locked:
                return redirect(url_for("login", error="locked", retry=str(retry_seconds)))

            # Only one owner account exists; we still count failures regardless of username mismatch.
            username_ok = username == admin_username
            password_ok = check_password_hash(admin_password_hash, password) if username_ok else False

            if not (username_ok and password_ok):
                # Tiny delay to make brute-force attempts slower.
                time.sleep(LOGIN_FAILURE_DELAY_SECONDS)
                record_failed_attempt(conn, ip, now_ts)
                return redirect(url_for("login", error=1))

            reset_failed_attempts(conn, ip)
        finally:
            conn.close()

        session.clear()
        session["admin_authed"] = True
        session.permanent = True

        return redirect(url_for("admin"))

    @app.get("/logout")
    def logout():
        session.clear()
        return redirect(url_for("login"))

    @app.get("/admin")
    @require_admin
    def admin():
        return send_from_directory(BASE_DIR, "index.html")

    @app.post("/api/leads")
    def post_leads():
        data = request.get_json(silent=True) or {}

        # Allow simple form posts if needed in the future
        if not data:
            data = request.form.to_dict(flat=True)

        name = (data.get("name") or "").strip()
        phone = (data.get("phone") or "").strip()
        email = (data.get("email") or "").strip() or None
        city = (data.get("city") or "").strip()
        date = (data.get("date") or "").strip()
        submission_type = (data.get("type") or data.get("tag") or "").strip() or "General Inquiry"
        message = (data.get("message") or "").strip() or None

        # Accept both `loan_amount` and `loanAmount` from the UI.
        loan_amount_raw = data.get("loan_amount", data.get("loanAmount"))
        loan_amount = None
        if loan_amount_raw is not None and str(loan_amount_raw).strip() != "":
            try:
                loan_amount = float(loan_amount_raw)
            except (TypeError, ValueError):
                loan_amount = None

        if not name or not phone or not city:
            return jsonify({"error": "Missing required fields"}), 400

        if not date:
            # Fallback date; UI usually sends date already.
            date = datetime.now(timezone.utc).strftime("%d/%m/%Y")

        lead_id = data.get("id")
        # Required Mongo fields (also returned in API response for admin compatibility)
        address = city
        system_size_raw = data.get("system_size", data.get("systemSize"))
        system_size = None
        if system_size_raw is not None and str(system_size_raw).strip() != "":
            try:
                system_size = float(system_size_raw)
            except (TypeError, ValueError):
                system_size = None

        timestamp_dt = datetime.now(timezone.utc)
        created_at = timestamp_dt.strftime("%Y-%m-%d %H:%M:%S")

        db_id = None
        if leads_collection is not None:
            doc = {
                # Required fields:
                "name": name,
                "phone": phone,
                "address": address,
                "system_size": system_size,
                "timestamp": timestamp_dt,
                # Compatibility fields (existing admin UI):
                "email": email,
                "city": city,
                "date": date,
                "tag": submission_type,
                "type": submission_type,
                "loan_amount": loan_amount,
                "message": message,
                "lead_id": lead_id,
                "created_at": created_at,
            }
            try:
                result = leads_collection.insert_one(doc)
                db_id = str(result.inserted_id)
            except Exception as e:
                return jsonify({"error": "MongoDB insert failed", "details": str(e)}), 503
        else:
            # SQLite fallback (local development / if Mongo is not configured)
            conn = sqlite3.connect(DB_PATH)
            try:
                conn.execute(
                    """
                    INSERT INTO leads (lead_id, name, phone, email, city, date, tag, loan_amount, message)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (lead_id, name, phone, email, city, date, submission_type, loan_amount, message),
                )
                conn.commit()

                row_id = conn.execute("SELECT last_insert_rowid()").fetchone()[0]
                created_at = conn.execute(
                    "SELECT created_at FROM leads WHERE id = ?",
                    (row_id,),
                ).fetchone()[0]
                db_id = row_id
            finally:
                conn.close()

        # Best-effort notifications (never block saving the submission)
        payload = {
            "db_id": db_id,
            "lead_id": lead_id,
            "name": name,
            "phone": phone,
            "email": email,
            "city": city,
            "date": date,
            "created_at": created_at,
            "tag": submission_type,
            "type": submission_type,
            "loan_amount": loan_amount,
            "message": message,
            # New required fields:
            "address": address,
            "system_size": system_size,
            "timestamp": timestamp_dt.isoformat(),
        }

        email_sent = False
        whatsapp_sent = False
        whatsapp_fallback_url = None
        if not NOTIFY_TYPES or submission_type in NOTIFY_TYPES:
            email_sent = notify_email_smtp(payload)
            # Prefer Meta Cloud API if configured; fallback to Twilio if configured.
            whatsapp_sent = notify_whatsapp_meta(payload) or notify_whatsapp_twilio(payload)
            if not whatsapp_sent:
                whatsapp_fallback_url = build_whatsapp_wa_me_fallback(payload)

        return (
            jsonify(
                {
                    "ok": True,
                    "db_id": db_id,
                    "created_at": created_at,
                    "tag": submission_type,
                    "loan_amount": loan_amount,
                    "message": message,
                    "email": email,
                    "city": city,
                    "name": name,
                    "phone": phone,
                    "date": date,
                    "lead_id": lead_id,
                    # Required Mongo-style fields (useful for admin/export):
                    "address": address,
                    "system_size": system_size,
                    "timestamp": timestamp_dt.isoformat(),
                    "notifications": {
                        "email_sent": email_sent,
                        "whatsapp_sent": whatsapp_sent,
                        "whatsapp_fallback_url": whatsapp_fallback_url,
                    },
                }
            ),
            201,
        )

    @app.get("/api/leads")
    @require_admin
    def get_leads():
        limit = request.args.get("limit", "50")
        try:
            limit = int(limit)
        except ValueError:
            limit = 50
        limit = max(1, min(200, limit))

        if leads_collection is not None:
            try:
                docs = list(
                    leads_collection.find(
                        {},
                        {
                            "_id": 1,
                            "lead_id": 1,
                            "name": 1,
                            "phone": 1,
                            "email": 1,
                            "city": 1,
                            "address": 1,
                            "date": 1,
                            "tag": 1,
                            "type": 1,
                            "loan_amount": 1,
                            "message": 1,
                            "system_size": 1,
                            "timestamp": 1,
                            "created_at": 1,
                        },
                    )
                    .sort("timestamp", DESCENDING)
                    .limit(limit)
                )
            except Exception as e:
                return jsonify({"error": "MongoDB query failed", "details": str(e)}), 503

            leads = []
            for d in docs:
                ts = d.get("timestamp")
                if isinstance(ts, datetime):
                    ts_iso = ts.isoformat()
                    created_at_val = d.get("created_at") or ts.strftime("%Y-%m-%d %H:%M:%S")
                else:
                    ts_iso = None
                    created_at_val = d.get("created_at") or d.get("date")

                leads.append(
                    {
                        "db_id": str(d.get("_id")),
                        "id": d.get("lead_id"),
                        "name": d.get("name"),
                        "phone": d.get("phone"),
                        "email": d.get("email"),
                        "city": d.get("city") or d.get("address"),
                        "date": d.get("date"),
                        "tag": d.get("tag") or d.get("type"),
                        "loan_amount": d.get("loan_amount"),
                        "message": d.get("message"),
                        "created_at": created_at_val,
                        # Required fields:
                        "address": d.get("address"),
                        "system_size": d.get("system_size"),
                        "timestamp": ts_iso,
                    }
                )
            return jsonify(leads)

        # SQLite fallback
        conn = sqlite3.connect(DB_PATH)
        try:
            rows = conn.execute(
                """
                SELECT id, lead_id, name, phone, email, city, date, tag, loan_amount, message, created_at
                FROM leads
                ORDER BY id DESC
                LIMIT ?
                """,
                (limit,),
            ).fetchall()
        finally:
            conn.close()

        leads = [
            {
                "db_id": r[0],
                "id": r[1],  # lead_id provided by the client (can be null)
                "name": r[2],
                "phone": r[3],
                "email": r[4],
                "city": r[5],
                "date": r[6],
                "tag": r[7],
                "loan_amount": r[8],
                "message": r[9],
                "created_at": r[10],
                # Required fields (mapped):
                "address": r[5],
                "system_size": None,
                "timestamp": None,
            }
            for r in rows
        ]
        return jsonify(leads)

    # Serve SPA/static: index.html for unknown paths.
    @app.get("/")
    def root():
        return send_from_directory(BASE_DIR, "index.html")

    @app.get("/<path:path>")
    def static_or_spa(path: str):
        # Serve real files when requested (logo.png, etc)
        abs_target = os.path.join(BASE_DIR, path)
        if os.path.exists(abs_target) and os.path.isfile(abs_target):
            return send_from_directory(BASE_DIR, path)
        return send_from_directory(BASE_DIR, "index.html")

    return app


# WSGI entrypoint for production servers (gunicorn/waitress).
app = create_app()

if __name__ == "__main__":
    port = int(os.environ.get("PORT", "5000"))
    host = os.environ.get("HOST", "0.0.0.0")
    app.run(host=host, port=port, debug=False, use_reloader=False)

