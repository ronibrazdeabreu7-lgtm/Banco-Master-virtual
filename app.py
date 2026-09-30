import os
import sqlite3
import uuid
import hashlib
from functools import wraps
from pathlib import Path

from dotenv import load_dotenv
from flask import Flask, render_template, request, redirect, url_for, session, flash, g
from werkzeug.security import generate_password_hash, check_password_hash
from flask_wtf.csrf import CSRFProtect

BASE_DIR = Path(__file__).resolve().parent
load_dotenv(BASE_DIR / ".env")
DB = BASE_DIR / "banco.db"

app = Flask(__name__)
SECRET_KEY = os.environ.get("BANCO_SECRET_KEY")

if not SECRET_KEY:
    raise RuntimeError(
        "BANCO_SECRET_KEY não configurada. "
        "Defina a chave no arquivo .env antes de iniciar a aplicação."
    )

app.config["SECRET_KEY"] = SECRET_KEY

app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["SESSION_COOKIE_SECURE"] = True

csrf = CSRFProtect(app)


def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DB)
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA foreign_keys = ON")
    return g.db


@app.teardown_appcontext
def close_db(exception=None):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def login_required(view):
    @wraps(view)
    def wrapped_view(*args, **kwargs):
        if "user_id" not in session:
            return redirect(url_for("login"))
        return view(*args, **kwargs)

    return wrapped_view


@app.route("/")
def index():
    if "user_id" in session:
        return redirect(url_for("dashboard"))
    return redirect(url_for("login"))


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        db = get_db()

        user = db.execute(
            """
            SELECT
                u.id,
                u.username,
                u.password_hash,
                u.account_id,
                u.client_id,
                a.account_number,
                a.agency,
                a.balance_cents,
                a.is_owner,
                c.name,
                c.test_id
            FROM users u
            JOIN accounts a ON a.id = u.account_id
            LEFT JOIN clients c ON c.id = u.client_id
            WHERE u.username = ?
            LIMIT 1
            """,
            (username,),
        ).fetchone()

        if user:
            senha_hash_atual = user["password_hash"]

            # Compatibilidade com hashes antigos SHA-256.
            if len(senha_hash_atual) == 64:
                senha_hash_antigo = hashlib.sha256(
                    password.encode("utf-8")
                ).hexdigest()

                senha_valida = (
                    senha_hash_atual == senha_hash_antigo
                )

                # Migra automaticamente para scrypt
                # somente depois de uma senha correta.
                if senha_valida:
                    novo_hash = generate_password_hash(
                        password,
                        method="scrypt"
                    )

                    db.execute(
                        """
                        UPDATE users
                        SET password_hash = ?
                        WHERE id = ?
                        """,
                        (novo_hash, user["id"])
                    )

                    db.commit()

            else:
                # Novos hashes usam o verificador seguro do Werkzeug.
                senha_valida = check_password_hash(
                    senha_hash_atual,
                    password
                )

            if senha_valida:
                session.clear()
                session["user_id"] = user["id"]
                session["account_id"] = user["account_id"]
                session["client_id"] = user["client_id"]
                session["is_owner"] = user["is_owner"]
                return redirect(url_for("dashboard"))

        flash("Usuário ou senha inválidos.", "error")

    return render_template("login.html")


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if "user_id" not in session:
            return redirect(url_for("login"))

        db = get_db()

        user = db.execute(
            "SELECT account_id FROM users WHERE id = ?",
            (session["user_id"],)
        ).fetchone()

        if not user:
            session.clear()
            return redirect(url_for("login"))

        account = db.execute(
            "SELECT is_owner FROM accounts WHERE id = ?",
            (user["account_id"],)
        ).fetchone()

        if not account or account["is_owner"] != 1:
            flash("Acesso administrativo não autorizado.", "error")
            return redirect(url_for("dashboard"))

        return f(*args, **kwargs)

    return decorated_function


@app.route("/dashboard")
@login_required
def dashboard():
    db = get_db()

    user = db.execute(
        """
        SELECT
            u.username,
            u.client_id,
            a.agency,
            a.account_number,
            a.balance_cents,
            a.is_owner,
            c.name,
            c.test_id
        FROM users u
        JOIN accounts a ON a.id = u.account_id
        LEFT JOIN clients c ON c.id = u.client_id
        WHERE u.id = ?
        """,
        (session["user_id"],),
    ).fetchone()

    transactions = db.execute(
        """
        SELECT
            transaction_id,
            type AS transaction_type,
            amount_cents,
            description,
            created_at
        FROM transactions
        WHERE account_id = ?
        ORDER BY id DESC
        LIMIT 20
        """,
        (session["account_id"],),
    ).fetchall()

    return render_template(
        "dashboard.html",
        user=user,
        transactions=transactions,
    )


@app.route("/admin")
@admin_required
def admin():
    db = get_db()

    total_clients = db.execute(
        "SELECT COUNT(*) AS total FROM clients"
    ).fetchone()["total"]

    total_accounts = db.execute(
        "SELECT COUNT(*) AS total FROM accounts"
    ).fetchone()["total"]

    total_clients_balance = db.execute(
        "SELECT COALESCE(SUM(balance_cents), 0) AS total "
        "FROM accounts WHERE is_owner = 0"
    ).fetchone()["total"]

    owner_balance = db.execute(
        "SELECT COALESCE(SUM(balance_cents), 0) AS total "
        "FROM accounts WHERE is_owner = 1"
    ).fetchone()["total"]

    total_transactions = db.execute(
        "SELECT COUNT(*) AS total FROM transactions"
    ).fetchone()["total"]

    total_pix = db.execute(
        "SELECT COUNT(*) AS total FROM pix_transactions"
    ).fetchone()["total"]

    total_pix_value = db.execute(
        "SELECT COALESCE(SUM(amount_cents), 0) AS total "
        "FROM pix_transactions"
    ).fetchone()["total"]

    recent = db.execute("""
        SELECT
            c.name,
            c.test_id,
            a.agency,
            a.account_number,
            a.balance_cents
        FROM clients c
        JOIN accounts a ON a.client_id = c.id
        WHERE a.is_owner = 0
        ORDER BY a.id DESC
        LIMIT 20
    """).fetchall()

    return render_template(
        "admin.html",
        total_clients=total_clients,
        total_accounts=total_accounts,
        total_clients_balance=total_clients_balance,
        owner_balance=owner_balance,
        total_transactions=total_transactions,
        total_pix=total_pix,
        total_pix_value=total_pix_value,
        recent=recent
    )


@app.route("/extrato")
@login_required
def extrato():
    db = get_db()

    transactions = db.execute(
        """
        SELECT
            transaction_id,
            type AS transaction_type,
            amount_cents,
            description,
            created_at
        FROM transactions
        WHERE account_id = ?
        ORDER BY id DESC
        LIMIT 100
        """,
        (session["account_id"],),
    ).fetchall()

    return render_template(
        "extrato.html",
        transactions=transactions,
    )


@app.route("/pix", methods=["GET", "POST"])
@login_required
def pix():
    if request.method == "POST":
        destination = request.form.get("destination", "").strip()
        amount_text = request.form.get("amount", "").strip().replace(",", ".")

        try:
            if not amount_text:
                raise ValueError

            if "," in amount_text:
                amount_text = amount_text.replace(",", ".")

            if amount_text.count(".") > 1:
                raise ValueError

            if "." in amount_text:
                inteiro, centavos = amount_text.split(".")
            else:
                inteiro, centavos = amount_text, "00"

            if not inteiro:
                inteiro = "0"

            if not inteiro.isdigit() or not centavos.isdigit():
                raise ValueError

            if len(centavos) > 2:
                raise ValueError

            centavos = centavos.ljust(2, "0")

            amount_cents = int(inteiro) * 100 + int(centavos)
        except (ValueError, TypeError):
            flash("Valor inválido.", "error")
            return redirect(url_for("pix"))

        if amount_cents <= 0:
            flash("O valor precisa ser maior que zero.", "error")
            return redirect(url_for("pix"))

        db = get_db()

        try:
            db.execute("BEGIN IMMEDIATE")

            origin = db.execute(
                """
                SELECT id, account_number, balance_cents
                FROM accounts
                WHERE id = ?
                """,
                (session["account_id"],),
            ).fetchone()

            target = db.execute(
                """
                SELECT id, account_number, balance_cents
                FROM accounts
                WHERE account_number = ?
                """,
                (destination,),
            ).fetchone()

            if not target:
                raise ValueError("Conta de destino não encontrada.")

            if target["id"] == origin["id"]:
                raise ValueError("A conta de destino não pode ser a mesma.")

            if origin["balance_cents"] < amount_cents:
                raise ValueError("Saldo insuficiente.")

            txid = "PIX-" + uuid.uuid4().hex[:20].upper()
            txid_envio = txid + "-E"
            txid_recebimento = txid + "-R"

            db.execute(
                """
                UPDATE accounts
                SET balance_cents = balance_cents - ?
                WHERE id = ?
                """,
                (amount_cents, origin["id"]),
            )

            db.execute(
                """
                UPDATE accounts
                SET balance_cents = balance_cents + ?
                WHERE id = ?
                """,
                (amount_cents, target["id"]),
            )

            db.execute(
                """
                INSERT INTO transactions
                (
                    transaction_id,
                    account_id,
                    type,
                    amount_cents,
                    description,
                    created_at
                )
                VALUES (?, ?, ?, ?, ?, datetime('now'))
                """,
                (
                    txid_envio,
                    origin["id"],
                    "PIX_ENVIO",
                    -amount_cents,
                    f"Pix enviado para {target['account_number']}",
                ),
            )

            db.execute(
                """
                INSERT INTO transactions
                (
                    transaction_id,
                    account_id,
                    type,
                    amount_cents,
                    description,
                    created_at
                )
                VALUES (?, ?, ?, ?, ?, datetime('now'))
                """,
                (
                    txid_recebimento,
                    target["id"],
                    "PIX_RECEBIDO",
                    amount_cents,
                    f"Pix recebido da conta {origin['account_number']}",
                ),
            )

            db.execute(
                """
                INSERT INTO pix_transactions
                (
                    transaction_id,
                    sender_account_id,
                    receiver_account_id,
                    amount_cents,
                    description,
                    created_at
                )
                VALUES (?, ?, ?, ?, ?, datetime('now'))
                """,
                (
                    txid,
                    origin["id"],
                    target["id"],
                    amount_cents,
                    f"Pix enviado para {target['account_number']}",
                ),
            )

            db.commit()

            flash(f"Pix realizado com sucesso. ID: {txid}", "success")

        except Exception as e:
            db.rollback()
            flash(str(e), "error")

        return redirect(url_for("pix"))

    return render_template("pix.html")


@app.template_filter("brl")
def brl(cents):
    value = cents / 100
    return (
        "R$ "
        + f"{value:,.2f}"
        .replace(",", "X")
        .replace(".", ",")
        .replace("X", ".")
    )


if __name__ == "__main__":
    app.run(
        host="0.0.0.0",
        port=5000,
        debug=False,
    )
