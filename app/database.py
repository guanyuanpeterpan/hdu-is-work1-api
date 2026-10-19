import os
import sqlite3
from app.security import hash_password

DB_PATH = os.getenv("DATABASE_PATH", "app.db")


def get_connection(db_path: str | None = None) -> sqlite3.Connection:
    target_path = db_path or os.getenv("DATABASE_PATH", DB_PATH)
    conn = sqlite3.connect(target_path)
    conn.row_factory = sqlite3.Row
    return conn


def init_db(db_path: str | None = None) -> None:
    """Initialize database tables and default seed accounts."""
    conn = get_connection(db_path)
    with conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                role TEXT DEFAULT 'user'
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS articles (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                title TEXT NOT NULL,
                content TEXT NOT NULL,
                author_id INTEGER NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (author_id) REFERENCES users(id)
            )
        """)
        cursor = conn.cursor()
        # Seed test user: alice / AliceSecurePass2026!
        cursor.execute("SELECT id FROM users WHERE username = ?", ("alice",))
        if not cursor.fetchone():
            cursor.execute(
                "INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)",
                ("alice", hash_password("AliceSecurePass2026!"), "user"),
            )
        # Seed test admin: admin / AdminSecurePass2026!
        cursor.execute("SELECT id FROM users WHERE username = ?", ("admin",))
        if not cursor.fetchone():
            cursor.execute(
                "INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)",
                ("admin", hash_password("AdminSecurePass2026!"), "admin"),
            )
    conn.close()


def get_user_by_username(username: str, db_path: str | None = None) -> dict | None:
    """Retrieve user record via parameterized query to prevent SQLi."""
    conn = get_connection(db_path)
    cursor = conn.cursor()
    cursor.execute(
        "SELECT id, username, password_hash, role FROM users WHERE username = ?",
        (username,),
    )
    row = cursor.fetchone()
    conn.close()
    return dict(row) if row else None


def insert_article(
    title: str, content: str, author_id: int, db_path: str | None = None
) -> dict:
    """Insert article using parameterized query to prevent SQLi."""
    conn = get_connection(db_path)
    cursor = conn.cursor()
    cursor.execute(
        "INSERT INTO articles (title, content, author_id) VALUES (?, ?, ?)",
        (title, content, author_id),
    )
    article_id = cursor.lastrowid
    conn.commit()
    cursor.execute(
        """
        SELECT a.id, a.title, a.content, u.username as author, a.created_at
        FROM articles a
        JOIN users u ON a.author_id = u.id
        WHERE a.id = ?
        """,
        (article_id,),
    )
    row = cursor.fetchone()
    conn.close()
    return dict(row) if row else {}


def get_articles(db_path: str | None = None) -> list[dict]:
    """Retrieve all articles via parameterized query."""
    conn = get_connection(db_path)
    cursor = conn.cursor()
    cursor.execute("""
        SELECT a.id, a.title, a.content, u.username as author, a.created_at
        FROM articles a
        JOIN users u ON a.author_id = u.id
        ORDER BY a.id DESC
    """)
    rows = cursor.fetchall()
    conn.close()
    return [dict(r) for r in rows]
