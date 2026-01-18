import sqlite3
import os

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DB_PATH = os.path.join(BASE_DIR, "database", "honeyvault.db")

def create_tables():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    # Table 1 — File Records
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS file_records (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            original_name TEXT,
            encrypted_name TEXT,
            upload_time TEXT,
            time_lock TEXT,
            uploaded_to_server INTEGER
        )
    """)

    # Table 2 — Key Records
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS key_records (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            file_id INTEGER,
            key_part_1 TEXT,
            key_part_2 TEXT,
            key_part_3 TEXT
        )
    """)

    # Table 3 — Logs
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            event TEXT,
            time TEXT
        )
    """)

    # Table 4 — Server records
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS server_records (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            file_id INTEGER,
            encrypted_name TEXT
        )
    """)

    conn.commit()
    conn.close()

def insert_file_record(original, encrypted, time_lock, uploaded_to_server):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    cursor.execute("""
        INSERT INTO file_records (original_name, encrypted_name, upload_time, time_lock, uploaded_to_server)
        VALUES (?, ?, datetime('now'), ?, ?)
    """, (original, encrypted, time_lock, uploaded_to_server))

    conn.commit()
    conn.close()

def insert_key_record(file_id, k1, k2, k3):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    cursor.execute("""
        INSERT INTO key_records (file_id, key_part_1, key_part_2, key_part_3)
        VALUES (?, ?, ?, ?)
    """, (file_id, k1, k2, k3))

    conn.commit()
    conn.close()

def insert_log(event):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    cursor.execute("""
        INSERT INTO logs (event, time)
        VALUES (?, datetime('now'))
    """, (event,))

    conn.commit()
    conn.close()
