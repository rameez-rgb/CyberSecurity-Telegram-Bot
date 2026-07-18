import sqlite3


def create_database():
    conn = sqlite3.connect("cyberbot.db")
    cursor = conn.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            username TEXT,
            command TEXT,
            time TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)

    conn.commit()
    conn.close()


def log_command(user_id, username, command):

    conn = sqlite3.connect("cyberbot.db")
    cursor = conn.cursor()

    cursor.execute("""
        INSERT INTO logs(user_id, username, command)
        VALUES (?, ?, ?)
    """, (user_id, username, command))

    conn.commit()
    conn.close()

def total_users():

    conn = sqlite3.connect("cyberbot.db")
    cursor = conn.cursor()

    cursor.execute("""
        SELECT COUNT(DISTINCT user_id)
        FROM logs
    """)

    result = cursor.fetchone()[0]

    conn.close()

    return result


def total_commands():

    conn = sqlite3.connect("cyberbot.db")
    cursor = conn.cursor()

    cursor.execute("""
        SELECT COUNT(*)
        FROM logs
    """)

    result = cursor.fetchone()[0]

    conn.close()

    return result


def most_used_command():

    conn = sqlite3.connect("cyberbot.db")
    cursor = conn.cursor()

    cursor.execute("""
        SELECT command, COUNT(*)
        FROM logs
        GROUP BY command
        ORDER BY COUNT(*) DESC
        LIMIT 1
    """)

    result = cursor.fetchone()

    conn.close()

    return result