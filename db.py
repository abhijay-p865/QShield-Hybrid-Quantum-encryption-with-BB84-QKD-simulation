import os

import psycopg2
import psycopg2.extras


def _connect():
    return psycopg2.connect(
        dbname="encryption_db",
        host=os.environ.get("PGHOST", "localhost"),
        user=os.environ.get("PGUSER", "postgres"),
        password=os.environ.get("PGPASSWORD"),
        port=os.environ.get("PGPORT", "5432"),
    )


def insert_message(fields: dict) -> str:
    conn = _connect()
    try:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO messages (encrypted_key, ciphertext, nonce, tag, key_id, qkd_key, qber, sifted_bits)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
                RETURNING id
                """,
                (
                    fields["encrypted_key"],
                    fields["ciphertext"],
                    fields["nonce"],
                    fields["tag"],
                    fields["key_id"],
                    fields["qkd_key"],
                    fields["qber"],
                    fields["sifted_bits"],
                ),
            )
            row = cur.fetchone()
            conn.commit()
            return str(row[0])
    finally:
        conn.close()


def insert_eve_attempt(qber: float) -> None:
    conn = _connect()
    try:
        with conn.cursor() as cur:
            cur.execute(
                "INSERT INTO eve_attempts (qber) VALUES (%s)",
                (qber,),
            )
            conn.commit()
    finally:
        conn.close()


def fetch_message(uuid: str) -> dict | None:
    conn = _connect()
    try:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute(
                """
                SELECT encrypted_key, ciphertext, nonce, tag, key_id, created_at, qkd_key, qber, sifted_bits
                FROM messages
                WHERE id = %s::uuid
                """,
                (uuid,),
            )
            row = cur.fetchone()
            if row is None:
                return None
            return dict(row)
    finally:
        conn.close()


def fetch_metrics() -> dict:
    conn = _connect()
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT COUNT(*) FROM messages")
            total_messages = cur.fetchone()[0]

            cur.execute("SELECT AVG(qber) FROM messages WHERE qber IS NOT NULL")
            avg_row = cur.fetchone()
            average_qber = float(avg_row[0]) if avg_row[0] is not None else 0.0

            cur.execute(
                "SELECT COUNT(*) FROM messages WHERE qber IS NOT NULL AND qber > %s",
                (0.11,),
            )
            threats_detected = cur.fetchone()[0]

            cur.execute("SELECT AVG(sifted_bits) FROM messages WHERE sifted_bits IS NOT NULL")
            avg_sifted_row = cur.fetchone()
            average_sifted_bits = float(avg_sifted_row[0]) if avg_sifted_row[0] is not None else 400.0

            cur.execute(
                """
                SELECT qber, created_at
                FROM (
                    SELECT qber, created_at FROM messages
                    UNION ALL
                    SELECT qber, created_at FROM eve_attempts
                ) AS combined
                ORDER BY created_at DESC
                LIMIT 10
                """
            )
            recent_rows = cur.fetchall()
            recent_qbers = [
                {
                    "qber": float(r[0]) if r[0] is not None else None,
                    "created_at": r[1].isoformat() if r[1] is not None else "",
                }
                for r in recent_rows
            ]

        return {
            "total_messages": total_messages,
            "average_qber": average_qber,
            "average_sifted_bits": average_sifted_bits,
            "threats_detected": threats_detected,
            "recent_qbers": recent_qbers,
        }
    finally:
        conn.close()