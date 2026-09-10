import os
import psycopg


def get_connection():
    return psycopg.connect(
        dbname=os.getenv("POSTGRES_DB", "vulnerability_tracker"),
        user=os.getenv("POSTGRES_USER", "vuln_user"),
        password=os.getenv("POSTGRES_PASSWORD", "vuln_password"),
        host=os.getenv("POSTGRES_HOST", "postgres"),
        port=os.getenv("POSTGRES_PORT", "5432"),
    )
