import os

import psycopg


class DatabaseConfigError(RuntimeError):
    pass


def get_database_url() -> str:
    url = os.environ.get("DEVAI_DATABASE_URL", "").strip()

    if not url:
        raise DatabaseConfigError(
            "DEVAI_DATABASE_URL is not configured"
        )

    return url


def connect():
    return psycopg.connect(
        get_database_url(),
        connect_timeout=5,
        application_name="devai-controller",
    )
