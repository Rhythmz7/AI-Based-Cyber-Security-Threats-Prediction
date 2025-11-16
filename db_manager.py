# utils/db.py

import os
import sqlite3
from typing import Optional, Union, Tuple, Dict, List

try:
    import psycopg2
except ImportError:
    psycopg2 = None

try:
    import mysql.connector
except ImportError:
    mysql = None


class Database:
    """
    Universal database wrapper.
    Supports SQLite (default), PostgreSQL, MySQL.
    Provides simple query() and insert() helpers.
    """

    def __init__(
        self,
        db_type: str = "sqlite",
        db_path: str = "database/siem.db",
        host: str = None,
        user: str = None,
        password: str = None,
        database: str = None,
        port: int = None,
    ):
        self.db_type = db_type.lower()
        self.connection = None

        os.makedirs(os.path.dirname(db_path), exist_ok=True)

        if self.db_type == "sqlite":
            self.connection = sqlite3.connect(db_path, check_same_thread=False)
            self.connection.row_factory = sqlite3.Row

        elif self.db_type == "postgres":
            if not psycopg2:
                raise ImportError("psycopg2 must be installed for PostgreSQL.")

            self.connection = psycopg2.connect(
                host=host,
                user=user,
                password=password,
                database=database,
                port=port or 5432,
            )

        elif self.db_type == "mysql":
            if not mysql:
                raise ImportError("mysql-connector-python must be installed for MySQL.")

            self.connection = mysql.connector.connect(
                host=host,
                user=user,
                password=password,
                database=database,
                port=port or 3306,
            )

        else:
            raise ValueError("db_type must be sqlite, postgres, or mysql")

        self.create_default_tables()

    # ----------------------------------------------------------------------
    # Create required SIEM database tables
    # ----------------------------------------------------------------------
    def create_default_tables(self):
        cursor = self.connection.cursor()

        # Logs table (Using SERIAL PRIMARY KEY for Postgres)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS logs (
                id SERIAL PRIMARY KEY,
                timestamp TEXT,
                src_ip TEXT,
                dst_ip TEXT,
                protocol TEXT,
                threat_type TEXT,
                severity INTEGER,
                raw_json TEXT
            );
        """)

        # Alerts table (Using SERIAL PRIMARY KEY for Postgres)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS alerts (
                id SERIAL PRIMARY KEY,
                timestamp TEXT,
                source_ip TEXT,
                threat_type TEXT,
                severity INTEGER,
                description TEXT
            );
        """)

        # Threat summary table (Using SERIAL PRIMARY KEY for Postgres)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS threat_summary (
                id SERIAL PRIMARY KEY,
                timestamp TEXT,
                threat_type TEXT,
                count INTEGER
            );
        """)

        self.connection.commit()

    # ----------------------------------------------------------------------
    # Run SELECT queries
    # ----------------------------------------------------------------------
    def query(self, q: str, params: tuple = ()):
        cur = self.connection.cursor()
        cur.execute(q, params)
        
        if self.db_type == "sqlite":
            rows = [dict(row) for row in cur.fetchall()]
        else:
            # For PostgreSQL & MySQL
            columns = [desc[0] for desc in cur.description]
            # Call fetchall() ONCE and store the result
            results = cur.fetchall() 
            # Now iterate over the stored result
            rows = [dict(zip(columns, row)) for row in results] 

        return rows
    # ----------------------------------------------------------------------
    # INSERT/UPDATE/DELETE
    # ----------------------------------------------------------------------
    def execute(self, q: str, params: tuple = ()):
        cur = self.connection.cursor()
        cur.execute(q, params)
        self.connection.commit()

    # ----------------------------------------------------------------------
    # Helpers for writing SIEM data
    # ----------------------------------------------------------------------
    def insert_log(self, ts: str, src: str, dst: str, proto: str, threat: str, severity: int, raw_json: str):
        self.execute(
            """
            INSERT INTO logs (timestamp, src_ip, dst_ip, protocol, threat_type, severity, raw_json)
            VALUES (%s, %s, %s, %s, %s, %s, %s)
            """,
            (ts, src, dst, proto, threat, severity, raw_json),
        )

    def insert_alert(self, ts: str, ip: str, threat: str, severity: int, desc: str):
        self.execute(
            """
            INSERT INTO alerts (timestamp, source_ip, threat_type, severity, description)
            VALUES (%s, %s, %s, %s, %s)
            """,
            (ts, ip, threat, severity, desc),
        )

    def insert_threat_summary(self, ts: str, threat: str, count: int):
        self.execute(
            """
            INSERT INTO threat_summary (timestamp, threat_type, count)
            VALUES (%s, %s, %s)
            """,
            (ts, threat, count),
        )

    # ----------------------------------------------------------------------
    # Close database connection
    # ----------------------------------------------------------------------
    def close(self):
        if self.connection:
            self.connection.close()



