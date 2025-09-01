#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
MySQL IP Blocker Module (v2)
----------------------------
- Persistent IP blocks with expiration
- Periodic OS-level enforcement (iptables/netsh/pfctl)
- Safe auto-recovery + schema creation
- Threaded background sync

Requires:
    pip install mysql-connector-python
"""

import os
import time
import threading
import platform
import subprocess
from datetime import datetime, timedelta, timezone
from typing import Optional, List, Tuple, Dict

import mysql.connector
from mysql.connector import pooling

# =============================
# CONFIGURATION
# =============================
MYSQL_CONFIG = {
    "host": os.getenv("MYSQL_HOST", "127.0.0.1"),
    "port": int(os.getenv("MYSQL_PORT", 3306)),
    "user": os.getenv("MYSQL_USER", "root"),
    "password": os.getenv("MYSQL_PASSWORD", "changeme"),
    "database": os.getenv("MYSQL_DB", "admin"),
    "charset": "utf8mb4",
    "use_pure": True,
}

POOL_NAME = "ipblocker_pool"
POOL_SIZE = int(os.getenv("MYSQL_POOL_SIZE", "5"))
DEFAULT_TTL = int(os.getenv("BLOCK_TTL_SECONDS", "300"))
SYNC_INTERVAL = int(os.getenv("BLOCK_SYNC_INTERVAL", "30"))

# OS Detection
OS_NAME = platform.system().lower()
IS_LINUX = "linux" in OS_NAME
IS_WINDOWS = "windows" in OS_NAME
IS_MAC = "darwin" in OS_NAME

# =============================
# CLASS: MySQLIPBlocker
# =============================
class MySQLIPBlocker:
    """
    MySQL-backed IP blocker with timed TTL + OS enforcement.
    """

    def __init__(self, default_ttl_seconds: int = DEFAULT_TTL, sync_interval_sec: int = SYNC_INTERVAL):
        self.default_ttl = max(1, default_ttl_seconds)
        self.sync_interval = sync_interval_sec
        self._stop_event = threading.Event()
        self._known_applied = set()

        self.pool = pooling.MySQLConnectionPool(
            pool_name=POOL_NAME,
            pool_size=POOL_SIZE,
            **MYSQL_CONFIG
        )

        self._init_table()

    def _conn(self):
        return self.pool.get_connection()

    def _init_table(self):
        """Ensure table exists."""
        sql = """
        CREATE TABLE IF NOT EXISTS blocked_ips (
            id INT AUTO_INCREMENT PRIMARY KEY,
            ip VARCHAR(45) NOT NULL UNIQUE,
            reason VARCHAR(255),
            blocked_at DATETIME NOT NULL DEFAULT (UTC_TIMESTAMP()),
            expires_at DATETIME NOT NULL
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
        """
        with self._conn() as cnx:
            with cnx.cursor() as cur:
                cur.execute(sql)
            cnx.commit()

    def block_ip(self, ip: str, reason: str = "", ttl_seconds: Optional[int] = None):
        """Insert or update an IP block."""
        ttl = ttl_seconds or self.default_ttl
        expires = datetime.utcnow() + timedelta(seconds=ttl)
        sql = """
        INSERT INTO blocked_ips (ip, reason, expires_at)
        VALUES (%s, %s, %s)
        ON DUPLICATE KEY UPDATE reason=VALUES(reason), expires_at=VALUES(expires_at);
        """
        with self._conn() as cnx:
            with cnx.cursor() as cur:
                cur.execute(sql, (ip, reason, expires.replace(tzinfo=None)))
            cnx.commit()

        self._apply_os_block(ip)

    def unblock_ip(self, ip: str):
        """Unblock IP in DB and OS."""
        with self._conn() as cnx:
            with cnx.cursor() as cur:
                cur.execute("DELETE FROM blocked_ips WHERE ip = %s", (ip,))
            cnx.commit()
        self._remove_os_block(ip)

    def get_active_blocks(self) -> List[Tuple[str, str, datetime]]:
        """Return (ip, reason, expires_at) list."""
        sql = """
        SELECT ip, COALESCE(reason, ''), expires_at
        FROM blocked_ips
        WHERE expires_at > UTC_TIMESTAMP()
        ORDER BY expires_at ASC
        """
        with self._conn() as cnx:
            with cnx.cursor() as cur:
                cur.execute(sql)
                return cur.fetchall()

    def sweep_expired(self):
        """Remove expired blocks from DB and OS."""
        sql = "SELECT ip FROM blocked_ips WHERE expires_at <= UTC_TIMESTAMP()"
        delete = "DELETE FROM blocked_ips WHERE expires_at <= UTC_TIMESTAMP()"

        with self._conn() as cnx:
            with cnx.cursor() as cur:
                cur.execute(sql)
                expired = [r[0] for r in cur.fetchall()]
                cur.execute(delete)
            cnx.commit()

        for ip in expired:
            self._remove_os_block(ip)

    def start_background_sync(self):
        """Start background thread for syncing DB ↔ OS."""
        t = threading.Thread(target=self._sync_loop, daemon=True)
        t.start()

    def stop(self):
        """Signal thread to stop."""
        self._stop_event.set()

    def _sync_loop(self):
        while not self._stop_event.is_set():
            try:
                self.sweep_expired()
                active_ips = {ip for ip, _, _ in self.get_active_blocks()}

                # Add new
                for ip in active_ips:
                    if ip not in self._known_applied:
                        self._apply_os_block(ip)

                # Remove expired from OS
                for ip in list(self._known_applied - active_ips):
                    self._remove_os_block(ip)
            except Exception as e:
                print("[IPBlocker] Sync error:", e)

            self._stop_event.wait(self.sync_interval)

    # =============================
    # OS-LEVEL ENFORCEMENT
    # =============================
    def _apply_os_block(self, ip: str):
        if ip in self._known_applied:
            return

        if IS_LINUX:
            cmd = f"iptables -C INPUT -s {ip} -j DROP || iptables -A INPUT -s {ip} -j DROP"
        elif IS_WINDOWS:
            cmd = f'netsh advfirewall firewall add rule name="Block_{ip}" dir=in action=block remoteip={ip}'
        elif IS_MAC:
            cmd = f"echo 'block drop from {ip} to any' | sudo pfctl -ef -"
        else:
            return

        os.system(cmd)
        self._known_applied.add(ip)

    def _remove_os_block(self, ip: str):
        if ip not in self._known_applied:
            return

        if IS_LINUX:
            cmd = f"iptables -D INPUT -s {ip} -j DROP"
        elif IS_WINDOWS:
            cmd = f'netsh advfirewall firewall delete rule name="Block_{ip}"'
        elif IS_MAC:
            cmd = "sudo pfctl -F rules -f /etc/pf.conf"
        else:
            return

        os.system(cmd)
        self._known_applied.discard(ip)
