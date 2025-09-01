#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
SecureAuth - MySQL-backed user authentication module
-----------------------------------------------------
- SHA256 + Base64 password hashing (with salt)
- Environment-based MySQL connection
- Functions: create_user(), verify_user(), update_password()
"""

import os
import hashlib
import base64
import mysql.connector
import traceback
from typing import Optional
from mysql.connector import pooling

# ==========================
# CONFIGURATION
# ==========================
MYSQL_CONFIG = {
    "host": os.getenv("MYSQL_HOST", "127.0.0.1"),
    "port": int(os.getenv("MYSQL_PORT", 3306)),
    "user": os.getenv("MYSQL_USER", "admin"),
    "password": os.getenv("MYSQL_PASSWORD", "changeme"),
    "database": os.getenv("MYSQL_DB", "admin"),
    "charset": "utf8mb4",
    "autocommit": True
}

POOL_SIZE = int(os.getenv("MYSQL_POOL_SIZE", "3"))

# ==========================
# CONNECTION POOL
# ==========================
try:
    POOL = pooling.MySQLConnectionPool(
        pool_name="secureauth_pool",
        pool_size=POOL_SIZE,
        **MYSQL_CONFIG
    )
except Exception as e:
    print(f"❌ Failed to connect to MySQL: {e}")
    raise

# ==========================
# PASSWORD FUNCTIONS
# ==========================
def hash_password(password: str, salt: str) -> str:
    """Returns base64(SHA256(salt + password))"""
    combined = (salt + password).encode("utf-8")
    digest = hashlib.sha256(combined).digest()
    return base64.b64encode(digest).decode("utf-8")

# ==========================
# CORE USER AUTH
# ==========================
def get_user(username: str) -> Optional[dict]:
    try:
        cnx = POOL.get_connection()
        cur = cnx.cursor(dictionary=True)
        cur.execute("SELECT * FROM users WHERE username = %s", (username,))
        user = cur.fetchone()
        cur.close()
        cnx.close()
        return user
    except Exception:
        print("❌ get_user error:", traceback.format_exc())
        return None

def verify_user(username: str, password: str) -> bool:
    user = get_user(username)
    if not user:
        return False
    try:
        expected_hash = user["password_hash"]
        salt = user.get("salt", "") or ""
        return hash_password(password, salt) == expected_hash
    except Exception:
        print("❌ verify_user error:", traceback.format_exc())
        return False

def create_user(username: str, password: str) -> bool:
    """Creates a user with salted password hash"""
    if get_user(username):
        print("⚠️ User already exists")
        return False
    salt = base64.b64encode(os.urandom(8)).decode("utf-8")
    pw_hash = hash_password(password, salt)
    try:
        cnx = POOL.get_connection()
        cur = cnx.cursor()
        cur.execute(
            "INSERT INTO users (username, password_hash, salt, is_active) VALUES (%s, %s, %s, 1)",
            (username, pw_hash, salt)
        )
        cur.close()
        cnx.commit()
        cnx.close()
        print(f"✅ User '{username}' created")
        return True
    except Exception:
        print("❌ create_user error:", traceback.format_exc())
        return False

def update_password(username: str, new_password: str) -> bool:
    """Update a user's password with new salt + hash"""
    if not get_user(username):
        print("❌ User not found")
        return False
    new_salt = base64.b64encode(os.urandom(8)).decode("utf-8")
    new_hash = hash_password(new_password, new_salt)
    try:
        cnx = POOL.get_connection()
        cur = cnx.cursor()
        cur.execute(
            "UPDATE users SET password_hash = %s, salt = %s WHERE username = %s",
            (new_hash, new_salt, username)
        )
        cur.close()
        cnx.commit()
        cnx.close()
        print(f"🔑 Password updated for {username}")
        return True
    except Exception:
        print("❌ update_password error:", traceback.format_exc())
        return False

# ==========================
# TEST ENTRY
# ==========================
if __name__ == "__main__":
    print("🔒 SecureAuth test mode")
    print("Create user: ", create_user("admin", "admin"))
    print("Login test: ", verify_user("admin", "admin"))
    print("Update password: ", update_password("admin", "newpass"))
    print("Login after update: ", verify_user("admin", "newpass"))
