#!/usr/bin/python3
# data.py

import os
import sqlite3
import hashlib
import secrets
import youtube_dl
from subprocess import Popen, PIPE
from config import DB_LOCATION, SHA256_SALT, VIDEOS_LOCATION


def authenticate(username, password):
    conn = sqlite3.connect(DB_LOCATION)
    cursor = conn.cursor()
    cursor.execute("SELECT pass FROM users WHERE user=\'" + username + "\';")
    query_response = cursor.fetchall()
    conn.close()
    if len(query_response) > 0:
        password_hash = hashlib.sha256((SHA256_SALT + password).encode()).hexdigest()
        if password_hash == query_response[0][0]:
            return True
    return False


def get_permissions(username):
    permissions = {}
    conn = sqlite3.connect(DB_LOCATION)
    cursor = conn.cursor()
    cursor.execute("PRAGMA table_info(users);")
    bools = [x[1] for x in cursor.fetchall() if x[2].upper() == "CHAR"]
    for var in bools:
        cursor.execute("SELECT " + var + " FROM users WHERE user = \'" + username + "\';")
        permissions[var] = cursor.fetchall()[0][0].lower() == "y"
    conn.close()
    return permissions


def get_bools(table):
    conn = sqlite3.connect(DB_LOCATION)
    cursor = conn.cursor()
    cursor.execute("PRAGMA table_info(" + table + ");")
    bools = [x[1] for x in cursor.fetchall() if x[2].upper() == "CHAR"]
    conn.close()
    return bools


def get_headers(table):
    conn = sqlite3.connect(DB_LOCATION)
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM " + table + ";")
    cursor.fetchall()
    headers = [x[0] for x in cursor.description]
    conn.close()
    return headers


def get_size_string(size):
    units = ["B", "KB", "MB", "GB", "TB"]
    length = len(str(size))
    if length % 3 == 0:
        number = str(size)[:(length % 3) + 3]
        unit = units[int(length / 3) - 1]
    else:
        number = str(size)[:length % 3]
        unit = units[int(length / 3)]
    return number + " " + unit


def create_videos_user(username, password):
    filename = os.path.join(VIDEOS_LOCATION, ".htpasswd")
    Popen(["htpasswd", "-i", filename, username], stdin=PIPE, stdout=PIPE, stderr=PIPE).communicate(input=password.encode())


def update_videos_user(username, password):
    delete_videos_user(username)
    create_videos_user(username, password)


def delete_videos_user(username):
    filename = os.path.join(VIDEOS_LOCATION, ".htpasswd")
    Popen(["htpasswd", "-D", filename, username], stdout=PIPE, stderr=PIPE)


def generate_api_token(user):
    conn = sqlite3.connect(DB_LOCATION)
    cursor = conn.cursor()
    if user:
        cursor.execute("SELECT token FROM tokens WHERE user = \"" + user + "\";")
        query_response = cursor.fetchall()
        if len(query_response) > 0:
            return query_response[0][0]
        token = secrets.token_urlsafe()
        cursor.execute("INSERT INTO tokens (token, user) VALUES (\"" + token + "\", \"" + user + "\");")
        conn.commit()
        conn.close()
        return token
    token = secrets.token_urlsafe()
    cursor.execute("INSERT INTO tokens (token, user) VALUES (\"" + token + "\", \"\");")
    conn.commit()
    conn.close()
    return token


def authorize(token):
    conn = sqlite3.connect(DB_LOCATION)
    cursor = conn.cursor()
    cursor.execute("SELECT token FROM tokens WHERE token = \"" + token + "\";")
    query_response = cursor.fetchall()
    conn.close()
    return len(query_response) > 0
