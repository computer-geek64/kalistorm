#!/usr/bin/python3
# server.py

import os
import sqlite3
import hashlib
from pwd import getpwuid
from datetime import datetime
from markdown import markdown
from subprocess import Popen, PIPE
from flask import Flask, jsonify, redirect, request, render_template, send_from_directory, session, safe_join, stream_with_context, Response
from data import authenticate, get_permissions, get_bools, get_headers, get_size_string, create_videos_user, update_videos_user, delete_videos_user, generate_api_token, authorize
from music import get_youtube_music

app = Flask(__name__, template_folder="templates")
app.config.from_object("config")


# Decorator functions
def require_authenticated(func):
    def wrapper(*args, **kwargs):
        if "username" not in session.keys() or "password" not in session.keys():
            return error_403(403)
        if not authenticate(session["username"], session["password"]):
            return error_401(401)
        return func(*args, **kwargs)
    return wrapper


def require_permissions(required_permissions):
    def decorator(func):
        def wrapper(*args, **kwargs):
            permissions = get_permissions(session["username"])
            for permission in required_permissions:
                if not permissions[permission]:
                    return error_403(403)
            return func(*args, **kwargs)
        return wrapper
    return decorator


# Additional functions
def markdown_to_html(filename):
    with open(filename, "r") as file:
        content = file.read().replace("  ", "    ").replace("\\R", "\\mathbb{R}").replace("\\Q", "\\mathbb{Q}").replace("\\Z", "\\mathbb{Z}").replace("\\N", "\\mathbb{N}").replace("\\C", "\\mathbb{C}").replace("\\{", "\\\\{").replace("\\}", "\\\\}").replace("<", "&lt;").replace(">", "&gt;")
    while "\\begin{matrix}" in content:
        start = content.index("\\begin{matrix}")
        end = content.index("\\end{matrix}")
        table_data = "<tr>" + "</tr><tr>".join(["<td><div lang=\"latex\">" + "</div></td><td><div lang=\"latex\">".join(x.split("&")) + "</div></td>" for x in content[start + 14:end].split("\\\\")]) + "</tr>"
        content = content[:start + 14] + table_data + content[end:]
        content = content.replace("\\begin{matrix}", "</div><table>", 1).replace("\\end{matrix}", "</table><div lang=\"latex\">", 1)
    content = content.split("$")
    output = ""
    c = 0
    for i in range(len(content)):
        if i == len(content) - 1:
            output += content[i]
            break
        if not content[i].endswith("\\"):
            if c % 2 == 0:
                output += content[i] + "<div lang=\"latex\">"
            else:
                output += content[i] + "</div>"
            c += 1
        else:
            output += content[i][:-1] + "$"
    #content = output.split("|")
    #output = ""
    #for i in range(len(content)):
    #    if not content[i].endswith("\\"):
    #        output += ("<tr>" if content[i].count("\n") > 1 else "") + "<td>" + content[i] + "</td>"
    #    else:
    #        output += content[i][:-1] + "|"
    return markdown(output).replace("<code>", "<pre>").replace("</code>", "</pre>")


# Home
@app.route(app.config["HOME"], methods=["GET"])
def get_home():
    if "username" in session.keys() and "password" in session.keys() and authenticate(session["username"], session["password"]):
        return redirect("/dashboard"), 302
    return redirect("/login"), 302
    return render_template("home.html", title="Welcome to Ashish's Server"), 200
    #versions = list(map(lambda x: str(x), app.config["VERSIONS"]))[::-1]
    #return render_template("api_home.html", title=app.config["API_NAME"] + " | Home", versions=versions, API_NAME=app.config["API_NAME"])


# Public files
@app.route(safe_join(app.config["HOME"], "public") + "/", methods=["GET"])
def get_public_files_root_index():
    return get_public_files_index(".")


@app.route(safe_join(app.config["HOME"], "public", "<path:path>"), methods=["GET"])
def get_public_files_index(path):
    if not request.path.endswith("/"):
        return redirect(request.path + "/"), 302
    local_path = safe_join("/var/www/server/static", path)
    if not os.path.exists(local_path):
        return error_404(404)
    root, dirs, files = next(os.walk(local_path))
    items = []
    for item in sorted(dirs + files):
        if root == "/var/www/server/static/." and item == "assets":
            continue
        items.append({})
        items[-1]["name"] = safe_join("/", "static", path, item)
        items[-1]["name"] += "/" if item in dirs else ""
        items[-1]["size"] = os.path.getsize(safe_join(root, item))
        items[-1]["modified"] = str(datetime.fromtimestamp(os.path.getmtime(safe_join(root, item))).strftime("%Y-%m-%d %H:%M:%S"))
        items[-1]["owner"] = getpwuid(os.stat(safe_join(root, item)).st_uid).pw_name
    if "s" in request.args.keys() and request.args["s"] == "A":
        items = sorted(items, key=lambda k: k["name"])
        items.reverse()
    elif "s" in request.args.keys() and request.args["s"] == "s":
        items = sorted(items, key=lambda k: k["size"] if not k["name"].endswith("/") else 0)
    elif "s" in request.args.keys() and request.args["s"] == "S":
        items = sorted(items, key=lambda k: k["size"] if not k["name"].endswith("/") else 0)
        items.reverse()
    elif "s" in request.args.keys() and request.args["s"] == "m":
        items = sorted(items, key=lambda k: k["modified"])
    elif "s" in request.args.keys() and request.args["s"] == "M":
        items = sorted(items, key=lambda k: k["modified"])
        items.reverse()
    elif "s" in request.args.keys() and request.args["s"] == "o":
        items = sorted(items, key=lambda k: k["owner"])
    elif "s" in request.args.keys() and request.args["s"] == "O":
        items = sorted(items, key=lambda k: k["owner"])
        items.reverse()
    else:
        items = sorted(items, key=lambda k: k["name"])
    for i in range(len(items)):
        items[i]["size"] = get_size_string(items[i]["size"])
    path = "" if path == "." else path
    return render_template("public_file_index.html", root=path, files=items)


# Private files
@app.route(safe_join(app.config["HOME"], "files") + "/", methods=["GET"])
def get_files_root_index():
    return get_files_index(".")


@app.route(safe_join(app.config["HOME"], "files", "<path:path>"), methods=["GET"])
def get_files_index(path):
    if "username" not in session.keys() or "password" not in session.keys():
        return error_403(403)
    if not authenticate(session["username"], session["password"]):
        return error_401(401)
    permissions = get_permissions(session["username"])
    if not permissions["file_access"]:
        return error_403(403)
    local_path = safe_join("/", path)
    path = "" if path == "." else path
    if not os.path.exists(local_path):
        return error_404(404)
    if not os.path.isdir(local_path) and os.path.isfile(local_path):
        if os.path.splitext(local_path)[-1] == ".md":
            return render_template("markdown.html", markdown=markdown_to_html(local_path), title=os.path.basename(local_path), permissions=permissions, active_sidenav="files"), 200
        return send_from_directory(os.path.dirname(local_path), filename=os.path.basename(local_path)), 200
    if not request.path.endswith("/"):
        return redirect(request.path + "/"), 302
    root, dirs, files = next(os.walk(local_path))
    items = []
    for item in sorted(dirs + files):
        items.append({})
        items[-1]["name"] = safe_join("/", path, item)
        items[-1]["name"] += "/" if item in dirs else ""
        items[-1]["size"] = os.path.getsize(safe_join(root, item))
        items[-1]["modified"] = str(datetime.fromtimestamp(os.path.getmtime(safe_join(root, item))).strftime("%Y-%m-%d %H:%M:%S"))
        items[-1]["owner"] = getpwuid(os.stat(safe_join(root, item)).st_uid).pw_name
    if "s" in request.args.keys() and request.args["s"] == "A":
        items = sorted(items, key=lambda k: k["name"])
        items.reverse()
    elif "s" in request.args.keys() and request.args["s"] == "s":
        items = sorted(items, key=lambda k: k["size"] if not k["name"].endswith("/") else 0)
    elif "s" in request.args.keys() and request.args["s"] == "S":
        items = sorted(items, key=lambda k: k["size"] if not k["name"].endswith("/") else 0)
        items.reverse()
    elif "s" in request.args.keys() and request.args["s"] == "m":
        items = sorted(items, key=lambda k: k["modified"])
    elif "s" in request.args.keys() and request.args["s"] == "M":
        items = sorted(items, key=lambda k: k["modified"])
        items.reverse()
    elif "s" in request.args.keys() and request.args["s"] == "o":
        items = sorted(items, key=lambda k: k["owner"])
    elif "s" in request.args.keys() and request.args["s"] == "O":
        items = sorted(items, key=lambda k: k["owner"])
        items.reverse()
    else:
        items = sorted(items, key=lambda k: k["name"])
    for i in range(len(items)):
        items[i]["size"] = get_size_string(items[i]["size"])
    return render_template("file_index.html", title="Index of /" + path, root=path, files=items, permissions=permissions, active_sidenav="files"), 200


# Login
@app.route(safe_join(app.config["HOME"], "login"), methods=["GET"])
def get_login():
    if "login_attempts" in session.keys() and session["login_attempts"] > 2:
        return error_403(403)
    if "username" in session.keys() and "password" in session.keys() and authenticate(session["username"], session["password"]):
        return redirect("/dashboard"), 302
    return render_template("login.html"), 200


@app.route(safe_join(app.config["HOME"], "login"), methods=["POST"])
def post_login():
    if "login_attempts" in session.keys():
        if session["login_attempts"] > 2:
            return error_403(403)
        session["login_attempts"] = int(session["login_attempts"]) + 1
    else:
        session["login_attempts"] = 1
    data = {k: "".join(request.form[k]) for k in request.form.keys()}
    username = data["username"]
    password = data["password"]
    if not authenticate(username, password):
        if session["login_attempts"] > 2:
            return error_403(403)
        return error_401(401)
    session["username"] = username
    session["password"] = password
    session.pop("login_attempts")
    return redirect("/dashboard"), 302


# Logout
@app.route(safe_join(app.config["HOME"], "logout"), methods=["GET"])
def get_logout():
    if "username" not in session.keys() or "password" not in session.keys():
        return error_403(403)
    if not authenticate(session["username"], session["password"]):
        return error_401(401)
    session.clear()
    return redirect(app.config["HOME"]), 302

# Dashboard
@app.route(safe_join(app.config["HOME"], "dashboard"), methods=["GET"])
def get_dashboard():
    if "username" not in session.keys() or "password" not in session.keys():
        return error_403(403)
    if not authenticate(session["username"], session["password"]):
        return error_401(401)
    permissions = get_permissions(session["username"])
    date = datetime.now()
    current_date = date.strftime("%A, %B %-d")
    current_date += "th" if 4 <= date.day <= 20 or 24 <= date.day <= 30 else ["st", "nd", "rd"][date.day % 10 - 1]
    current_date += ", " + date.strftime("%Y")
    current_time = date.strftime("%-I:%M:%S %p")
    uptime = Popen(["uptime", "-p"], stdout=PIPE, stderr=PIPE).communicate()[0].decode().capitalize() + " since "
    uptime += datetime.strptime(Popen(["uptime", "-s"], stdout=PIPE, stderr=PIPE).communicate()[0].decode().strip(), "%Y-%m-%d %H:%M:%S").strftime("%a %b %d %-I:%M:%S %p")
    #raw_response_text = requests.get("http://wttr.in?0?T?q", timeout=5).text
    #weather = raw_response_text.split("\n")[1][15:].strip() + ", " + raw_response_text.split("\n")[2][15:].strip() + " in " + raw_response_text.split("\n")[0]
    system_info = Popen(["uname", "-snrmo"], stdout=PIPE, stderr=PIPE).communicate()[0].decode().strip()
    temperature = -1
    with open("/sys/class/thermal/thermal_zone0/temp", "r") as file:
        celsius = float(file.read()) / 1000
        temperature = round(celsius * 9 / 5 + 32, 2)
    updates = Popen(["aptitude", "search", "~U"], stdout=PIPE, stderr=PIPE).communicate()[0].decode().count("\n")
    services = [x == "active" for x in Popen(["systemctl", "is-active", "apache2", "ssh", "tor", "network-manager", "networking"], stdout=PIPE, stderr=PIPE).communicate()[0].decode().strip().split("\n")]
    services = {
        "Apache HTTP Server": services[0],
        "OpenSSH Server": services[1],
        "TOR Service": services[2],
        "Network Manager": services[3],
        "Networking": services[4]
    }
    who = Popen(["who", "--ips"], stdout=PIPE, stderr=PIPE).communicate()[0].decode().strip().split("\n")
    if who == [""]:
        who = []
    for i in range(len(who)):
        who[i] = [x for x in who[i].split(" ") if x]
        who[i][2] = who[i][2] + " " + who[i].pop(3)
    screens = Popen(["screen", "-ls"], stdout=PIPE, stderr=PIPE).communicate()[0].decode().strip()
    screens = [x.strip().split("\t") for x in screens.split("\n") if x.startswith("\t")] if screens.startswith("There") else False
    fs_info = [[y for y in x.split(" ") if y] for x in Popen(["df", "--output=source,fstype,size,used,avail,pcent,target", "-H", "-x", "tmpfs", "-x", "devtmpfs"], stdout=PIPE, stderr=PIPE).communicate()[0].decode().split("\n")[1:] if not ("fn" + "op"[::-1] + "nr"[::-1] + str(4))[2:-1] in x]
    return render_template("dashboard.html", current_date=current_date, current_time=current_time, uptime=uptime, system_info=system_info, temperature=temperature, updates=updates, services=services, who=who, screens=screens, fs_info=fs_info, title=session["username"].capitalize() + "\'s Dashboard", permissions=permissions, active_sidenav="dashboard"), 200


# Admin
@app.route(safe_join(app.config["HOME"], "admin", "table") + "/", methods=["GET"])
def get_admin_table_list():
    if "username" not in session.keys() or "password" not in session.keys():
        return error_403(403)
    if not authenticate(session["username"], session["password"]):
        return error_401(401)
    permissions = get_permissions(session["username"])
    if not permissions["admin"]:
        return error_403(403)
    conn = sqlite3.connect(app.config["DB_LOCATION"])
    cursor = conn.cursor()
    cursor.execute("SELECT name FROM sqlite_master WHERE type = \'table\';")
    tables = [x[0] for x in cursor.fetchall()]
    conn.close()
    return render_template("admin/table_list.html", tables=tables, title="Table List", permissions=permissions, active_sidenav="tables"), 200


@app.route(safe_join(app.config["HOME"], "admin", "table", "<string:table>"), methods=["GET"])
def get_admin_table(table):
    if "username" not in session.keys() or "password" not in session.keys():
        return error_403(403)
    if not authenticate(session["username"], session["password"]):
        return error_401(401)
    permissions = get_permissions(session["username"])
    if not permissions["admin"]:
        return error_403(403)
    conn = sqlite3.connect(app.config["DB_LOCATION"])
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM " + table + ";")
    query_response = cursor.fetchall()
    headers = [x[0] for x in cursor.description]
    conn.close()
    return render_template("admin/table.html", title=table.capitalize() + " Table", headers=headers, table=query_response, bools=get_bools("users"), permissions=permissions, active_sidenav="tables"), 200


@app.route(safe_join(app.config["HOME"], "admin", "table", "<string:table>"), methods=["POST"])
def post_admin_table(table):
    if "username" not in session.keys() or "password" not in session.keys():
        return error_403(403)
    if not authenticate(session["username"], session["password"]):
        return error_401(401)
    permissions = get_permissions(session["username"])
    if not permissions["admin"]:
        return error_403(403)
    conn = sqlite3.connect(app.config["DB_LOCATION"])
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM " + table + ";")
    query_response = cursor.fetchall()
    headers = [x[0] for x in cursor.description]
    data = {k: "".join(request.form[k]) for k in request.form.keys()}
    for name in data:
        i, j = name.split("-")
        cursor.execute("UPDATE " + table + " SET " + headers[int(j)] + " = \'" + data[name] + "\' WHERE " + headers[0] + " = \'" + query_response[int(i)][0] + "\';")
        conn.commit()
    conn.close()
    return get_admin_table(table)


@app.route(safe_join(app.config["HOME"], "admin", "users") + "/", methods=["GET"])
def get_users():
    if "username" not in session.keys() or "password" not in session.keys():
        return error_403(403)
    if not authenticate(session["username"], session["password"]):
        return error_401(401)
    permissions = get_permissions(session["username"])
    if not permissions["admin"]:
        return error_403(403)
    return render_template("admin/users.html", title="Users", permissions=permissions, active_sidenav="users"), 200


@app.route(safe_join(app.config["HOME"], "admin", "users", "create"), methods=["GET"])
def get_user_create():
    if "username" not in session.keys() or "password" not in session.keys():
        return error_403(403)
    if not authenticate(session["username"], session["password"]):
        return error_401(401)
    permissions = get_permissions(session["username"])
    if not permissions["admin"]:
        return error_403(403)
    return render_template("admin/user_create.html", title="Create User", headers=get_headers("users"), bools=get_bools("users"), permissions=permissions, active_sidenav="users"), 200


@app.route(safe_join(app.config["HOME"], "admin", "users", "create"), methods=["POST"])
def post_user_create():
    if "username" not in session.keys() or "password" not in session.keys():
        return error_403(403)
    if not authenticate(session["username"], session["password"]):
        return error_401(401)
    permissions = get_permissions(session["username"])
    if not permissions["admin"]:
        return error_403(403)
    data = {k: "".join(request.form[k]) for k in request.form.keys()}
    create_videos_user(data["user"], data["pass"])
    data["pass"] = hashlib.sha256((app.config["SHA256_SALT"] + data["pass"]).encode()).hexdigest()
    for k in data.keys():
        if type(data[k]) == list:
            data[k] = str(data[k][0])
        if not data[k].replace(".", "", 1).isdigit():
            data[k] = "\'" + data[k] + "\'"
    conn = sqlite3.connect(app.config["DB_LOCATION"])
    cursor = conn.cursor()
    cursor.execute("INSERT INTO users (" + ", ".join(data.keys()) + ") VALUES (" + ", ".join(data.values()) + ");")
    conn.commit()
    conn.close()
    return get_user_create()


@app.route(safe_join(app.config["HOME"], "admin", "users", "delete"), methods=["GET"])
def get_user_delete():
    if "username" not in session.keys() or "password" not in session.keys():
        return error_403(403)
    if not authenticate(session["username"], session["password"]):
        return error_401(401)
    permissions = get_permissions(session["username"])
    if not permissions["admin"]:
        return error_403(403)
    conn = sqlite3.connect(app.config["DB_LOCATION"])
    cursor = conn.cursor()
    cursor.execute("SELECT user FROM users;")
    users = [x[0] for x in cursor.fetchall()]
    conn.close()
    return render_template("admin/user_get.html", title="Delete User", users=users, permissions=permissions, active_sidenav="users"), 200


@app.route(safe_join(app.config["HOME"], "admin", "users", "delete"), methods=["POST"])
def post_user_delete():
    if "username" not in session.keys() or "password" not in session.keys():
        return error_403(403)
    if not authenticate(session["username"], session["password"]):
        return error_401(401)
    permissions = get_permissions(session["username"])
    if not permissions["admin"]:
        return error_403(403)
    data = {k: "".join(request.form[k]) for k in request.form.keys()}
    conn = sqlite3.connect(app.config["DB_LOCATION"])
    cursor = conn.cursor()
    cursor.execute("DELETE FROM users WHERE user = \'" + data["user"] + "\';")
    conn.commit()
    conn.close()
    delete_videos_user(data["user"])
    return get_user_delete()


@app.route(safe_join(app.config["HOME"], "admin", "users", "edit"), methods=["GET"])
def get_user_edit():
    if "username" not in session.keys() or "password" not in session.keys():
        return error_403(403)
    if not authenticate(session["username"], session["password"]):
        return error_401(401)
    permissions = get_permissions(session["username"])
    if not permissions["admin"]:
        return error_403(403)
    conn = sqlite3.connect(app.config["DB_LOCATION"])
    cursor = conn.cursor()
    cursor.execute("SELECT user FROM users;")
    users = [x[0] for x in cursor.fetchall()]
    conn.close()
    return render_template("admin/user_get.html", title="Edit User", users=users, permissions=permissions, active_sidenav="users"), 200


@app.route(safe_join(app.config["HOME"], "admin", "users", "edit"), methods=["POST"])
def post_user_edit():
    if "username" not in session.keys() or "password" not in session.keys():
        return error_403(403)
    if not authenticate(session["username"], session["password"]):
        return error_401(401)
    permissions = get_permissions(session["username"])
    if not permissions["admin"]:
        return error_403(403)
    data = {k: "".join(request.form[k]) for k in request.form.keys()}
    if "username" not in data.keys():
        conn = sqlite3.connect(app.config["DB_LOCATION"])
        cursor = conn.cursor()
        cursor.execute("PRAGMA table_info(users);")
        bools = [x[1] for x in cursor.fetchall() if x[2].upper() == "CHAR"]
        user = data["user"]
        cursor.execute("SELECT * FROM users WHERE user = \'" + user + "\';")
        table_data = cursor.fetchall()[0]
        headers = [x[0] for x in cursor.description]
        conn.close()
        return render_template("admin/user_edit.html", title="Edit User", headers=headers, bools=bools, data=table_data, user=user, permissions=permissions, active_sidenav="users"), 200
    else:
        conn = sqlite3.connect(app.config["DB_LOCATION"])
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users;")
        cursor.fetchall()
        data = {k: "".join(request.form[k]) for k in request.form.keys()}
        username = data.pop("username")
        if "pass" in data.keys():
            data["pass"] = hashlib.sha256((app.config["SHA256_SALT"] + data["pass"]).encode()).hexdigest()
            update_videos_user(username, data["pass"])
        cursor.execute("UPDATE users SET " + ", ".join([x + " = \'" + data[x] + "\'" for x in data.keys() if x != "username"]) + " WHERE user = \'" + username + "\';")
        conn.commit()
        conn.close()
        return get_user_edit()


# Power
@app.route(safe_join(app.config["HOME"], "power") + "/", methods=["GET"])
def get_power():
    if "username" not in session.keys() or "password" not in session.keys():
        return error_403(403)
    if not authenticate(session["username"], session["password"]):
        return error_401(401)
    permissions = get_permissions(session["username"])
    if not permissions["power"]:
        return error_403(403)
    return render_template("power/power.html", title="Power", permissions=permissions, active_sidenav="power"), 200


@app.route(safe_join(app.config["HOME"], "power", "<string:action>"), methods=["GET", "POST"])
def power_action(action):
    if "username" not in session.keys() or "password" not in session.keys():
        return error_403(403)
    if not authenticate(session["username"], session["password"]):
        return error_401(401)
    permissions = get_permissions(session["username"])
    if not permissions["power"]:
        return error_403(403)
    minutes = "now"
    data = {k: "".join(request.form[k]) for k in request.form.keys()}
    if "time" in request.args:
        try:
            int(request.args["time"])
            minutes = request.args["time"]
        except ValueError:
            return render_template("power/power.html", message="Invalid number", title="Power", permissions=permissions, active_sidenav="power"), 200
    if "time" in data:
        try:
            int(data["time"])
            minutes = data["time"]
        except ValueError:
            return render_template("power/power.html", message="Invalid number", title="Power", permissions=permissions, active_sidenav="power"), 200
    if action == "shutdown":
        Popen(["/usr/bin/sudo", "/usr/sbin/shutdown", "-P", minutes], stderr=PIPE, stdout=PIPE)
    elif action == "restart":
        Popen(["/usr/bin/sudo", "/usr/sbin/shutdown", "-r", minutes], stdout=PIPE, stderr=PIPE)
    else:
        return error_404(404)
    return render_template("power/power.html", message=action.capitalize() + " scheduled", title="Power", permissions=permissions, active_sidenav="power"), 200


# Videos
@app.route(safe_join(app.config["HOME"], "videos") + "/", methods=["GET"])
def get_videos():
    if "username" not in session.keys() or "password" not in session.keys():
        return error_403(403)
    if not authenticate(session["username"], session["password"]):
        return error_401(401)
    permissions = get_permissions(session["username"])
    return render_template("videos/videos.html", title="Videos", permissions=permissions, active_sidenav="videos"), 200


@app.route(safe_join(app.config["HOME"], "videos", "movies") + "/", methods=["GET"])
def get_movies():
    if "username" not in session.keys() or "password" not in session.keys():
        return error_403(403)
    if not authenticate(session["username"], session["password"]):
        return error_401(401)
    permissions = get_permissions(session["username"])
    movies = [x.split(os.path.join(app.config["VIDEOS_LOCATION"], "movies") + "/")[-1] for x in Popen(["find", os.path.join(app.config["VIDEOS_LOCATION"], "movies"), "-name", "*.mp4"], stdout=PIPE, stderr=PIPE).communicate()[0].decode().strip().split("\n")]
    movies = sorted([[x, os.path.basename(os.path.splitext(x)[0])] for x in movies])
    return render_template("videos/movies.html", title="Movies", movies=movies, permissions=permissions, active_sidenav="videos"), 200


@app.route(safe_join(app.config["HOME"], "videos", "movies", "<path:path>"), methods=["GET"])
def get_movie(path):
    if "username" not in session.keys() or "password" not in session.keys():
        return error_403(403)
    if not authenticate(session["username"], session["password"]):
        return error_401(401)
    permissions = get_permissions(session["username"])
    local_path = os.path.join(app.config["VIDEOS_LOCATION"], "movies", path)
    if not os.path.exists(local_path):
        return error_404(404)
    if os.path.exists(os.path.join(app.config["VIDEOS_LOCATION"], "movies", "Subtitles", os.path.splitext(path)[0] + " Subtitles.vtt")):
        subtitles = safe_join("/videos/movies/subtitles", path)
    else:
        subtitles = None
    #return render_template("videos/movie.html", movie=safe_join("http://" + app.config["VIDEOS_USERNAME"] + ":" + app.config["VIDEOS_PASSWORD"] + "@" + request.host.split(":")[0] + ":81", "movies", path), subtitles=subtitles, title=os.path.splitext(os.path.basename(local_path))[0], permissions=permissions, active_sidenav="videos"), 200
    return render_template("videos/movie.html", movie=safe_join("http://" + session["username"] + ":" + session["password"] + "@" + request.host.split(":")[0] + ":81", "movies", path), subtitles=subtitles, title=os.path.splitext(os.path.basename(local_path))[0], permissions=permissions, active_sidenav="videos"), 200


@app.route(safe_join(app.config["HOME"], "videos", "movies", "subtitles", "<path:path>"), methods=["GET"])
def get_movie_subtitles(path):
    if "username" not in session.keys() or "password" not in session.keys():
        return error_403(403)
    if not authenticate(session["username"], session["password"]):
        return error_401(401)
    permissions = get_permissions(session["username"])
    local_path = os.path.join(app.config["VIDEOS_LOCATION"], "movies", "Subtitles", os.path.splitext(path)[0] + " Subtitles.vtt")
    if not os.path.exists(local_path):
        return error_404(404)
    return send_from_directory(os.path.split(local_path)[0], filename=os.path.basename(local_path)), 200


# Music
@app.route(safe_join(app.config["HOME"], "music") + "/", methods=["GET"])
def get_music():
    if "username" not in session.keys() or "password" not in session.keys():
        return error_403(403)
    if not authenticate(session["username"], session["password"]):
        return error_401(401)
    permissions = get_permissions(session["username"])
    music = {}
    for root, dirs, files in os.walk(app.config["MUSIC_LOCATION"]):
        music.update({x: safe_join("/music", "src", x) for x in files if x.endswith(".mp3")})
    return render_template("music/music.html", music=music, title="Music", permissions=permissions, active_sidenav="music"), 200


@app.route(safe_join(app.config["HOME"], "music") + "/", methods=["POST"])
def post_music():
    if "username" not in session.keys() or "password" not in session.keys():
        return error_403(403)
    if not authenticate(session["username"], session["password"]):
        return error_401(401)
    permissions = get_permissions(session["username"])
    data = {k: "".join(request.form[k]) for k in request.form.keys()}
    if "url" in data:
        get_youtube_music(data["url"], app.config["MUSIC_DOWNLOAD_LOCATION"])
    return get_music()


@app.route(safe_join(app.config["HOME"], "music", "src", "<path:path>"), methods=["GET"])
def get_music_source(path):
    if "username" not in session.keys() or "password" not in session.keys():
        return error_403(403)
    if not authenticate(session["username"], session["password"]):
        return error_401(401)
    permissions = get_permissions(session["username"])
    for root, dirs, files in os.walk(app.config["MUSIC_LOCATION"]):
        if path in files:
            return send_from_directory(root, filename=path)
    return error_404(404)



# API Endpoints
@app.route(safe_join(app.config["HOME"], app.config["API_NAME"].lower(), "api") + "/", methods=["GET"])
def get_api_endpoint():
    return "Welcome to the " + app.config["API_NAME"] + " API!"\
           "<br>This API is currently under development, and is not yet intended for stable use."


@app.route(safe_join(app.config["HOME"], app.config["API_NAME"].lower(), "api", "generate_token"), methods=["POST"])
def post_api_generate_token():
    response = {
        "authenticated": False,
        "status_code": 400
    }
    data = {k: "".join(request.form[k]) for k in request.form.keys()}
    if "username" not in data or "password" not in data:
        response["status_code"] = 403
        return jsonify(response), response["status_code"]
    if not authenticate(data["username"], data["password"]):
        response["status_code"] = 401
        return jsonify(response), response["status_code"]
    response["authenticated"] = True
    response["status_code"] = 200
    token = generate_api_token(data["username"])
    response["auth_token"] = token
    return jsonify(response), response["status_code"]


@app.route(safe_join(app.config["HOME"], app.config["API_NAME"].lower(), "api", "test_token"), methods=["GET"])
def get_api_test_token():
    response = {
        "authenticated": False,
        "status_code": 400
    }
    if "token" not in request.args:
        response["status_code"] = 403
        return jsonify(response), response["status_code"]
    if not authorize(request.args["token"]):
        response["status_code"] = 401
        return jsonify(response), response["status_code"]
    response["authenticated"] = True
    response["status_code"] = 200
    return jsonify(response), response["status_code"]


@app.route(safe_join(app.config["HOME"], app.config["API_NAME"].lower(), "api", "services"), methods=["GET"])
def get_api_services():
    response = {
        "authenticated": False,
        "status_code": 400
    }
    if "token" not in request.args:
        response["status_code"] = 403
        return jsonify(response), response["status_code"]
    if not authorize(request.args["token"]):
        response["status_code"] = 401
        return jsonify(response), response["status_code"]
    response["authenticated"] = True
    response["status_code"] = 200
    services = [x == "active" for x in Popen(["systemctl", "is-active", "apache2", "ssh", "tor", "network-manager", "networking"], stdout=PIPE, stderr=PIPE).communicate()[0].decode().strip().split("\n")]
    services = {
        "apache2": services[0],
        "ssh": services[1],
        "tor": services[2],
        "network-manager": services[3],
        "networking": services[4]
    }
    response["services"] = services
    return jsonify(response), response["status_code"]


@app.route(safe_join(app.config["HOME"], app.config["API_NAME"].lower(), "api", "movies"), methods=["GET"])
def get_api_movies():
    response = {
        "authenticated": False,
        "status_code": 400
    }
    if "token" not in request.args:
        response["status_code"] = 403
        return jsonify(response), response["status_code"]
    if not authorize(request.args["token"]):
        response["status_code"] = 401
        return jsonify(response), response["status_code"]
    response["authenticated"] = True
    response["status_code"] = 200
    if 'movie' in request.args.keys():
        movie = request.args['movie']
        movies = [x.split(os.path.join(app.config["VIDEOS_LOCATION"], "movies") + "/")[-1] for x in Popen(["find", os.path.join(app.config["VIDEOS_LOCATION"], "movies"), "-name", "*" + movie + ".mp4"], stdout=PIPE, stderr=PIPE).communicate()[0].decode().strip().split("\n")]
        local_path = os.path.join(app.config["VIDEOS_LOCATION"], "movies", "Subtitles", os.path.splitext(movies[0])[0] + " Subtitles.srt")
        if os.path.exists(local_path):
            response['subtitles'] = os.path.splitext(movies[0])[0] + ' Subtitles.srt'
        response['path'] = movies[0]
        return jsonify(response), response['status_code']
    movies = [x.split(os.path.join(app.config["VIDEOS_LOCATION"], "movies") + "/")[-1] for x in Popen(["find", os.path.join(app.config["VIDEOS_LOCATION"], "movies"), "-name", "*.mp4"], stdout=PIPE, stderr=PIPE).communicate()[0].decode().strip().split("\n")]
    movies = sorted([{'path': x, 'name': os.path.basename(os.path.splitext(x)[0])} for x in movies], key=lambda x: x['path'])
    response["movies"] = movies
    return jsonify(response), response["status_code"]


@app.route(safe_join(app.config["HOME"], app.config["API_NAME"].lower(), "api", "shutdown"), methods=["GET"])
def get_shutdown():
    response = {
        "authenticated": False,
        "status_code": 400
    }
    if "token" not in request.args:
        response["status_code"] = 403
        return jsonify(response), response["status_code"]
    if request.args['token'] == app.config['ROOT_TOKEN']:
        Popen(["/usr/bin/sudo", "/usr/sbin/shutdown", "-P", "0"], stderr=PIPE, stdout=PIPE)
    return jsonify(response), response['status_code']


# API Docs
@app.route(safe_join(app.config["HOME"], app.config["API_NAME"].lower(), "api", "docs") + "/", methods=["GET"])
def get_docs():
    content = [
        {
            "title": "Generate Auth Token",
            "request_type": "POST",
            "url": safe_join(app.config["HOME"], app.config["API_NAME"].lower(), "api", "generate_token"),
            "description": "Generate an authorization token for API use. This endpoint requires authentication to prove the user is valid and exists in the system.",
            "request": [
                {
                    "parameter": "username",
                    "type": "string",
                    "position": "body",
                    "required": "yes",
                    "description": "Username of an authenticated user."
                },
                {
                    "parameter": "password",
                    "type": "string",
                    "position": "body",
                    "required": "yes",
                    "description": "Password of an authenticated user."
                }
            ],
            "response": """{
    "authenticated": true,
    "status_code": 200,
    "auth_token": "YIhmQraMfO45XUgRushZw6IKRcNfsG8aY_oqLyOI0Yw"
}"""
        },
        {
            "title": "Test Auth Token",
            "request_type": "GET",
            "url": safe_join(app.config["HOME"], app.config["API_NAME"].lower(), "api", "test_token"),
            "description": "Test an authorization token to determine if it is valid.",
            "request": [
                {
                    "parameter": "token",
                    "type": "string",
                    "position": "header",
                    "required": "yes",
                    "description": "Authorization token"
                }
            ],
            "response": """{
    "authenticated": true,
    "status_code": 200
}"""
        },
        {
            "title": "Get Statuses of Services",
            "request_type": "GET",
            "url": safe_join(app.config["HOME"], app.config["API_NAME"].lower(), "api", "services"),
            "description": "Retrieve the statuses of publicly listed services.",
            "request": [
                {
                    "parameter": "token",
                    "type": "string",
                    "position": "header",
                    "required": "yes",
                    "description": "Authorization token"
                }
            ],
            "response": """{
    "authenticated": true,
    "status_code": 200,
    "services": {
        "apache2": true,
        "ssh": true,
        "tor": false,
        "network-manager": true,
        "networking": true
    }
}"""
        }
    ]
    return render_template("docs.html", API_NAME=app.config["API_NAME"], content=content)


# Error handlers
@app.errorhandler(404)
def error_404(e):
    return render_template("error_templates/404.html"), 404


@app.errorhandler(400)
def error_400(e):
    return "HTTP 400 - Bad Request", 400


@app.errorhandler(500)
def error_500(e):
    return render_template("error_templates/500.html"), 500


@app.errorhandler(403)
def error_403(e):
    return render_template("error_templates/403.html"), 403


@app.errorhandler(401)
def error_401(e):
    return render_template("error_templates/401.html")


if __name__ == "__main__":
    app.run(app.config["IP"], app.config["PORT"])
