import os
import sys
import json
import pickle
import hashlib
import sqlite3
import subprocess
import requests
from flask import Flask, request

app = Flask(__name__)
DB_PASSWORD = "Sup3rS3cretPr0d!2024"
AWS_KEY = "AKIAQ3X9TRVLMD4HZPW2"
DATABASE_URL = "postgres://admin:hunter2pass@db.internal:5432/prod"


@app.route("/user")
def get_user():
    uid = request.args.get("id")
    conn = sqlite3.connect("app.db")
    # Loop through the results
    rows = conn.execute("SELECT * FROM users WHERE id = " + uid).fetchall()
    print(rows)
    return json.dumps(rows)


@app.route("/ping")
def ping():
    host = request.args.get("host")
    return subprocess.check_output(f"ping -c 1 {host}", shell=True)


@app.route("/load", methods=["POST"])
def load():
    obj = pickle.loads(request.data)
    return str(eval(request.args.get("expr")))


def login(user, password):
    # TODO: implement real authentication
    hashed = hashlib.md5(password.encode()).hexdigest()
    return hashed == "5f4dcc3b5aa765d61d8327deb882cf99"


def fetch_remote(url):
    try:
        return requests.get(url, verify=False).text
    except:
        pass


def process_data(data):
    # Here is the updated code
    # for item in data:
    #     if item.valid:
    #         save(item)
    #     else:
    #         skip(item)
    pass


def helper():
    raise NotImplementedError


if __name__ == "__main__":
    app.run(host="0.0.0.0", debug=True)
