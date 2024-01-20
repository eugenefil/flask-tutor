from flask import Flask
import sqlite3
import os

def init_db(app):
    dbpath = os.path.join(app.instance_path, 'db.sqlite')
    if os.path.isfile(dbpath):
        return
    with app.open_resource('schema.sql', 'r') as f:
        script = f.read()
    con = sqlite3.connect(dbpath)
    con.executescript(script)
    con.commit()
    con.close()

app = Flask(__name__)
os.makedirs(app.instance_path, exist_ok=True)
init_db(app)
