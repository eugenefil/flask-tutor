import sqlite3
import os

from flask import (Flask, render_template, abort, request, g, redirect,
    url_for, flash)
from werkzeug.security import check_password_hash, generate_password_hash

app = Flask(__name__)
app.config.from_mapping(SECRET_KEY='dev') # used for signing session cookies and flash()
dbpath = os.path.join(app.instance_path, 'db.sqlite')

def get_db():
    if 'db' not in g:
        g.db = sqlite3.connect(dbpath)
        g.db.row_factory = sqlite3.Row
    return g.db

def close_db(err):
    db = g.pop('db', None)
    if db is not None:
        db.close()

def init_db(app):
    if os.path.isfile(dbpath):
        return
    with app.open_resource('schema.sql', 'r') as f:
        script = f.read()
    db = get_db()
    db.executescript(script)
    db.commit()

@app.route('/register', methods=('GET', 'POST'))
def register():
    if request.method == 'POST':
        f = request.form
        if 'username' not in f or not f['username']:
            flash('Username is required')
        elif 'password' not in f or not f['password']:
            flash('Password is required')
        else:
            db = get_db()
            h = generate_password_hash(f['password'])
            try:
                db.execute('pragma foreign_keys = on') # disabled by default
                db.execute('insert into user (name, password) values (?, ?)',
                    (f['username'], h))
                db.commit()
            except sqlite3.IntegrityError:
                flash('User "{}" already exists'.format(f['username']))
            else:
                return redirect(url_for('login'))

    return render_template('register.html')

@app.route('/login')
def login():
    abort(404)

@app.route('/logout')
def logout():
    abort(404);

os.makedirs(app.instance_path, exist_ok=True)
app.teardown_appcontext(close_db) # close db connection after request is processed
with app.app_context(): # create app context for g object in get_db()
    init_db(app)
