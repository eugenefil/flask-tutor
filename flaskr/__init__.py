import sqlite3
import os
import functools

from flask import (Flask, render_template, abort, request, g, redirect,
    url_for, flash, session)
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


# use `curl -X POST --data-urlencode 'username=foo' --data-urlencode 'password=bar' http://127.0.0.1:5000/register` to test POST
# use `nc -l -p 5000 127.0.0.1` to check what's being sent
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
                db.execute('insert into user (name, password) values (?, ?)',
                    (f['username'], h))
                db.commit()
            except sqlite3.IntegrityError:
                flash('User "{}" already exists'.format(f['username']))
            else:
                return redirect(url_for('login'))

    return render_template('register.html')


@app.route('/login', methods=('GET', 'POST'))
def login():
    if request.method == 'POST':
        f = request.form
        if 'username' not in f or not f['username']:
            flash('Username is required')
        elif 'password' not in f or not f['password']:
            flash('Password is required')
        else:
            user = get_db().execute(
                'select * from user where name = ?', (f['username'],)).fetchone()
            if user is None or not check_password_hash(user['password'], f['password']):
                flash('Invalid username or password')
            else:
                session.clear()
                session['user_id'] = user['id']
                return redirect(url_for('index'))

    return render_template('login.html')


@app.before_request
def load_user():
    uid = session.get('user_id')
    if uid:
        g.user = get_db().execute(
            'select * from user where id = ?', (uid,)).fetchone()


@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('index'))


@app.route('/')
def index():
    posts = get_db().execute('''
        select user.name user
            ,post.author_id
            ,post.id
            ,date(post.ctime, 'unixepoch') date
            ,post.title
            ,post.content
        from post inner join user on user.id = post.author_id
        order by post.ctime desc''').fetchall()
    return render_template('index.html', posts=posts)


def login_required(view):
    # functools.wraps copies original __name__ of a view to wrapper
    # otherwise wrapper will have __name__ 'wrapper' associated with
    # the route, so url_for(view) will fail
    @functools.wraps(view)
    def wrapper(*args, **kws):
        if 'user' in g: # was user data loaded by load_user()?
            return view(*args, **kws)
        return redirect(url_for('login'))
    return wrapper


@app.route('/create', methods=('GET', 'POST'))
@login_required
def create():
    if request.method == 'POST':
        title = request.form.get('title')
        content = request.form.get('content')
        if not title:
            flash('Title is required')
        elif not content:
            flash('Content is required')
        else:
            db = get_db()
            try:
                db.execute('pragma foreign_keys = on') # disabled by default
                db.execute(
                    'insert into post (author_id, title, content) values (?, ?, ?)',
                    (g.user['id'], title, content))
                db.commit()
            except sqlite3.IntegrityError:
                return redirect(url_for('logout'))
            else:
                return redirect(url_for('index'))

    return render_template('create.html')


# see https://flask.palletsprojects.com/en/3.0.x/api/#url-route-registrations
# for how to specify variable part of the url ('<int:post_id>' below)
@app.route('/update/<int:post_id>', methods=('GET', 'POST'))
@login_required
def update(post_id):
    db = get_db()
    post = db.execute('select * from post where id = ?', (post_id,)).fetchone()
    if post is None:
        abort(404)
    elif post['author_id'] != g.user['id']:
        abort(403)

    if request.method == 'POST':
        title = request.form.get('title')
        content = request.form.get('content')
        if not title:
            flash('Title is required')
        elif not content:
            flash('Content is required')
        else:
            db.execute('update post set title = ?, content = ? where id = ?',
                (title, content, post['id']))
            db.commit()
            return redirect(url_for('index'))

    return render_template('update.html', post=post)


os.makedirs(app.instance_path, exist_ok=True)
app.teardown_appcontext(close_db) # close db connection after request is processed
with app.app_context(): # create app context for g object in get_db()
    init_db(app)
