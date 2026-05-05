import sqlite3
import os
from flask import Flask, render_template, request, redirect, url_for, session, g, flash
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps

app = Flask(__name__)

# Persist secret key across restarts without hardcoding it
_key_file = os.path.join(os.path.dirname(os.path.abspath(__file__)), '.secret_key')
if os.path.exists(_key_file):
    with open(_key_file, 'rb') as f:
        app.secret_key = f.read()
else:
    _key = os.urandom(24)
    with open(_key_file, 'wb') as f:
        f.write(_key)
    app.secret_key = _key

DATABASE = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'notes.db')


# ── Database helpers ──────────────────────────────────────────────────────────

def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect(DATABASE)
        db.row_factory = sqlite3.Row
    return db


@app.teardown_appcontext
def close_db(exception):
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()


def init_db():
    with sqlite3.connect(DATABASE) as db:
        db.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id       INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT    UNIQUE NOT NULL,
                password TEXT    NOT NULL
            )
        ''')
        db.execute('''
            CREATE TABLE IF NOT EXISTS notes (
                id         INTEGER   PRIMARY KEY AUTOINCREMENT,
                user_id    INTEGER   NOT NULL,
                title      TEXT      NOT NULL,
                body       TEXT      NOT NULL DEFAULT '',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users(id)
            )
        ''')
        db.commit()


# ── Auth decorator ────────────────────────────────────────────────────────────

def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated


# ── Auth routes ───────────────────────────────────────────────────────────────

@app.route('/')
def index():
    return redirect(url_for('notes') if 'user_id' in session else url_for('login'))


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username'].strip()
        password = request.form['password']
        db = get_db()

        if not username or not password:
            flash('Both fields are required.')
        elif db.execute('SELECT id FROM users WHERE username = ?', (username,)).fetchone():
            flash('Username already taken.')
        else:
            db.execute('INSERT INTO users (username, password) VALUES (?, ?)',
                       (username, generate_password_hash(password)))
            db.commit()
            flash('Account created — please log in.')
            return redirect(url_for('login'))

    return render_template('register.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username'].strip()
        password = request.form['password']
        user = get_db().execute(
            'SELECT * FROM users WHERE username = ?', (username,)
        ).fetchone()

        if user and check_password_hash(user['password'], password):
            session.clear()
            session['user_id'] = user['id']
            session['username'] = user['username']
            return redirect(url_for('notes'))

        flash('Invalid username or password.')

    return render_template('login.html')


@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))


# ── Notes routes ──────────────────────────────────────────────────────────────

@app.route('/notes')
@login_required
def notes():
    rows = get_db().execute(
        'SELECT * FROM notes WHERE user_id = ? ORDER BY created_at DESC',
        (session['user_id'],)
    ).fetchall()
    return render_template('notes.html', notes=rows)


@app.route('/notes/new', methods=['GET', 'POST'])
@login_required
def new_note():
    if request.method == 'POST':
        title = request.form['title'].strip()
        body  = request.form['body'].strip()
        if not title:
            flash('Title is required.')
        else:
            db = get_db()
            db.execute('INSERT INTO notes (user_id, title, body) VALUES (?, ?, ?)',
                       (session['user_id'], title, body))
            db.commit()
            return redirect(url_for('notes'))

    return render_template('note_form.html', note=None)


@app.route('/notes/<int:note_id>/edit', methods=['GET', 'POST'])
@login_required
def edit_note(note_id):
    db   = get_db()
    note = db.execute(
        'SELECT * FROM notes WHERE id = ? AND user_id = ?',
        (note_id, session['user_id'])
    ).fetchone()

    if note is None:
        return redirect(url_for('notes'))

    if request.method == 'POST':
        title = request.form['title'].strip()
        body  = request.form['body'].strip()
        if not title:
            flash('Title is required.')
        else:
            db.execute(
                'UPDATE notes SET title = ?, body = ? WHERE id = ? AND user_id = ?',
                (title, body, note_id, session['user_id'])
            )
            db.commit()
            return redirect(url_for('notes'))

    return render_template('note_form.html', note=note)


@app.route('/notes/<int:note_id>/delete', methods=['POST'])
@login_required
def delete_note(note_id):
    db = get_db()
    db.execute('DELETE FROM notes WHERE id = ? AND user_id = ?',
               (note_id, session['user_id']))
    db.commit()
    return redirect(url_for('notes'))


if __name__ == '__main__':
    init_db()
    app.run(debug=True)
