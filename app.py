from flask import Flask, render_template, request, redirect, url_for, session
from flask_sqlalchemy import SQLAlchemy
import sqlite3

app = Flask(__name__)
app.secret_key = "supersecretkey"  # Used for session management (CSRF vulnerability)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)


# Database Model
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password = db.Column(db.String(50), nullable=False)  # Stored in plain text (Security flaw)
    bio = db.Column(db.Text, default="Hello! I'm new here.")  # XSS vulnerability


class Post(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.Text, nullable=False)  # No sanitization (XSS vulnerability)
    author = db.Column(db.String(50), nullable=False)


# Create DB Tables
with app.app_context():
    db.create_all()


@app.route("/")
def home():
    posts = Post.query.all()
    return render_template("index.html", posts=posts)


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]

        new_user = User(username=username, password=password)
        db.session.add(new_user)
        db.session.commit()

        return redirect(url_for("login"))

    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]

        # 🚨 INTENTIONALLY VULNERABLE SQL QUERY (BYPASSING SQLAlchemy)
        conn = sqlite3.connect("instance/database.db")
        cursor = conn.cursor()

        query = f"SELECT * FROM user WHERE username='{username}' AND password='{password}'"
        print(f"🔥 Executing SQL Query: {query}")  # Debugging

        cursor.execute(query)
        user = cursor.fetchone()

        conn.close()

        if user:
            print(f"✅ Query Result: {user}")  # Print user data
            session["user"] = user[1]
            return redirect(url_for("profile"))
        else:
            print("❌ No user found (SQL Injection failed!)")
            return "❌ Invalid login credentials! (Or SQL Injection failed!)"

    return render_template("login.html")


@app.route("/profile", methods=["GET", "POST"])
def profile():
    if "user" not in session:
        return redirect(url_for("login"))

    user = User.query.filter_by(username=session["user"]).first()
    posts = Post.query.filter_by(author=user.username).all()

    if request.method == "POST":
        new_bio = request.form["bio"]
        user.bio = new_bio  # ⚠️ XSS vulnerability (no sanitization)
        db.session.commit()

    return render_template("profile.html", user=user, posts=posts)



@app.route("/post", methods=["POST"])
def post():
    if "user" not in session:
        return redirect(url_for("login"))

    content = request.form["content"]
    new_post = Post(content=content, author=session["user"])
    db.session.add(new_post)
    db.session.commit()

    return redirect(url_for("home"))


@app.route("/logout")
def logout():
    session.pop("user", None)
    return redirect(url_for("login"))


if __name__ == "__main__":
    app.run(debug=True)
