from flask import Flask, render_template, request, redirect, url_for, session, flash
from flask_sqlalchemy import SQLAlchemy

app = Flask(__name__)
app.secret_key = "supersecretkey"  # Used for session management (CSRF vulnerability)

import os

BASE_DIR = os.path.abspath(os.getcwd())  # Get project root path
DB_PATH = os.path.join(BASE_DIR, "database.db")  # Ensure single DB path
app.config["SQLALCHEMY_DATABASE_URI"] = f"sqlite:///{DB_PATH}"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
db = SQLAlchemy(app)


# ------------------- DATABASE MODELS -------------------
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password = db.Column(db.String(50), nullable=False)  # Stored in plain text (Security flaw)
    bio = db.Column(db.Text, default="Hello! I'm new here.")  # XSS vulnerability


class Post(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.Text, nullable=False)  # No sanitization (XSS vulnerability)
    author = db.Column(db.String(50), nullable=False)


# Follower Relationship Model
class Follow(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    follower = db.Column(db.String(50), nullable=False)  # Who follows
    following = db.Column(db.String(50), nullable=False)  # Who is followed


# Ensure database tables are created
with app.app_context():
    db.create_all()


# ------------------- HOME (FEED) -------------------
@app.route("/")
def home():
    if "user" not in session:
        return redirect(url_for("login"))

    current_user = session["username"]

    # Get users the logged-in user follows
    followed_users = [f.following for f in Follow.query.filter_by(follower=current_user).all()]
    followed_users.append(current_user)  # Include own posts

    # Get posts only from followed users
    posts = Post.query.filter(Post.author.in_(followed_users)).order_by(Post.id.desc()).all()

    # Get list of users the current user is following
    following = [f.following for f in Follow.query.filter_by(follower=current_user).all()]

    return render_template("index.html", posts=posts, following=following)



# ------------------- USER REGISTRATION -------------------
@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]

        # Check if the username already exists
        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            flash("❌ Username already exists! Please choose a different one.", "danger")
            return redirect(url_for("register"))

        new_user = User(username=username, password=password)
        db.session.add(new_user)
        db.session.commit()

        flash("✅ Registration successful! You can now log in.", "success")
        return redirect(url_for("login"))

    return render_template("register.html")


# ------------------- USER LOGIN -------------------
import sqlite3


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]

        # 🚨 INTENTIONALLY VULNERABLE SQL QUERY (BYPASSING SQLAlchemy)
        conn = sqlite3.connect("database.db")
        cursor = conn.cursor()

        query = f"SELECT * FROM user WHERE username='{username}' AND password='{password}'"
        print(f"🔥 Executing SQL Query: {query}")

        cursor.execute(query)
        user = cursor.fetchone()

        conn.close()

        if user:
            print(f"✅ Query Result: {user}")
            session["user"] = user[1]  # Store correct session key
            flash("✅ Login successful!", "success")
            return redirect(url_for("home"))  # Redirect to home instead of rendering index.html directly
        else:
            flash("❌ Invalid login credentials! (Or SQL Injection failed!)", "danger")
            return redirect(url_for("login"))

    return render_template("login.html")



# ------------------- VIEW USER PROFILE -------------------
@app.route("/profile/<username>")
def profile(username):
    if "username" not in session:  # Ensure correct session key
        return redirect(url_for("login"))

    user = User.query.filter_by(username=username).first()
    if not user:
        flash("❌ User not found!", "danger")
        return redirect(url_for("home"))

    posts = Post.query.filter_by(author=user.username).all()

    # Fetch followers and following lists
    following = [f.following for f in Follow.query.filter_by(follower=user.username).all()]
    followers = [f.follower for f in Follow.query.filter_by(following=user.username).all()]

    # Check if the logged-in user follows this profile
    logged_in_user = session.get("username")  # Retrieve username safely
    is_following = False

    if logged_in_user:  # Avoid KeyError if session is empty
        is_following = Follow.query.filter_by(follower=logged_in_user, following=username).first() is not None

    return render_template(
        "profile.html",
        user=user,
        posts=posts,
        following=following,
        followers=followers,
        is_following=is_following,
    )

# ------------------- CREATE POSTS -------------------
@app.route("/post", methods=["POST"])
def post():
    if "user" not in session:
        return redirect(url_for("login"))

    content = request.form["content"]
    new_post = Post(content=content, author=session["user"])
    db.session.add(new_post)
    db.session.commit()

    flash("✅ Post created!", "success")
    return redirect(url_for("home"))


# ------------------- FOLLOW / UNFOLLOW -------------------
@app.route("/follow/<username>")
def follow(username):
    if "user" not in session:
        return redirect(url_for("login"))

    if username != session["user"]:
        existing_follow = Follow.query.filter_by(follower=session["user"], following=username).first()
        if not existing_follow:
            new_follow = Follow(follower=session["user"], following=username)
            db.session.add(new_follow)
            db.session.commit()
            flash(f"✅ You are now following {username}!", "success")

    return redirect(url_for("profile", username=username))

@app.route("/unfollow/<username>")
def unfollow(username):
    if "user" not in session:
        return redirect(url_for("login"))

    follow_entry = Follow.query.filter_by(follower=session["user"], following=username).first()

    if follow_entry:
        db.session.delete(follow_entry)
        db.session.commit()
        flash(f"❌ Unfollowed {username}.", "warning")

    return redirect(url_for("profile", username=username))


# ------------------- LOGOUT -------------------
@app.route("/logout")
def logout():
    session.pop("user", None)  # Remove correct session key
    flash("✅ Logged out successfully!", "success")
    return redirect(url_for("login"))


# ------------------- REMOVE CSP HEADERS (FOR XSS TESTING) -------------------
@app.after_request
def remove_csp(response):
    response.headers["Content-Security-Policy"] = ""
    return response

@app.route("/search_users")
def search_users():
    if "user" not in session:
        return redirect(url_for("login"))

    query = request.args.get("query")
    if not query:
        flash("❌ Please enter a search term!", "warning")
        return redirect(url_for("home"))

    # Perform a simple search in the User table
    users = User.query.filter(User.username.like(f"%{query}%")).all()

    return render_template("search_results.html", users=users)

# ------------------- RUN APP -------------------
if __name__ == "__main__":
    app.run(debug=True)
