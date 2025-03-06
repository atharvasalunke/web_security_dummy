from flask import Flask, render_template, request, redirect, url_for, session, flash, abort
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate, upgrade
from flask import jsonify
import os
import secrets
from werkzeug.security import generate_password_hash, check_password_hash
import bleach

app = Flask(__name__)

app.secret_key = "supersecretkey"  # Used for session management (CSRF vulnerability)

BASE_DIR = os.path.abspath(os.getcwd())  # Get project root path
DB_PATH = os.path.join(BASE_DIR, "database.db")  # Ensure single DB path
app.config["SQLALCHEMY_DATABASE_URI"] = f"sqlite:///{DB_PATH}"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["SESSION_COOKIE_HTTPONLY"] = True  # Prevent JS from accessing cookies
db = SQLAlchemy(app)
migrate = Migrate(app, db)

@app.before_request
def set_csrf_token():
    if "csrf_token" not in session:
        session["csrf_token"] = secrets.token_hex(32)
        session.modified = True  # Ensure session updates

    print("CSRF Token Set:", session.get("csrf_token"))  # Debugging

@app.after_request
def set_csrf_cookie(response):
    response.set_cookie("csrf_token", session.get("csrf_token"), httponly=False, samesite="Strict")
    return response

# ------------------- DATABASE MODELS -------------------
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password = db.Column(db.String(128), nullable=False)  # Stored in plain text (Security flaw)
    bio = db.Column(db.Text, default="Hello! I'm new here.")  # XSS vulnerability

    def set_password(self, password):
        self.password = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password, password)
    
    def set_bio(self, bio):
        allowed_tags = ['b', 'i', 'u', 'strong', 'em', 'p', 'br', 'a']
        self.bio = bleach.clean(bio, tags=allowed_tags)


class Post(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.Text, nullable=False)  # No sanitization (XSS vulnerability)
    author = db.Column(db.String(50), nullable=False)

    def set_content(self, content):
        allowed_tags = ['b', 'i', 'u', 'strong', 'em', 'p', 'br', 'a']
        self.content = bleach.clean(content, tags=allowed_tags)

# Follower Relationship Model
class Follow(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    follower = db.Column(db.String(50), nullable=False)
    following = db.Column(db.String(50), nullable=False)


# Ensure database tables are created
with app.app_context():
    db.create_all()


# ------------------- HOME (FEED) -------------------
from flask import get_flashed_messages

@app.route("/")
def home():

    if "user" not in session:
        get_flashed_messages()
        return redirect(url_for("login"))

    current_user = session.get("user")

    # Get users the logged-in user follows
    followed_users = [f.following for f in Follow.query.filter_by(follower=current_user).all()]
    followed_users.append(current_user)  # Include own posts

    # Get posts only from followed users
    posts = Post.query.filter(Post.author.in_(followed_users)).order_by(Post.id.desc()).all()

    # Get suggested users (excluding the current user & already followed users)
    following = [f.following for f in Follow.query.filter_by(follower=current_user).all()]
    suggested_users = User.query.filter(User.username != current_user, User.username.notin_(following)).limit(5).all()

    return render_template("index.html", posts=posts, suggested_users=suggested_users, following=following)




# ------------------- USER REGISTRATION -------------------
@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]

        # Check if the username already exists
        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            flash("Username already exists! Please choose a different one.", "danger")
            return redirect(url_for("register"))

        new_user = User(username=username)
        new_user.set_password(password)
        db.session.add(new_user)
        db.session.commit()

        flash("Registration successful! You can now log in.", "success")
        return redirect(url_for("login"))

    return render_template("register.html")


# ------------------- USER LOGIN -------------------
@app.route("/login", methods=["GET", "POST"])
def login():
    print("Request Method:", request.method)
    print("Request Form Data:", request.form)  
    print("Session CSRF Token:", session.get("csrf_token")) 
    if request.method == "POST":
        print("Form CSRF Token:", request.form.get("csrf_token"))
        print("Session CSRF Token:", session.get("csrf_token"))

        if request.form.get("csrf_token") != session.get("csrf_token"):
            abort(403)  # Forbidden

        username = request.form["username"]
        password = request.form["password"]

        user = User.query.filter_by(username=username).first()
        if user and user.check_password(password):
            session["user"] = user.username
            session.modified = True
            return redirect(url_for("home"))
        else:
            flash("Invalid login credentials!", "danger")
            return redirect(url_for("login"))

    return render_template("login.html")




# ------------------- VIEW USER PROFILE -------------------
@app.route("/profile/<username>", methods=["GET", "POST"])
def profile(username):
    if "user" not in session:  # Ensure correct session key
        return redirect(url_for("login"))

    user: User = User.query.filter_by(username=username).first()
    if not user:
        flash("User not found!", "danger")
        return redirect(url_for("home"))

    posts = Post.query.filter_by(author=user.username).all()

    # Fetch followers and following lists
    following = [f.following for f in Follow.query.filter_by(follower=user.username).all()]
    followers = [f.follower for f in Follow.query.filter_by(following=user.username).all()]

    # Check if the logged-in user follows this profile
    logged_in_user = session.get("user")  # Retrieve username safely
    is_following = False
    #print("logged in user :", logged_in_user)
    if logged_in_user:  # Avoid KeyError if session is empty
        is_following = Follow.query.filter_by(follower=logged_in_user, following=username).first() is not None
    #print("following :", is_following)

    if request.method == "POST":
        if request.form.get("csrf_token") != session.get("csrf_token"):
            abort(403)
        new_bio = request.form["bio"]
        user.set_bio(new_bio)
        db.session.commit()

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
    if request.form.get("csrf_token") != session.get("csrf_token"):
        abort(403)

    if "user" not in session:
        return redirect(url_for("login"))

    content = request.form["content"]
    new_post = Post(author=session["user"])
    new_post.set_content(content)
    db.session.add(new_post)
    db.session.commit()

    flash("Post created!", "success")
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
            flash(f"You are now following {username}!", "success")

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

@app.route("/latest_post/<username>", methods=["GET"])
def latest_post(username):
    latest = Post.query.filter_by(author=username).order_by(Post.id.desc()).first()
    #print({"post": latest.content})
    if latest is None:
        return jsonify({"message": "No posts yet."}), 200

    return jsonify({"post": latest.content})

@app.route("/debug_session")
def debug_session():
    session["test"] = "Hello"
    print("Session Content:", dict(session))  # Print session data
    return jsonify(session=dict(session))

# ------------------- RUN APP -------------------
if __name__ == "__main__":
    with app.app_context():
        upgrade()
    app.run(debug=True)