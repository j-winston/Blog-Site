import flask
from flask import Flask, render_template, redirect, url_for, flash, request, abort
from flask_bootstrap import Bootstrap
from flask_ckeditor import CKEditor
from datetime import date
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, login_user, LoginManager, current_user, logout_user
from forms import CreatePostForm, RegistrationForm, LoginForm, CommentForm
from functools import wraps
from flask_gravatar import Gravatar
from hashlib import md5

app = Flask(__name__)
app.config['SECRET_KEY'] = '8BYkEfBA6O6donzWlSihBXox7C0sKR6b'
ckeditor = CKEditor(app)
Bootstrap(app)

##CONNECT TO DB
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///blog.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# Gravatars

##CONFIGURE TABLES
class User(db.Model, UserMixin):
    __tablename__ = "user"
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(250), nullable=False)
    email = db.Column(db.String(250), unique=True, nullable=False)
    password = db.Column(db.String(250), nullable=False)
    posts = db.relationship('BlogPost', back_populates="author")
    comments = db.relationship('Comment', back_populates="author")
    def make_gravatar():
        g = Gravatar(app,
                    size=100,
                    rating='R',
                    default='retro',
                    force_default=False,
                    force_lower=False,
                    use_ssl=False,
                    base_url=None)
        return g

    gravatar = make_gravatar()



class BlogPost(db.Model):
    __tablename__ = "blog_posts"
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(250), nullable=False)
    subtitle = db.Column(db.String(250), nullable=False)
    date = db.Column(db.String(250), nullable=False)
    body = db.Column(db.Text, nullable=False)
    img_url = db.Column(db.String(250))

    author_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    author = db.relationship('User', back_populates='posts')


class Comment(db.Model):
    __tablename__ = "comments"
    id = db.Column(db.Integer, primary_key=True)
    comment = db.Column(db.Text, nullable=False)
    author_name = db.Column(db.String(250))
    author = db.relationship('User', back_populates='comments')
    author_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    email = str(User.email)
    email_encoded = email.lower().strip().encode()
    email_hash = md5(email_encoded).hexdigest()
    gravatar_url = f"https://www.gravatar.com/avatar/{email_hash}"




db.create_all()

# Initialize Flask login
login_manager = LoginManager()
login_manager.init_app(app)


# Decorator function equiv ie; get_all_posts = admin_only(get_all_posts) --> @ admin_only
def admin_only(func):
    @wraps(func)
    def decorated_function(*args, **kwargs):
        if current_user.id != 1:
            return abort(403)
        return func(*args, **kwargs)
    return decorated_function


@app.route('/')
def get_all_posts():
    all_posts = BlogPost.query.all()
    if current_user.is_active:
        return render_template("index.html", all_posts=all_posts, user_id=current_user.id)
    else:
        return render_template("index.html", all_posts=all_posts)


@app.route('/register', methods=['POST', 'GET'])
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        new_user = User()
        new_user.email = request.form['email'].lower().strip()
        # Check if email already exists
        email_exists = User.query.filter_by(email=form.email.data).first()
        if email_exists:
            flash("You've already signed in with that email, log in instead!")
            return redirect(url_for('login'))
        else:
            new_user.name = request.form['name']
            new_user.password = generate_password_hash(form.password.data)
            db.session.add(new_user)
            db.session.commit()
            login_user(new_user)
            return redirect(url_for('get_all_posts'))
    return render_template("register.html", form=form)


@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    all_posts = BlogPost.query.all()

    if form.validate_on_submit():
        email = form.email.data
        user = User.query.filter_by(email=email).first()

        if user:
            pwhash = user.password
            if check_password_hash(pwhash, form.password.data):
                login_user(user)
                return render_template('index.html', all_posts=all_posts, is_logged_in=True, user_id=user.id)
            else:
                flask.flash("Password incorrect, please try again")
                return redirect(url_for('login'))
        elif not user:
            flask.flash("That email doesn't exist, please try again.")
            return redirect(url_for('login'))
    return render_template('login.html', form=form)

# Needed for flask-login
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(user_id)


@app.route('/logout')
def logout():
    all_posts = BlogPost.query.all()
    logout_user()
    return render_template("index.html", all_posts=all_posts)


@app.route("/post/<int:post_id>", methods=['GET', 'POST'])
def show_post(post_id):
    requested_post = BlogPost.query.get(post_id)
    all_comments = Comment.query.all()
    for comment in all_comments:
        print(comment.gravatar_url)
    form = CommentForm()
    if form.validate_on_submit():
        if current_user.is_active:
            comment_form_data = form.comment.data
            new_comment = Comment(comment=comment_form_data, author_name=current_user.name)
            db.session.add(new_comment)
            db.session.commit()
            return redirect(url_for('show_post', post_id=post_id))
        else:
            flash("Please login, first.")
            return redirect(url_for('login'))
    else:
        return render_template("post.html",
                               post=requested_post,
                               form=form,
                               all_comments=all_comments)


@app.route("/about")
def about():
    return render_template("about.html")


@app.route("/contact")
def contact():
    return render_template("contact.html")


@app.route("/new-post", methods=['GET', 'POST'])
@admin_only
def add_new_post():
    form = CreatePostForm()
    if form.validate_on_submit():
        new_post = BlogPost(
            title=form.title.data,
            subtitle=form.subtitle.data,
            body=form.body.data,
            img_url=form.img_url.data,
            date=date.today().strftime("%B %d, %Y"),
            author_id=current_user.id
        )
        db.session.add(new_post)
        db.session.commit()
        return redirect(url_for("get_all_posts"))
    return render_template("make-post.html", form=form, is_edit=False)


@app.route("/edit-post/<int:post_id>")
def edit_post(post_id):
    post = BlogPost.query.get(post_id)
    edit_form = CreatePostForm(
        title=post.title,
        subtitle=post.subtitle,
        img_url=post.img_url,
        author=post.author,
        body=post.body
    )
    if edit_form.validate_on_submit():
        post.title = edit_form.title.data
        post.subtitle = edit_form.subtitle.data
        post.img_url = edit_form.img_url.data
        post.author = edit_form.author.data
        post.body = edit_form.body.data
        db.session.commit()
        return redirect(url_for("show_post", post_id=post.id))
    return render_template("make-post.html", form=edit_form, is_edit=True)


@app.route("/delete/<int:post_id>")
@admin_only
def delete_post(post_id):
    post_to_delete = BlogPost.query.get(post_id)
    db.session.delete(post_to_delete)
    db.session.commit()
    return redirect(url_for('get_all_posts'))


if __name__ == "__main__":
    app.run(host='0.0.0.0', port=5000, debug=True)
