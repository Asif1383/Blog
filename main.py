from flask import Flask, render_template, redirect, url_for, flash, abort
from flask_bootstrap import Bootstrap
from flask_ckeditor import CKEditor
from datetime import date
from functools import wraps
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import relationship
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user
from forms import CreatePostForm, CreateRegistrationForm, LoginForm, CommentSection
from flask_gravatar import Gravatar
from sqlalchemy import ForeignKey

####Intialization

is_logged_in = False
app = Flask(__name__)
app.config['SECRET_KEY'] = 'TOP SECRET'
ckeditor = CKEditor(app)
Bootstrap(app)

####COnnection to Gravator
gravatar = Gravatar(app,
                    size=100,
                    rating='pg',
                    default='retro',
                    force_default=False,
                    force_lower=False,
                    use_ssl=False,
                    base_url='none')

##CONNECT TO LOGIN_MANAGER
login_manager = LoginManager()
login_manager.init_app(app)

def admin_only(f):
    @wraps(f)
    def decorated_function_of_admin(*args, **kwargs):

        if int(current_user.get_id()) != 1:

            return abort(403)

        return f(*args, **kwargs)
    return decorated_function_of_admin

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


##CONNECT TO DB
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///blog.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)


##CONFIGURE TABLES

class Comment(db.Model):
    __tablename__ = 'comments'
    id = db.Column(db.Integer, primary_key=True)
    text = db.Column(db.Text, nullable=False)
    user_id = db.Column(db.Integer, ForeignKey('user.id'))
    comment_to_user = relationship('User', backref='comment_of_user')
    blog_id = db.Column(db.Integer, ForeignKey('blog_posts.id'))
    comment_to_blog = relationship('BlogPost', backref='comment_on_blog')


class BlogPost(db.Model):
    __tablename__ = "blog_posts"
    author_id = db.Column(db.Integer, ForeignKey('user.id'))
    id = db.Column(db.Integer, primary_key=True)
    author = db.Column(db.String(250), nullable=False)
    title = db.Column(db.String(250), unique=True, nullable=False)
    subtitle = db.Column(db.String(250), nullable=False)
    date = db.Column(db.String(250), nullable=False)
    body = db.Column(db.Text, nullable=False)
    img_url = db.Column(db.String(250), nullable=False)
    blog_to_user = relationship("User", backref="blog_of_user")
    comment_blog = relationship("Comment", backref="blog_on_comment")


##USER TABLE
class User(UserMixin, db.Model):
    __tablename__ = 'user'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(250), nullable=False)
    email = db.Column(db.String(250), nullable=False, unique=True)
    password = db.Column(db.String(500),nullable=False)
    user = relationship("BlogPost", backref="user")
    comments = relationship('Comment', backref='comment')
db.create_all()

# /// add new post

@app.route("/new-post", methods=["POST", "GET"])
@admin_only
def add_new_post():
    print(current_user.id)
    form = CreatePostForm()
    if form.validate_on_submit():
        new_post = BlogPost(
            title=form.title.data,
            subtitle=form.subtitle.data,
            body=form.body.data,
            img_url=form.img_url.data,
            author=current_user.name,
            date=date.today().strftime("%B %d, %Y"),
            author_id=int(current_user.id)
        )
        db.session.add(new_post)
        db.session.commit()
        return redirect(url_for("get_all_posts"))
    return render_template("make-post.html", form=form)

# about Me Page

@app.route("/about")
def about():
    return render_template("about.html", is_logged_in=current_user.is_authenticated)

# contact page

@app.route("/contact")
def contact():
    return render_template("contact.html", is_logged_in=current_user.is_authenticated)

# home page

@app.route('/')
def get_all_posts():
    posts = BlogPost.query.all()

    return render_template("index.html", all_posts=posts, is_logged_in=current_user.is_authenticated)

# registration page

@app.route('/register', methods=["POST", "GET"])
def register():

    registration_form = CreateRegistrationForm()

    if registration_form.validate_on_submit():

        email = registration_form.email.data
        password_of_user = registration_form.password.data
        password_in_database = generate_password_hash(password_of_user, method='pbkdf2:sha256', salt_length=8)

        users = db.session.query(User).all()

        if users:
            for user in users:
                if email == user.email:
                    flash("Email already exist")

                    return redirect(url_for('login'))


        user_to_add = User(name=registration_form.name.data,
                                    password=password_in_database,
                                    email=registration_form.email.data
                                     )
        db.session.add(user_to_add)
        db.session.commit()
        login_user(user_to_add)
        return redirect(url_for('get_all_posts'))
    return render_template("register.html", form=registration_form)

# Login route

@app.route('/login', methods=["POST", "GET"])
def login():
    login_form = LoginForm()

    if login_form.validate_on_submit():
        email = login_form.email.data

        password_of_user = login_form.password.data
        user = User.query.filter_by(email=email).first()

        if user:

            if check_password_hash(user.password, password=password_of_user):
                login_user(user)
                return redirect(url_for('get_all_posts'))
            else:
                flash("Password is incorrect Please recheck your password", 'error')
                return redirect(url_for('login'))
        else:
            flash("Your email is wrong.Please try again", 'error')
            return redirect(url_for('login'))

    return render_template("login.html", form=login_form)


# Logout route

@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('get_all_posts'))

# show the blog route

@app.route("/post/<int:post_id>")
def show_post(post_id):
    comment_section = CommentSection()
    requested_post = BlogPost.query.get(post_id)
    for message in requested_post.comment_on_blog:
        print(message.comment_to_user.name)
    return render_template("post.html", form=comment_section, post=requested_post,
                           is_logged_in=current_user.is_authenticated, comment=requested_post.comment_on_blog)

# Edit the blog post page

@app.route("/edit-post/<int:post_id>", methods=["POST", "GET"])
@admin_only
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

    return render_template("make-post.html", form=edit_form, is_logged_in=current_user.is_authenticated)


# delete the blog post

@app.route("/delete/<int:post_id>", methods=["POST", "GET"])
def delete_post(post_id):
    post_to_delete = BlogPost.query.get(post_id)
    db.session.delete(post_to_delete)
    db.session.commit()
    return redirect(url_for('get_all_posts'))

#################################################################################################
@app.route('/post/<int:post_id>', methods=['POST', 'GET'])
def comment(post_id):
    comment_section = CommentSection()
    if comment_section.validate_on_submit():
        if not current_user.is_authenticated:
            flash('Please login to comment')
            return redirect(url_for('login'))

        text_data = comment_section.body.data
        print(text_data)
        comment_data = Comment(text=text_data, user_id=current_user.id, blog_id=post_id)
        db.session.add(comment_data)
        db.session.commit()
    return redirect(url_for('show_post', post_id=post_id))
################################################################################################
# ////start from hear
if __name__ == "__main__":
    app.run(debug=True)
