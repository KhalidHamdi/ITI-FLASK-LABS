from flask import Flask, render_template, redirect, url_for, flash, session, send_file, request
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from models import db, User, Book
from forms import RegistrationForm, LoginForm, AddBookForm
import os
import io


app = Flask(__name__)

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///project.db'
app.config['SECRET_KEY'] = '123'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db.init_app(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/register", methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('index'))

    form = RegistrationForm()
    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')

        is_admin = form.admin_code.data == '123'

        user = User(username=form.username.data, password=hashed_password, is_admin=is_admin)
        db.session.add(user)
        db.session.commit()

        flash('Account created successfully!', 'success')
        return redirect(url_for('login'))

    return render_template('register.html', form=form)



@app.route("/login", methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user and bcrypt.check_password_hash(user.password, form.password.data):
            login_user(user)
            return redirect(url_for('library'))
        else:
            flash('Login unsuccessful. Check username and password.', 'danger')
    return render_template('login.html', form=form)

@app.route("/logout")
def logout():
    logout_user()
    return redirect(url_for('index'))

@app.route("/library")
@login_required
def library():
    books = Book.query.filter_by(user_id=current_user.id).all()
    return render_template('library.html', books=books)

@app.route("/add_book", methods=['GET', 'POST'])
@login_required
def add_book():
    form = AddBookForm()
    if form.validate_on_submit():
        image_data = form.image.data.read() if form.image.data else None
        new_book = Book(title=form.title.data, image=image_data, user_id=current_user.id)
        db.session.add(new_book)
        db.session.commit()
        flash('Book added to your library!', 'success')
        return redirect(url_for('library'))
    return render_template('add_book.html', form=form)

@app.route("/book_image/<int:book_id>")
@login_required
def book_image(book_id):
    book = Book.query.get_or_404(book_id)
    return send_file(io.BytesIO(book.image), mimetype='image/jpeg', as_attachment=False)

@app.route("/admin_dashboard")
@login_required
def admin_dashboard():
    if not current_user.is_admin:
        return redirect(url_for('index'))
    users = User.query.all()
    books = Book.query.all()
    return render_template('admin_dashboard.html', users=users, books=books)

@app.route("/edit_book/<int:book_id>", methods=['GET', 'POST'])
@login_required
def edit_book(book_id):
    if not current_user.is_admin:
        return redirect(url_for('index'))
    
    book = Book.query.get_or_404(book_id)
    if request.method == 'POST':
        book.title = request.form.get('title')
        image_data = request.files.get('image').read() if 'image' in request.files else book.image
        book.image = image_data
        db.session.commit()
        flash('Book updated successfully!', 'success')
        return redirect(url_for('admin_dashboard'))

    return render_template('edit_book.html', book=book)


@app.route("/delete_book/<int:book_id>")
@login_required
def delete_book(book_id):
    book = Book.query.get_or_404(book_id)
    if current_user.is_admin or book.user_id == current_user.id:
        db.session.delete(book)
        db.session.commit()
        flash('Book deleted successfully.', 'success')
    return redirect(url_for('library'))

@app.route("/delete_user/<int:user_id>")
@login_required
def delete_user(user_id):
    if not current_user.is_admin:
        return redirect(url_for('index'))
    user = User.query.get_or_404(user_id)
    db.session.delete(user)
    db.session.commit()
    flash('User deleted successfully.', 'success')
    return redirect(url_for('admin_dashboard'))

if __name__ == '__main__':
    app.run(debug=True)
