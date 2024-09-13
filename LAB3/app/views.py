from flask import Blueprint, render_template, redirect, url_for, flash, request, jsonify, session
from flask_login import login_user, logout_user, login_required, current_user
from flask_jwt_extended import create_access_token, jwt_required, get_jwt_identity, decode_token
from .models import User, Book
from .forms import RegisterForm, LoginForm, AddBookForm , EditBookForm
from . import db
from flask import send_file
import io

main_bp = Blueprint('main', __name__)

def get_user_from_token():
    token = session.get('jwt_token')
    if token:
        try:
            decoded_token = decode_token(token)
            user_id = decoded_token['sub']
            return User.query.get(user_id)
        except Exception as e:
            print(f"Token decoding error: {e}")
            return None
    return None

@main_bp.route('/')
def index():
    if 'jwt_token' in session:

        return redirect(url_for('main.dashboard_jwt'))
    else:
        return redirect(url_for('main.login_jwt_view'))


@main_bp.route('/book_cover/<int:book_id>')
def book_cover(book_id):
    book = Book.query.get_or_404(book_id)
    if book.cover_image:
        return send_file(io.BytesIO(book.cover_image), mimetype='image/jpeg')  
    return send_file(io.BytesIO(), mimetype='image/jpeg')


@main_bp.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        existing_user_email = User.query.filter_by(email=form.email.data).first()
        existing_user_username = User.query.filter_by(username=form.username.data).first()

        if existing_user_email:
            flash('Email already registered. Please use a different email.', 'danger')
            return redirect(url_for('main.register'))
        
        if existing_user_username:
            flash('Username already taken. Please choose a different username.', 'danger')
            return redirect(url_for('main.register'))
        
        user = User(username=form.username.data, email=form.email.data)
        user.set_password(form.password.data)

        user.is_admin = 'is_admin' in request.form

        db.session.add(user)
        db.session.commit()
        flash('Registration successful!', 'success')
        return redirect(url_for('main.login'))
    
    return render_template('register.html', form=form)




@main_bp.route('/login_jwt', methods=['GET', 'POST'])
def login_jwt_view():
    form = LoginForm()
    if request.method == 'POST':
        if form.validate_on_submit():
            user = User.query.filter_by(email=form.email.data).first()
            if user and user.check_password(form.password.data):
                access_token = create_access_token(identity=user.id)
                session['jwt_token'] = access_token  
                flash('Login successful!', 'success')
                return redirect(url_for('main.dashboard_jwt'))  
            
            flash('Invalid credentials. Please try again.', 'danger')
            return jsonify({"msg": "Invalid credentials"}), 401

        return jsonify({"msg": "Form validation failed", "errors": form.errors}), 400

    return render_template('login_jwt.html', form=form)


@main_bp.route('/logout_jwt')
def logout_jwt():
    session.pop('jwt_token', None)  
    flash('You have been logged out.', 'info')
    return redirect(url_for('main.login_jwt_view'))  


@main_bp.route('/delete_book_jwt/<int:book_id>')
def delete_book_jwt(book_id):
    user = get_user_from_token()
    if not user:
        flash('Please log in to delete a book.', 'warning')
        return redirect(url_for('main.login_jwt_view'))

    book = Book.query.get_or_404(book_id)
    if book.user_id != user.id:
        flash('You do not have permission to delete this book.', 'danger')
        return redirect(url_for('main.dashboard_jwt'))

    db.session.delete(book)
    db.session.commit()
    flash('Book deleted successfully!', 'success')
    return redirect(url_for('main.dashboard_jwt'))

@main_bp.route('/edit_book_jwt/<int:book_id>', methods=['GET', 'POST'])
def edit_book_jwt(book_id):
    user = get_user_from_token()
    if not user:
        flash('Please log in to edit a book.', 'warning')
        return redirect(url_for('main.login_jwt_view'))

    book = Book.query.get_or_404(book_id)
    if book.user_id != user.id:
        flash('You do not have permission to edit this book.', 'danger')
        return redirect(url_for('main.dashboard_jwt'))

    form = EditBookForm(obj=book)
    if request.method == 'POST':
        if form.validate_on_submit():
            book.title = form.title.data
            book.author = form.author.data
            if form.cover_image.data:
                book.cover_image = form.cover_image.data.read()
            db.session.commit()
            flash('Book updated successfully!', 'success')
            return redirect(url_for('main.dashboard_jwt'))
        else:
            return jsonify({"msg": "Form validation failed", "errors": form.errors}), 400

    return render_template('edit_book.html', form=form, book=book)


@main_bp.route('/register_jwt', methods=['GET', 'POST'])
def register_jwt_view():
    form = RegisterForm()
    if request.method == 'POST':
        if form.validate_on_submit():
            existing_user_email = User.query.filter_by(email=form.email.data).first()
            existing_user_username = User.query.filter_by(username=form.username.data).first()

            if existing_user_email:
                return jsonify({"msg": "Email already registered"}), 400

            if existing_user_username:
                return jsonify({"msg": "Username already taken"}), 400

            user = User(username=form.username.data, email=form.email.data)
            user.set_password(form.password.data)

            is_admin = request.form.get('is_admin') == 'true'
            user.is_admin = is_admin

            db.session.add(user)
            db.session.commit()

            flash('Registration successful! Please log in.', 'success')
            return redirect(url_for('main.login_jwt_view')) 
        return jsonify({"msg": "Form validation failed", "errors": form.errors}), 400
     
    return render_template('register_jwt.html', form=form)



@main_bp.route('/dashboard_jwt', methods=['GET'])
def dashboard_jwt():
    user = get_user_from_token()
    if not user:
        flash('Please log in to access the dashboard.', 'warning')
        return redirect(url_for('main.login_jwt_view'))

    books = Book.query.filter_by(user_id=user.id).all()
    return render_template('dashboard_jwt.html', books=books, user=user)




@main_bp.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()

        if user is None:
            flash('Email not found. Please try again or register.', 'danger')
        elif not user.check_password(form.password.data):
            flash('Incorrect password. Please try again.', 'danger')
        else:
            login_user(user)
            if user.is_admin:
                return redirect(url_for('main.admin_dashboard'))
            return redirect(url_for('main.dashboard'))

    flash('Please check your form input.', 'danger')
    return render_template('login.html', form=form)


@main_bp.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('main.login'))

@main_bp.route('/dashboard')
@login_required
def dashboard():
    books = Book.query.filter_by(user_id=current_user.id).all()
    return render_template('dashboard.html', books=books)

@main_bp.route('/add_book_jwt', methods=['GET', 'POST'])
def add_book_jwt():
    user = get_user_from_token()
    if not user:
        flash('Please log in to add a book.', 'warning')
        return redirect(url_for('main.login_jwt_view'))

    form = AddBookForm()
    if request.method == 'POST':
        if form.validate_on_submit():
            book = Book(title=form.title.data, author=form.author.data, user_id=user.id)
            if form.cover_image.data:
                book.cover_image = form.cover_image.data.read()
            db.session.add(book)
            db.session.commit()
            flash('Book added successfully!', 'success')
            return redirect(url_for('main.dashboard_jwt'))
        else:
            return jsonify({"msg": "Form validation failed", "errors": form.errors}), 400

    return render_template('add_book.html', form=form)

@main_bp.route('/add_book', methods=['GET', 'POST'])
@login_required
def add_book():
    form = AddBookForm()
    if form.validate_on_submit():
        book = Book(title=form.title.data, author=form.author.data, user_id=current_user.id)
        if form.cover_image.data:
            book.cover_image = form.cover_image.data.read()
        db.session.add(book)
        db.session.commit()
        return redirect(url_for('main.dashboard'))
    return render_template('add_book.html', form=form)

@main_bp.route('/delete_book/<int:book_id>')
@login_required
def delete_book(book_id):
    book = Book.query.get_or_404(book_id)
    if book.user_id != current_user.id:
        return redirect(url_for('main.dashboard'))
    db.session.delete(book)
    db.session.commit()
    return redirect(url_for('main.dashboard'))

@main_bp.route('/edit_book/<int:book_id>', methods=['GET', 'POST'])
@login_required
def edit_book(book_id):
    book = Book.query.get_or_404(book_id)
    if book.user_id != current_user.id:
        return redirect(url_for('main.dashboard'))
    
    form = EditBookForm(obj=book)
    if form.validate_on_submit():
        book.title = form.title.data
        book.author = form.author.data
        if form.cover_image.data:
            book.cover_image = form.cover_image.data.read()
        db.session.commit()
        flash('Book updated successfully!')
        return redirect(url_for('main.dashboard'))
    
    return render_template('edit_book.html', form=form, book=book)

# Admin dashboard route
# @main_bp.route('/admin_dashboard')
# @login_required
# def admin_dashboard():
#     if not current_user.is_admin:
#         flash('You do not have permission to view this page.')
#         return redirect(url_for('main.dashboard'))
#     users = User.query.all()
#     books = Book.query.all()
#     return render_template('admin_dashboard.html', users=users, books=books)


@main_bp.route('/admin_dashboard_jwt', methods=['GET'])
@jwt_required()
def admin_dashboard_jwt():
    user_id = get_jwt_identity()
    user = User.query.get(user_id)
    
    if not user or not user.is_admin:
        return jsonify({"msg": "Access denied. Admins only."}), 403

    users = User.query.all()
    books = Book.query.all()
    return render_template('admin_dashboard_jwt.html', users=users, books=books)
