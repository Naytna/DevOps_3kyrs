from flask import Flask, render_template, redirect, url_for, request, flash, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SelectField, IntegerField
from wtforms.validators import DataRequired, Length, EqualTo
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.exceptions import abort
from functools import wraps
import os

app = Flask(__name__)
app.config['SECRET_KEY'] = 'secret-key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///warehouse.db'
db = SQLAlchemy(app)

login_manager = LoginManager(app)
login_manager.login_view = 'login'

# Модели
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(128))
    role = db.Column(db.String(20), default='user')

class Client(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text)
    address = db.Column(db.String(200))
    contacts = db.Column(db.String(100))

class Product(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text)
    client_id = db.Column(db.Integer, db.ForeignKey('client.id'))
    client = db.relationship('Client', backref='products')

class Department(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    number = db.Column(db.String(20), unique=True, nullable=False)
    name = db.Column(db.String(100))

class Stock(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    product_id = db.Column(db.Integer, db.ForeignKey('product.id'))
    client_id = db.Column(db.Integer, db.ForeignKey('client.id'))
    department_id = db.Column(db.Integer, db.ForeignKey('department.id'))
    quantity = db.Column(db.Integer)

class DepartmentAccess(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    department_id = db.Column(db.Integer, db.ForeignKey('department.id'))

# Формы
class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=4, max=80)])
    password = PasswordField('Password', validators=[DataRequired()])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])

class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])

class ProductForm(FlaskForm):
    name = StringField('Name', validators=[DataRequired()])
    description = StringField('Description')
    client = SelectField('Client', coerce=int)

class ClientForm(FlaskForm):
    name = StringField('Name', validators=[DataRequired()])
    description = StringField('Description')
    address = StringField('Address')
    contacts = StringField('Contacts')

class DepartmentForm(FlaskForm):
    number = StringField('Number', validators=[DataRequired()])
    name = StringField('Name')

class StockForm(FlaskForm):
    product = SelectField('Product', coerce=int)
    client = SelectField('Client', coerce=int)
    department = SelectField('Department', coerce=int)
    quantity = IntegerField('Quantity', validators=[DataRequired()])

class UserForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    role = SelectField('Role', choices=[('user', 'User'), ('admin', 'Admin')])

class DepartmentAccessForm(FlaskForm):
    department = SelectField('Department', coerce=int)
    user = SelectField('User', coerce=int)

# Логика
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or current_user.role != 'admin':
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def department_access_required(department_id):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if current_user.role != 'admin' and not DepartmentAccess.query.filter_by(
                user_id=current_user.id, 
                department_id=department_id
            ).first():
                abort(403)
            return f(*args, **kwargs)
        return decorated_function
    return decorator

# Маршруты
@app.route('/')
def home():
    return render_template('home.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        hashed_password = generate_password_hash(form.password.data)
        user = User(username=form.username.data, password_hash=hashed_password)
        db.session.add(user)
        db.session.commit()
        flash('Registration successful!')
        return redirect(url_for('login'))
    return render_template('register.html', form=form)

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user and check_password_hash(user.password_hash, form.password.data):
            login_user(user)
            return redirect(url_for('dashboard'))
        flash('Invalid username or password')
    return render_template('login.html', form=form)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('home'))

@app.route('/dashboard')
@login_required
def dashboard():
    return render_template('dashboard.html')

@app.route('/health')
def health():
    return jsonify(status='OK')

# Админские маршруты
@app.route('/admin/departments', methods=['GET', 'POST'])
@admin_required
def manage_departments():
    form = DepartmentForm()
    if form.validate_on_submit():
        department = Department(number=form.number.data, name=form.name.data)
        db.session.add(department)
        db.session.commit()
        flash('Department added!')
    departments = Department.query.all()
    return render_template('manage_departments.html', form=form, departments=departments)

# Маршруты для товаров
@app.route('/products', methods=['GET', 'POST'])
@login_required
def manage_products():
    form = ProductForm()
    form.client.choices = [(c.id, c.name) for c in Client.query.all()]
    
    if form.validate_on_submit():
        product = Product(
            name=form.name.data,
            description=form.description.data,
            client_id=form.client.data
        )
        db.session.add(product)
        db.session.commit()
        flash('Product added!')
        return redirect(url_for('manage_products'))
    
    products = Product.query.all()
    return render_template('products.html', form=form, products=products)

@app.route('/product/delete/<int:id>', methods=['POST'])
@login_required
def delete_product(id):
    product = Product.query.get_or_404(id)
    if current_user.role != 'admin' and product.client.user_id != current_user.id:
        abort(403)
    
    db.session.delete(product)
    db.session.commit()
    flash('Product deleted!')
    return redirect(url_for('manage_products'))

@app.route('/products-by-client/<int:client_id>')
@login_required
def get_products_by_client(client_id):
    products = Product.query.filter_by(client_id=client_id).all()
    return jsonify({'products': [{'id': p.id, 'name': p.name} for p in products]})

# Маршруты для клиентов
@app.route('/clients', methods=['GET', 'POST'])
@login_required
def manage_clients():
    form = ClientForm()
    if form.validate_on_submit():
        client = Client(
            name=form.name.data,
            description=form.description.data,
            address=form.address.data,
            contacts=form.contacts.data
        )
        db.session.add(client)
        db.session.commit()
        flash('Client added!')
        return redirect(url_for('manage_clients'))
    
    clients = Client.query.all()
    return render_template('clients.html', form=form, clients=clients)


@app.route('/client/delete/<int:id>', methods=['POST'])
@admin_required
def delete_client(id):
    client = Client.query.get_or_404(id)
    db.session.delete(client)
    db.session.commit()
    flash('Client deleted!')
    return redirect(url_for('manage_clients'))



# Маршруты для управления запасами
@app.route('/stock', methods=['GET', 'POST'])
@login_required
def manage_stock():
    form = StockForm()
    # Фильтруем выборки для обычных пользователей
    if current_user.role == 'admin':
        form.client.choices = [(c.id, c.name) for c in Client.query.all()]
        form.department.choices = [(d.id, d.name) for d in Department.query.all()]
    else:
        form.client.choices = [(c.id, c.name) for c in current_user.clients]
        form.department.choices = [(d.id, d.name) for d in current_user.departments]
    
    form.product.choices = [(p.id, p.name) for p in Product.query.filter_by(client_id=form.client.data)]
    
    if form.validate_on_submit():
        stock = Stock.query.filter_by(
            product_id=form.product.data,
            department_id=form.department.data
        ).first()
        
        if stock:
            stock.quantity += form.quantity.data
        else:
            stock = Stock(
                product_id=form.product.data,
                client_id=form.client.data,
                department_id=form.department.data,
                quantity=form.quantity.data
            )
            db.session.add(stock)
        
        db.session.commit()
        flash('Stock updated!')
        return redirect(url_for('manage_stock'))
    
    stocks = Stock.query.all()
    return render_template('stock.html', form=form, stocks=stocks)

# Админские маршруты
@app.route('/admin/users', methods=['GET', 'POST'])
@admin_required
def manage_users():
    users = User.query.all()
    return render_template('admin/users.html', users=users)

@app.route('/admin/grant-access', methods=['GET', 'POST'])
@admin_required
def grant_access():
    form = DepartmentAccessForm()
    form.department.choices = [(d.id, d.name) for d in Department.query.all()]
    form.user.choices = [(u.id, u.username) for u in User.query.filter_by(role='user')]
    
    if form.validate_on_submit():   
        access = DepartmentAccess(
            user_id=form.user.data,
            department_id=form.department.data
        )
        db.session.add(access)
        db.session.commit()
        flash('Access granted!')
    
    return render_template('admin/grant_access.html', form=form)

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        # Создаем админа по умолчанию если нет
        if not User.query.filter_by(username='admin').first():
            admin = User(
                username='admin',
                password_hash=generate_password_hash('admin'),
                role='admin'
            )
            db.session.add(admin)
            db.session.commit()
    app.run(debug=True)
