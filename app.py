import os
from decimal import Decimal
from flask import *
from wtforms import *
from wtforms.validators import *
from flask_wtf import *
from flask_sqlalchemy import SQLAlchemy
import gc
from functools import *
from flask_login import *
from werkzeug.security import *
from sqlalchemy import *
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm.util import join
from werkzeug.utils import secure_filename


ALLOWED_EXTENSIONS = set(['png', 'jpg', 'jpeg'])
app=Flask(__name__)
app.config['UPLOAD_FOLDER'] = os.path.realpath('.') + '/static/uploads'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///./static/test.db'
app.config['WTF_CSRF_SECRET_KEY'] = 'p5YP19TVO2'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = True
db = SQLAlchemy(app)


# Login form to authenticate registered user
class LoginForm(Form):
    username = TextField('Username', [InputRequired()])
    password = PasswordField('Password', [InputRequired()])


# Registration form for New Users
class RegistrationForm(Form):
    username = TextField('Username', [InputRequired()])
    email = TextField('Email', [InputRequired()])
    password = PasswordField('Password', [InputRequired(), EqualTo('confirm', message='Passwords must match')])
    confirm = PasswordField('Confirm Password', [InputRequired()])
    accept_tos = BooleanField('I Accept the <a href="/tos/"> Terms of Service </a> and <a href="/privacy/"> Privacy </a>', [InputRequired()])


# for selecting catgory
class CategoryField(SelectField):
    #widget = CustomCategoryInput()
    def iter_choices(self):
        categories = [(c.id, c.category_name) for c in Category.query.all()]
        for value, label in categories:
            yield (value, label, self.coerce(value) == self.data)

    def pre_validate(self, form):
        for v, _ in [(c.id, c.category_name) for c in Category.query.all()]:
            if self.data == v:
                break
        else:
            raise ValueError(self.gettext('Not a valid choice'))


class ProductForm(Form):
    product_name = TextField('Product Name', validators=[InputRequired()])
    price = DecimalField('Price', validators=[
        InputRequired(), NumberRange(min=Decimal('0.0'))])
    weight = DecimalField('Weight', validators=[InputRequired(),
                                                NumberRange(min=Decimal('0.0'))])
    category = CategoryField('Category', validators=[InputRequired()], coerce=int)
    image = FileField('Product Image')


# ensures that there are not duplicate categories
def check_duplicate_category(case_sensitive=True):
    def _check_duplicate(form, field):
        if case_sensitive:
            res = Category.query.filter(
                Category.category_name.like('%' + field.data + '%')
            ).first()
        else:
            res = Category.query.filter(
                Category.category_name.ilike('%' + field.data + '%')
            ).first()
        if res:
            raise ValidationError(
                'Category named %s already exists' % field.data
            )
    return _check_duplicate


class CategoryForm(Form):
    category = TextField('Name', validators=[InputRequired(), check_duplicate_category()])


# user registration
# Database to store User credentials (table 1)
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100))
    email = db.Column(db.String(100))
    pwdhash = db.Column(db.String())

    def __init__(self, username, email, password):
        self.username = username
        self.email = email
        self.pwdhash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.pwdhash, password)

    def is_authenticated(self):
        return True

    def is_active(self):
        return True

    def is_anonymous(self):
        return False

    def get_id(self):
        return int(self.id)

    def __repr__(self):
        return '<Category %d>' % self.id


# create the product table with foreign keys
# for user and category (table 2)
class Product(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    product_name = db.Column(db.String(255))
    price = db.Column(db.Float)
    weight = db.Column(db.Float)
    category_id = db.Column(db.Integer, db.ForeignKey('category.id'))
    category = db.relationship('Category',
                               backref=db.backref('products', lazy='dynamic'))

    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    user = db.relationship(
        'User', backref = db.backref('user', lazy='dynamic'))
    image_path = db.Column(db.String(255))

    def __init__(self, product_name, price, weight, category, user, image_path):
        self.product_name = product_name
        self.price = price
        self.weight = weight
        self.category = category
        self.user = user
        self.image_path = image_path

    def __repr__(self):
        return '<Product %d>' % self.id


# links products to categories (table 2)
class Category(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    category_name = db.Column(db.String(100))

    def __init__(self, category_name):
        self.category_name = category_name

    def __repr__(self):
        return '<Category %d>' % self.id
db.create_all()
# +++++++++++++++++++++++++++++++++++++++++++


# for flask-login
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
login_manager.session_protection = "strong"
# ++++++++++++++++++++++++++++++++++++++++++++


# management of user sessions
@login_manager.user_loader
def load_user(id):
    return User.query.get(int(id))


@app.before_request
def get_current_user():
    g.user = get_current_user
# ++++++++++++++++++++++++++++++++++++++++++++++


def template_or_json(template=None):
    """"Return a dict from your view and this will either
    pass it to a template or render json. Use like:

    @template_or_json('template.html')
    """
    def decorated(f):
        @wraps(f)
        def decorated_fn(*args, **kwargs):
            ctx = f(*args, **kwargs)
            if request.is_xhr or not template:
                return jsonify(ctx)
            else:
                return render_template(template, **ctx)
        return decorated_fn
    return decorated


def allowed_file(filename):
    return '.' in filename and \
            filename.lower().rsplit('.', 1)[1] in ALLOWED_EXTENSIONS

# error handler
@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404
# ++++++++++++++++++++++++++++++++++++++++++++++++++


# This section handles all View related code
# this route is for the homepage
@app.route('/')
@app.route('/home')
# @template_or_json('home.html')
def home():
    return render_template('home.html')
    # products = Product.query.all()
    # return {'count': len(products)}
# +++++++++++++++++++++++++++++++++++++++++++++++++++


# this route is for allowing users to register
# from the template side
@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        flash('You have to log out first before registering a new account', 'info')
        return redirect(url_for('home'))

    # fetches the registration form
    form = RegistrationForm(request.form)
    if request.method == 'POST' and form.validate():
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')

        existing_username = User.query.filter_by(username=username).first()
        if existing_username:
            flash('This username %s has been already taken. Try another one.' % username, 'warning')
            return render_template('register.html', form=form)

        user = User(username, email, password)
        db.session.add(user)
        db.session.commit()
        flash('You are now registered. Please login.', 'success')
        return redirect(url_for('login'))
    if form.errors:
        flash(form.errors, 'danger')
    return render_template('register.html', form=form)


# this route is for allowing registered users
# to login
@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        flash('You are already logged in.')
        return redirect(url_for('home'))
    # fetches the form for login
    form = LoginForm(request.form)

    # capture credentials from user
    # posts the captured information to the server
    # for validation
    if request.method == 'POST' and form.validate():
        username = request.form.get('username')
        password = request.form.get('password')

        # checks if the provided matches the data in database
        # if not, user prompted to re-enter
        existing_user = User.query.filter_by(username=username).first() # filters db raws by comparing provided username with those in db
        # if the username is not in the db - error
        # if the username is in db but doesnt match provided passwrd - error
        # that is, checks availability of username first
        # before checking if password matches the username
        # doesnt check for password first
        # that's why the username must be unique
        if not (existing_user and existing_user.check_password(password)):
            flash('Invalid username or password. Please try again.', 'danger')
            return render_template('login.html', form=form)
        # if credentials match, a cookies for the user is created
        login_user(existing_user)
        flash('You have successfully logged in.', 'success')
        return redirect(url_for('home'))

    if form.errors:
        flash(form.errors, 'danger')
    return render_template('login.html', form=form)


# this route handles ending session of active user
@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have successfully logged out.', 'success')
    return redirect(url_for('home'))
    gc.collect

@app.route('/product/<id>')
def product(id):
    product = Product.query.get_or_404(id)
    return render_template('product.html', product=product)
    


@app.route('/products')
@app.route('/products/<int:page>')
def products(page=1):
    if current_user.is_authenticated:
        products = Product.query.paginate(page, 10)
        if products == None:
            return flash ("You have not created a product yet")
        return render_template('catalog_page.html', products=products)


@app.route('/product-create', methods=['GET', 'POST'])
@login_required
def create_product():
    form = ProductForm(request.form)

    if form.validate_on_submit():
        product_name = form.product_name.data
        price = form.price.data
        weight = form.weight.data
        category = Category.query.get_or_404(
            form.category.data)
        #use = int(''.join((current_user.get_id())))
        use = User.query.get_or_404(current_user.get_id())

        #if 'file' not in request.files:
            #flah('No File Part')
            #return redirect(url_for('create_product')
                            
        image = request.files['image']
        if image.filename == '':
            flash("No file selected")
            return redirect(url_for('create_product'))
        
        if image and allowed_file(image.filename):
            filename = secure_filename(image.filename)
            image.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
            
        product = Product(product_name, price, weight, category, use, filename)
        db.session.add(product)
        db.session.commit()
        flash('The product %s has been created' % product_name, 'success')
        return redirect(url_for('product', id=product.id))

    if form.errors:
        flash(form.errors, 'danger')

    return render_template('product-create.html', form=form)


@app.route('/product-search')
@app.route('/product-search/<int:page>')
def product_search(page=1):
    name = request.args.get('name')
    price = request.args.get('price')
    company = request.args.get('company')
    category = request.args.get('category')
    products = Product.query
    if name:
        products = products.filter(Product.name.like('%' + name + '%'))
    if price:
        products = products.filter(Product.price == price)
    if company:
        products = products.filter(Product.company.like('%' + company + '%'))
    if category:
        products = products.select_from(join(Product, Category)).filter(
            Category.name.like('%' + category + '%'))
    return render_template(
        'products.html', products=products.paginate(page, 10))


@app.route('/category-create', methods=['GET', 'POST'])
def create_category():
    form = CategoryForm(request.form)

    if form.validate_on_submit():
        category = form.category.data
        category_name = Category(category)
        db.session.add(category_name)
        db.session.commit()
        flash('The category %s has been created' % category, 'success')
        return redirect(url_for('category', id=category_name.id))

    if form.errors:
        flash(form.errors, 'danger')

    return render_template('category-create.html', form=form)


@app.route('/category/<id>')
def category(id):
    category_name = Category.query.get_or_404(id)
    return render_template('category.html', category_name=category_name)
    

@app.route('/categories')
def categories():
    categories = Category.query.all()
    return render_template('categories.html', categories=categories)








if __name__ == '__main__':
    app.secret_key='TlPc6E7afp'
    app.run(debug = True)
