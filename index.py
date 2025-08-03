from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta
import os
from functools import wraps

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key-change-in-production'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///ecommerce.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['JWT_SECRET_KEY'] = 'jwt-secret-string'
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(hours=24)

db = SQLAlchemy(app)
jwt = JWTManager(app)

# Models
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(120), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Relationships
    orders = db.relationship('Order', backref='user', lazy=True)
    cart_items = db.relationship('CartItem', backref='user', lazy=True)

class Category(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text)
    
    # Relationships
    products = db.relationship('Product', backref='category', lazy=True)

class Product(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text)
    price = db.Column(db.Float, nullable=False)
    stock = db.Column(db.Integer, nullable=False, default=0)
    category_id = db.Column(db.Integer, db.ForeignKey('category.id'), nullable=False)
    image_url = db.Column(db.String(300))
    is_active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    def to_dict(self):
        return {
            'id': self.id,
            'name': self.name,
            'description': self.description,
            'price': self.price,
            'stock': self.stock,
            'category_id': self.category_id,
            'category_name': self.category.name if self.category else None,
            'image_url': self.image_url,
            'is_active': self.is_active
        }

class CartItem(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    product_id = db.Column(db.Integer, db.ForeignKey('product.id'), nullable=False)
    quantity = db.Column(db.Integer, nullable=False, default=1)
    added_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Relationships
    product = db.relationship('Product', backref='cart_items')

class Order(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    total_amount = db.Column(db.Float, nullable=False)
    status = db.Column(db.String(50), default='pending')  # pending, confirmed, shipped, delivered, cancelled
    shipping_address = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Relationships
    order_items = db.relationship('OrderItem', backref='order', lazy=True, cascade='all, delete-orphan')

class OrderItem(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    order_id = db.Column(db.Integer, db.ForeignKey('order.id'), nullable=False)
    product_id = db.Column(db.Integer, db.ForeignKey('product.id'), nullable=False)
    quantity = db.Column(db.Integer, nullable=False)
    price = db.Column(db.Float, nullable=False)  # Price at time of order
    
    # Relationships
    product = db.relationship('Product', backref='order_items')

# Decorators
def admin_required(f):
    @wraps(f)
    @jwt_required()
    def decorated_function(*args, **kwargs):
        user_id = get_jwt_identity()
        user = User.query.get(user_id)
        if not user or not user.is_admin:
            return jsonify({'message': 'Admin access required'}), 403
        return f(*args, **kwargs)
    return decorated_function

# Authentication Routes
@app.route('/api/register', methods=['POST'])
def register():
    data = request.get_json()
    
    if User.query.filter_by(username=data['username']).first():
        return jsonify({'message': 'Username already exists'}), 400
    
    if User.query.filter_by(email=data['email']).first():
        return jsonify({'message': 'Email already registered'}), 400
    
    user = User(
        username=data['username'],
        email=data['email'],
        password_hash=generate_password_hash(data['password'])
    )
    
    db.session.add(user)
    db.session.commit()
    
    return jsonify({'message': 'User registered successfully'}), 201

@app.route('/api/login', methods=['POST'])
def login():
    data = request.get_json()
    user = User.query.filter_by(username=data['username']).first()
    
    if user and check_password_hash(user.password_hash, data['password']):
        access_token = create_access_token(identity=user.id)
        return jsonify({
            'access_token': access_token,
            'user': {
                'id': user.id,
                'username': user.username,
                'email': user.email,
                'is_admin': user.is_admin
            }
        })
    
    return jsonify({'message': 'Invalid credentials'}), 401

# Product Routes
@app.route('/api/products', methods=['GET'])
def get_products():
    category_id = request.args.get('category_id')
    search = request.args.get('search')
    page = int(request.args.get('page', 1))
    per_page = int(request.args.get('per_page', 10))
    
    query = Product.query.filter_by(is_active=True)
    
    if category_id:
        query = query.filter_by(category_id=category_id)
    
    if search:
        query = query.filter(Product.name.contains(search))
    
    products = query.paginate(page=page, per_page=per_page, error_out=False)
    
    return jsonify({
        'products': [product.to_dict() for product in products.items],
        'total': products.total,
        'pages': products.pages,
        'current_page': page
    })

@app.route('/api/products/<int:product_id>', methods=['GET'])
def get_product(product_id):
    product = Product.query.get_or_404(product_id)
    return jsonify(product.to_dict())

@app.route('/api/products', methods=['POST'])
@admin_required
def create_product():
    data = request.get_json()
    
    product = Product(
        name=data['name'],
        description=data.get('description'),
        price=data['price'],
        stock=data['stock'],
        category_id=data['category_id'],
        image_url=data.get('image_url')
    )
    
    db.session.add(product)
    db.session.commit()
    
    return jsonify(product.to_dict()), 201

@app.route('/api/products/<int:product_id>', methods=['PUT'])
@admin_required
def update_product(product_id):
    product = Product.query.get_or_404(product_id)
    data = request.get_json()
    
    product.name = data.get('name', product.name)
    product.description = data.get('description', product.description)
    product.price = data.get('price', product.price)
    product.stock = data.get('stock', product.stock)
    product.category_id = data.get('category_id', product.category_id)
    product.image_url = data.get('image_url', product.image_url)
    product.is_active = data.get('is_active', product.is_active)
    
    db.session.commit()
    
    return jsonify(product.to_dict())

@app.route('/api/products/<int:product_id>', methods=['DELETE'])
@admin_required
def delete_product(product_id):
    product = Product.query.get_or_404(product_id)
    product.is_active = False
    db.session.commit()
    
    return jsonify({'message': 'Product deactivated'})

# Category Routes
@app.route('/api/categories', methods=['GET'])
def get_categories():
    categories = Category.query.all()
    return jsonify([{
        'id': cat.id,
        'name': cat.name,
        'description': cat.description,
        'product_count': len(cat.products)
    } for cat in categories])

@app.route('/api/categories', methods=['POST'])
@admin_required
def create_category():
    data = request.get_json()
    
    category = Category(
        name=data['name'],
        description=data.get('description')
    )
    
    db.session.add(category)
    db.session.commit()
    
    return jsonify({
        'id': category.id,
        'name': category.name,
        'description': category.description
    }), 201

# Cart Routes
@app.route('/api/cart', methods=['GET'])
@jwt_required()
def get_cart():
    user_id = get_jwt_identity()
    cart_items = CartItem.query.filter_by(user_id=user_id).all()
    
    cart_data = []
    total = 0
    
    for item in cart_items:
        item_total = item.product.price * item.quantity
        total += item_total
        
        cart_data.append({
            'id': item.id,
            'product': item.product.to_dict(),
            'quantity': item.quantity,
            'item_total': item_total
        })
    
    return jsonify({
        'items': cart_data,
        'total': total
    })

@app.route('/api/cart', methods=['POST'])
@jwt_required()
def add_to_cart():
    user_id = get_jwt_identity()
    data = request.get_json()
    
    product = Product.query.get_or_404(data['product_id'])
    
    if product.stock < data['quantity']:
        return jsonify({'message': 'Insufficient stock'}), 400
    
    # Check if item already in cart
    existing_item = CartItem.query.filter_by(
        user_id=user_id,
        product_id=data['product_id']
    ).first()
    
    if existing_item:
        existing_item.quantity += data['quantity']
    else:
        cart_item = CartItem(
            user_id=user_id,
            product_id=data['product_id'],
            quantity=data['quantity']
        )
        db.session.add(cart_item)
    
    db.session.commit()
    
    return jsonify({'message': 'Item added to cart'}), 201

@app.route('/api/cart/<int:item_id>', methods=['PUT'])
@jwt_required()
def update_cart_item(item_id):
    user_id = get_jwt_identity()
    data = request.get_json()
    
    cart_item = CartItem.query.filter_by(id=item_id, user_id=user_id).first_or_404()
    
    if cart_item.product.stock < data['quantity']:
        return jsonify({'message': 'Insufficient stock'}), 400
    
    cart_item.quantity = data['quantity']
    db.session.commit()
    
    return jsonify({'message': 'Cart updated'})

@app.route('/api/cart/<int:item_id>', methods=['DELETE'])
@jwt_required()
def remove_from_cart(item_id):
    user_id = get_jwt_identity()
    cart_item = CartItem.query.filter_by(id=item_id, user_id=user_id).first_or_404()
    
    db.session.delete(cart_item)
    db.session.commit()
    
    return jsonify({'message': 'Item removed from cart'})

# Order Routes
@app.route('/api/orders', methods=['POST'])
@jwt_required()
def create_order():
    user_id = get_jwt_identity()
    data = request.get_json()
    
    # Get cart items
    cart_items = CartItem.query.filter_by(user_id=user_id).all()
    
    if not cart_items:
        return jsonify({'message': 'Cart is empty'}), 400
    
    # Calculate total and check stock
    total_amount = 0
    for item in cart_items:
        if item.product.stock < item.quantity:
            return jsonify({'message': f'Insufficient stock for {item.product.name}'}), 400
        total_amount += item.product.price * item.quantity
    
    # Create order
    order = Order(
        user_id=user_id,
        total_amount=total_amount,
        shipping_address=data['shipping_address']
    )
    
    db.session.add(order)
    db.session.flush()  # Get order ID
    
    # Create order items and update stock
    for item in cart_items:
        order_item = OrderItem(
            order_id=order.id,
            product_id=item.product_id,
            quantity=item.quantity,
            price=item.product.price
        )
        db.session.add(order_item)
        
        # Update product stock
        item.product.stock -= item.quantity
    
    # Clear cart
    CartItem.query.filter_by(user_id=user_id).delete()
    
    db.session.commit()
    
    return jsonify({
        'order_id': order.id,
        'total_amount': order.total_amount,
        'status': order.status
    }), 201

@app.route('/api/orders', methods=['GET'])
@jwt_required()
def get_orders():
    user_id = get_jwt_identity()
    orders = Order.query.filter_by(user_id=user_id).order_by(Order.created_at.desc()).all()
    
    orders_data = []
    for order in orders:
        order_items = []
        for item in order.order_items:
            order_items.append({
                'product_name': item.product.name,
                'quantity': item.quantity,
                'price': item.price,
                'total': item.price * item.quantity
            })
        
        orders_data.append({
            'id': order.id,
            'total_amount': order.total_amount,
            'status': order.status,
            'created_at': order.created_at.isoformat(),
            'items': order_items
        })
    
    return jsonify(orders_data)

@app.route('/api/orders/<int:order_id>', methods=['GET'])
@jwt_required()
def get_order(order_id):
    user_id = get_jwt_identity()
    order = Order.query.filter_by(id=order_id, user_id=user_id).first_or_404()
    
    order_items = []
    for item in order.order_items:
        order_items.append({
            'product_name': item.product.name,
            'quantity': item.quantity,
            'price': item.price,
            'total': item.price * item.quantity
        })
    
    return jsonify({
        'id': order.id,
        'total_amount': order.total_amount,
        'status': order.status,
        'shipping_address': order.shipping_address,
        'created_at': order.created_at.isoformat(),
        'items': order_items
    })

# Admin Routes
@app.route('/api/admin/orders', methods=['GET'])
@admin_required
def admin_get_orders():
    orders = Order.query.order_by(Order.created_at.desc()).all()
    
    orders_data = []
    for order in orders:
        orders_data.append({
            'id': order.id,
            'user_id': order.user_id,
            'username': order.user.username,
            'total_amount': order.total_amount,
            'status': order.status,
            'created_at': order.created_at.isoformat()
        })
    
    return jsonify(orders_data)

@app.route('/api/admin/orders/<int:order_id>/status', methods=['PUT'])
@admin_required
def update_order_status(order_id):
    order = Order.query.get_or_404(order_id)
    data = request.get_json()
    
    order.status = data['status']
    db.session.commit()
    
    return jsonify({'message': 'Order status updated'})

# Initialize database
@app.before_first_request
def create_tables():
    db.create_all()
    
    # Create default admin user if not exists
    if not User.query.filter_by(username='admin').first():
        admin = User(
            username='admin',
            email='admin@example.com',
            password_hash=generate_password_hash('admin123'),
            is_admin=True
        )
        db.session.add(admin)
        db.session.commit()

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        
        # Create default admin user if not exists
        if not User.query.filter_by(username='admin').first():
            admin = User(
                username='admin',
                email='admin@example.com',
                password_hash=generate_password_hash('admin123'),
                is_admin=True
            )
            db.session.add(admin)
            db.session.commit()
        
        # Create sample categories
        if not Category.query.first():
            categories = [
                Category(name='Electronics', description='Electronic devices and gadgets'),
                Category(name='Clothing', description='Fashion and apparel'),
                Category(name='Books', description='Books and educational materials'),
                Category(name='Home & Garden', description='Home improvement and gardening')
            ]
            for cat in categories:
                db.session.add(cat)
            db.session.commit()
    
    app.run(debug=True)