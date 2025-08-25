import os
import sys
from flask import Flask, send_from_directory
from flask_cors import CORS
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from flask import Blueprint, request, jsonify
from functools import wraps
import jwt
from datetime import datetime, timedelta
import pandas as pd
from werkzeug.utils import secure_filename

# Initialize Flask app
app = Flask(__name__, static_folder="static", template_folder="static")
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "supersecretkey")
app.config["MAX_CONTENT_LENGTH"] = 50 * 1024 * 1024  # 50MB max file size

# Enable CORS for all routes
CORS(app)

# Database configuration
database_path = os.path.join(os.path.dirname(__file__), "data", "app.db")
os.makedirs(os.path.dirname(database_path), exist_ok=True)
app.config["SQLALCHEMY_DATABASE_URI"] = f"sqlite:///{database_path}"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

# Initialize database
db = SQLAlchemy(app)

# User Model
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(20), nullable=False, default='search')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    is_active = db.Column(db.Boolean, default=True)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def to_dict(self):
        return {
            'id': self.id,
            'username': self.username,
            'role': self.role,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'is_active': self.is_active
        }

# Inventory Models
class InventoryItem(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    data = db.Column(db.JSON, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def to_dict(self):
        return {
            'id': self.id,
            'data': self.data,
            'created_at': self.created_at.isoformat() if self.created_at else None
        }

class InventoryMeta(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    headers = db.Column(db.JSON, nullable=False)
    total_rows = db.Column(db.Integer, default=0)
    upload_date = db.Column(db.DateTime, default=datetime.utcnow)
    filename = db.Column(db.String(255))

    def to_dict(self):
        return {
            'id': self.id,
            'headers': self.headers,
            'total_rows': self.total_rows,
            'upload_date': self.upload_date.isoformat() if self.upload_date else None,
            'filename': self.filename
        }

# Auth decorator
def require_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('Authorization')
        if not token:
            return jsonify({'error': 'رمز المصادقة مطلوب'}), 401
        
        try:
            if token.startswith('Bearer '):
                token = token[7:]
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
            current_user = User.query.get(data['user_id'])
            if not current_user or not current_user.is_active:
                return jsonify({'error': 'المستخدم غير موجود أو غير نشط'}), 401
        except jwt.ExpiredSignatureError:
            return jsonify({'error': 'انتهت صلاحية رمز المصادقة'}), 401
        except jwt.InvalidTokenError:
            return jsonify({'error': 'رمز المصادقة غير صحيح'}), 401
        
        return f(current_user, *args, **kwargs)
    return decorated

def require_admin(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('Authorization')
        if not token:
            return jsonify({'error': 'رمز المصادقة مطلوب'}), 401
        
        try:
            if token.startswith('Bearer '):
                token = token[7:]
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
            current_user = User.query.get(data['user_id'])
            if not current_user or not current_user.is_active:
                return jsonify({'error': 'المستخدم غير موجود أو غير نشط'}), 401
            if current_user.role != 'admin':
                return jsonify({'error': 'صلاحيات المدير مطلوبة'}), 403
        except jwt.ExpiredSignatureError:
            return jsonify({'error': 'انتهت صلاحية رمز المصادقة'}), 401
        except jwt.InvalidTokenError:
            return jsonify({'error': 'رمز المصادقة غير صحيح'}), 401
        
        return f(current_user, *args, **kwargs)
    return decorated

# Auth routes
@app.route('/api/auth/login', methods=['POST'])
def login():
    try:
        data = request.get_json()
        username = data.get('username')
        password = data.get('password')
        
        if not username or not password:
            return jsonify({'error': 'اسم المستخدم وكلمة المرور مطلوبان'}), 400
        
        user = User.query.filter_by(username=username).first()
        
        if user and user.check_password(password) and user.is_active:
            token = jwt.encode({
                'user_id': user.id,
                'username': user.username,
                'role': user.role,
                'exp': datetime.utcnow() + timedelta(hours=24)
            }, app.config['SECRET_KEY'], algorithm='HS256')
            
            return jsonify({
                'token': token,
                'user': user.to_dict(),
                'message': 'تم تسجيل الدخول بنجاح'
            })
        else:
            return jsonify({'error': 'اسم المستخدم أو كلمة المرور غير صحيحة'}), 401
            
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/auth/verify', methods=['GET'])
@require_auth
def verify_token(current_user):
    return jsonify({
        'valid': True,
        'user': current_user.to_dict()
    })

# User management routes
@app.route('/api/users/', methods=['GET'])
@require_admin
def get_users(current_user):
    try:
        users = User.query.all()
        return jsonify({
            'users': [user.to_dict() for user in users]
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/users/add', methods=['POST'])
@require_admin
def create_user(current_user):
    try:
        data = request.get_json()
        username = data.get('username')
        password = data.get('password')
        role = data.get('role', 'search')
        
        if not username or not password:
            return jsonify({'error': 'اسم المستخدم وكلمة المرور مطلوبان'}), 400
        
        if role not in ['admin', 'search']:
            return jsonify({'error': 'نوع الصلاحية غير صحيح'}), 400
        
        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            return jsonify({'error': 'اسم المستخدم موجود بالفعل'}), 400
        
        user = User(username=username, role=role)
        user.set_password(password)
        
        db.session.add(user)
        db.session.commit()
        
        return jsonify({
            'message': 'تم إضافة المستخدم بنجاح',
            'user': user.to_dict()
        })
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

@app.route('/api/users/<int:user_id>/password', methods=['PUT'])
@require_admin
def update_user_password(current_user, user_id):
    try:
        data = request.get_json()
        new_password = data.get('password')
        
        if not new_password:
            return jsonify({'error': 'كلمة المرور الجديدة مطلوبة'}), 400
            
        user = User.query.get_or_404(user_id)
        user.set_password(new_password)
        db.session.commit()
        
        return jsonify({
            'message': 'تم تحديث كلمة المرور بنجاح',
            'user': user.to_dict()
        })
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

@app.route('/api/users/<int:user_id>', methods=['DELETE'])
@require_admin
def delete_user(current_user, user_id):
    try:
        user = User.query.get_or_404(user_id)
        
        if user.username == 'admin':
            return jsonify({'error': 'لا يمكن حذف المستخدم الإداري الرئيسي'}), 400
        
        if user.role == 'admin':
            admin_count = User.query.filter_by(role='admin', is_active=True).count()
            if admin_count <= 1:
                return jsonify({'error': 'لا يمكن حذف آخر مستخدم إداري'}), 400
        
        db.session.delete(user)
        db.session.commit()
        
        return jsonify({'message': 'تم حذف المستخدم بنجاح'}) 
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

# Inventory routes
@app.route('/api/inventory/search', methods=['POST'])
@require_auth
def search_inventory(current_user):
    try:
        data = request.get_json()
        search_term = data.get('search_term', '').strip()
        
        if not search_term:
            return jsonify({'error': 'مصطلح البحث مطلوب'}), 400
        
        # Search in inventory items
        items = InventoryItem.query.all()
        results = []
        
        for item in items:
            item_data = item.data
            for key, value in item_data.items():
                if search_term.lower() in str(value).lower():
                    results.append({
                        'id': item.id,
                        'data': item_data,
                        'created_at': item.created_at.isoformat() if item.created_at else None
                    })
                    break  
        
        return jsonify({
            'results': results,
            'total': len(results),
            'search_term': search_term
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/inventory/upload', methods=['POST'])
@require_admin
def upload_inventory(current_user):
    try:
        if 'file' not in request.files:
            return jsonify({'error': 'لم يتم اختيار ملف'}), 400
        
        file = request.files['file']
        if file.filename == '':
            return jsonify({'error': 'لم يتم اختيار ملف'}), 400
        
        if file and file.filename.endswith(('.xlsx', '.xls')):
            filename = secure_filename(file.filename)
            
            df = pd.read_excel(file)
            
            InventoryItem.query.delete()
            InventoryMeta.query.delete()
            
            headers = df.columns.tolist()
            meta = InventoryMeta(
                headers=headers,
                total_rows=len(df),
                filename=filename
            )
            db.session.add(meta)
            
            for _, row in df.iterrows():
                item_data = row.to_dict()
                for key, value in item_data.items():
                    if pd.isna(value):
                        item_data[key] = None
                
                item = InventoryItem(data=item_data)
                db.session.add(item)
            
            db.session.commit()
            
            return jsonify({
                'message': f'تم رفع الملف بنجاح وتم معالجة {len(df)} عنصر',
                'processed_count': len(df),
                'headers': headers
            })
        else:
            return jsonify({'error': 'نوع الملف غير مدعوم. يرجى رفع ملف Excel (.xlsx أو .xls)'}), 400
            
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

@app.route('/api/inventory/meta', methods=['GET'])
@require_auth
def get_inventory_meta(current_user):
    try:
        meta = InventoryMeta.query.first()
        if meta:
            return jsonify(meta.to_dict())
        else:
            return jsonify({'message': 'لا توجد بيانات مخزون'}), 404
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# Static file serving
@app.route("/", defaults={"path": ""})
@app.route("/<path:path>")
def serve(path):
    static_folder_path = app.static_folder
    if static_folder_path is None:
        return "Static folder not configured", 404

    if path != "" and os.path.exists(os.path.join(static_folder_path, path)):
        return send_from_directory(static_folder_path, path)
    else:
        index_path = os.path.join(static_folder_path, "index.html")
        if os.path.exists(index_path):
            return send_from_directory(static_folder_path, "index.html")
        else:
            return "index.html not found", 404

# Create database tables and default admin if they don't exist
with app.app_context():
    db.create_all()
    admin_user = User.query.filter_by(username="admin").first()
    if not admin_user:
        admin = User(username="admin", role="admin")
        admin.set_password("admin2025")
        db.session.add(admin)
        db.session.commit()
        print("Default admin user created: admin/admin2025")

# للتشغيل المحلي فقط
if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=True)

