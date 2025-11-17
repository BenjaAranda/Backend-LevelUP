# app.py
import os
import sys
import datetime
from functools import wraps

from flask import Flask, request, jsonify
from flask_cors import CORS
import psycopg2
from psycopg2.extras import RealDictCursor
from werkzeug.security import generate_password_hash, check_password_hash
import jwt
from dotenv import load_dotenv

# Cargar .env si existe
load_dotenv()

# ---------------------------
# CONFIG / CREDENCIALES RDS
# ---------------------------
DB_HOST = os.getenv("DB_HOST", "localhost")
DB_NAME = os.getenv("DB_NAME", "postgres")
DB_USER = os.getenv("DB_USER", "postgres")
DB_PASS = os.getenv("DB_PASS", "REDACTED_DB_PASSWORD")
DB_PORT = int(os.getenv("DB_PORT", 5432))

# Secret para JWT (en producción ponlo en variable de entorno segura)
JWT_SECRET = os.getenv("JWT_SECRET", "REDACTED_JWT_SECRET")
JWT_ALGORITHM = "HS256"
JWT_EXP_HOURS = int(os.getenv("JWT_EXP_HOURS", 24))

app = Flask(__name__)
CORS(app)


# ---------------------------
# DB utility
# ---------------------------
def get_db_connection():
    try:
        conn = psycopg2.connect(
            host=DB_HOST,
            database=DB_NAME,
            user=DB_USER,
            password=DB_PASS,
            port=DB_PORT
        )
        return conn
    except Exception as e:
        print(f"Error al conectar a la BD: {e}", file=sys.stderr)
        return None


# ---------------------------
# Crear tablas si no existen
# ---------------------------
def create_tables():
    conn = get_db_connection()
    if conn is None:
        print("No se pudo conectar a la BD para crear tablas.", file=sys.stderr)
        return
    try:
        cur = conn.cursor()
        cur.execute("""
        CREATE TABLE IF NOT EXISTS categories (
            id SERIAL PRIMARY KEY,
            name VARCHAR(150) UNIQUE NOT NULL
        );
        """)
        cur.execute("""
        CREATE TABLE IF NOT EXISTS products (
            id SERIAL PRIMARY KEY,
            name VARCHAR(255) NOT NULL,
            description TEXT DEFAULT '',
            price NUMERIC(12,2) NOT NULL,
            stock INTEGER DEFAULT 0,
            category_id INTEGER REFERENCES categories(id) ON DELETE SET NULL,
            image_url TEXT DEFAULT '',
            created_at TIMESTAMP DEFAULT NOW()
        );
        """)
        cur.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id SERIAL PRIMARY KEY,
            email VARCHAR(255) UNIQUE NOT NULL,
            pass VARCHAR(255) NOT NULL,
            name VARCHAR(255),
            is_admin BOOLEAN DEFAULT FALSE,
            has_duoc_discount BOOLEAN DEFAULT FALSE,
            created_at TIMESTAMP DEFAULT NOW()
        );
        """)
        cur.execute("""
        CREATE TABLE IF NOT EXISTS cart_items (
            id SERIAL PRIMARY KEY,
            user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
            product_id INTEGER REFERENCES products(id) ON DELETE CASCADE,
            quantity INTEGER NOT NULL CHECK (quantity > 0),
            added_at TIMESTAMP DEFAULT NOW(),
            UNIQUE(user_id, product_id)
        );
        """)
        cur.execute("""
        CREATE TABLE IF NOT EXISTS orders (
            id SERIAL PRIMARY KEY,
            user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
            total NUMERIC(12,2) NOT NULL,
            status VARCHAR(50) DEFAULT 'PENDING',
            created_at TIMESTAMP DEFAULT NOW()
        );
        """)
        cur.execute("""
        CREATE TABLE IF NOT EXISTS order_items (
            id SERIAL PRIMARY KEY,
            order_id INTEGER REFERENCES orders(id) ON DELETE CASCADE,
            product_id INTEGER REFERENCES products(id) ON DELETE SET NULL,
            quantity INTEGER NOT NULL CHECK (quantity > 0),
            unit_price NUMERIC(12,2) NOT NULL
        );
        """)
        conn.commit()
        cur.close()
        conn.close()
        print("Tablas verificadas/creadas correctamente.")
    except Exception as e:
        print(f"Error creando tablas: {e}", file=sys.stderr)
        try:
            conn.rollback()
            cur.close()
            conn.close()
        except Exception:
            pass


# ---------------------------
# Helpers (JWT)
# ---------------------------
def generate_token(user_id, email, is_admin=False):
    payload = {
        "sub": user_id,
        "email": email,
        "is_admin": is_admin,
        "exp": datetime.datetime.utcnow() + datetime.timedelta(hours=JWT_EXP_HOURS)
    }
    token = jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)
    # PyJWT >=2 returns str, but ensure string for compatibility
    if isinstance(token, bytes):
        token = token.decode("utf-8")
    return token


def decode_token(token):
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        return payload
    except jwt.ExpiredSignatureError:
        return None
    except Exception:
        return None


def auth_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        auth = request.headers.get("Authorization", None)
        if not auth:
            return jsonify({"success": False, "message": "Token no proporcionado"}), 401
        parts = auth.split()
        if len(parts) != 2 or parts[0].lower() != "bearer":
            return jsonify({"success": False, "message": "Header Authorization inválido"}), 401
        token = parts[1]
        payload = decode_token(token)
        if not payload:
            return jsonify({"success": False, "message": "Token inválido o expirado"}), 401
        request.user = payload
        return f(*args, **kwargs)
    return decorated


def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not hasattr(request, "user"):
            return jsonify({"success": False, "message": "No autenticado"}), 401
        if not request.user.get("is_admin", False):
            return jsonify({"success": False, "message": "Acceso denegado: admin only"}), 403
        return f(*args, **kwargs)
    return decorated


# ---------------------------
# Routes: REGISTER / LOGIN
# ---------------------------
@app.route("/api/register", methods=["POST"])
def register_user():
    data = request.get_json()
    if not data:
        return jsonify({"success": False, "message": "No se enviaron datos"}), 400

    email = data.get("email", "").strip().lower()
    password = data.get("pass", "").strip()
    name = data.get("name", "").strip()
    has_duoc = bool(data.get("has_duoc_discount", False))

    if not email:
        return jsonify({"success": False, "message": "El correo es obligatorio"}), 400
    if "@" not in email:
        return jsonify({"success": False, "message": "El correo no es válido"}), 400
    if not password or len(password) < 4:
        return jsonify({"success": False, "message": "La contraseña es obligatoria (mín 4 caracteres)"}), 400

    conn = get_db_connection()
    if conn is None:
        return jsonify({"success": False, "message": "Error al conectar a la base de datos"}), 500

    try:
        cur = conn.cursor()
        cur.execute("SELECT id FROM users WHERE email = %s", (email,))
        if cur.fetchone():
            cur.close()
            conn.close()
            return jsonify({"success": False, "message": "El correo ya está registrado"}), 409

        hashed = generate_password_hash(password)
        cur.execute(
            "INSERT INTO users (email, pass, name, has_duoc_discount) VALUES (%s, %s, %s, %s) RETURNING id",
            (email, hashed, name if name else None, has_duoc)
        )
        user_id = cur.fetchone()[0]
        conn.commit()
        cur.close()
        conn.close()

        token = generate_token(user_id, email, False)
        return jsonify({"success": True, "message": "Usuario registrado exitosamente", "data": {"token": token}}), 201
    except Exception as e:
        try:
            conn.rollback()
            cur.close()
            conn.close()
        except Exception:
            pass
        return jsonify({"success": False, "message": f"Error interno: {e}"}), 500


@app.route("/api/login", methods=["POST"])
def login_user():
    data = request.get_json()
    if not data:
        return jsonify({"success": False, "message": "No se enviaron datos"}), 400

    email = data.get("email", "").strip().lower()
    password = data.get("pass", "").strip()

    if not email or not password:
        return jsonify({"success": False, "message": "Correo y contraseña obligatorios"}), 400

    conn = get_db_connection()
    if conn is None:
        return jsonify({"success": False, "message": "Error al conectar a la base de datos"}), 500

    try:
        cur = conn.cursor(cursor_factory=RealDictCursor)
        cur.execute("SELECT id, email, pass, is_admin, has_duoc_discount, name FROM users WHERE email = %s", (email,))
        user = cur.fetchone()
        cur.close()
        conn.close()
        if not user:
            return jsonify({"success": False, "message": "Credenciales inválidas"}), 401
        if not check_password_hash(user["pass"], password):
            return jsonify({"success": False, "message": "Credenciales inválidas"}), 401

        token = generate_token(user["id"], user["email"], user["is_admin"])
        # no devolver pass en la respuesta
        user.pop("pass", None)
        return jsonify({"success": True, "message": "Login correcto", "data": {"token": token, "user": user}}), 200
    except Exception as e:
        try:
            cur.close()
            conn.close()
        except Exception:
            pass
        return jsonify({"success": False, "message": f"Error interno: {e}"}), 500


# ---------------------------
# Products & Categories
# ---------------------------
@app.route("/api/categories", methods=["GET"])
def list_categories():
    conn = get_db_connection()
    if conn is None:
        return jsonify({"success": False, "message": "Error BD"}), 500
    try:
        cur = conn.cursor(cursor_factory=RealDictCursor)
        cur.execute("SELECT id, name FROM categories ORDER BY name")
        rows = cur.fetchall()
        cur.close()
        conn.close()
        return jsonify({"success": True, "data": rows}), 200
    except Exception as e:
        return jsonify({"success": False, "message": str(e)}), 500


@app.route("/api/categories", methods=["POST"])
@auth_required
@admin_required
def create_category():
    data = request.get_json() or {}
    name = data.get("name", "").strip()
    if not name:
        return jsonify({"success": False, "message": "Nombre de categoría requerido"}), 400
    conn = get_db_connection()
    try:
        cur = conn.cursor()
        cur.execute("INSERT INTO categories (name) VALUES (%s) RETURNING id", (name,))
        cat_id = cur.fetchone()[0]
        conn.commit()
        cur.close()
        conn.close()
        return jsonify({"success": True, "message": "Categoría creada", "data": {"id": cat_id, "name": name}}), 201
    except Exception as e:
        conn.rollback()
        return jsonify({"success": False, "message": str(e)}), 500


@app.route("/api/products", methods=["GET"])
def list_products():
    # Soporta búsqueda y filtro por category_id
    q = request.args.get("q", "").strip()
    category_id = request.args.get("category_id", None)
    conn = get_db_connection()
    try:
        cur = conn.cursor(cursor_factory=RealDictCursor)
        sql = "SELECT p.id, p.name, p.description, p.price, p.stock, p.category_id, c.name as category_name, p.image_url FROM products p LEFT JOIN categories c ON p.category_id = c.id"
        params = []
        where = []
        if q:
            where.append("(p.name ILIKE %s OR p.description ILIKE %s)")
            params.extend([f"%{q}%", f"%{q}%"])
        if category_id:
            where.append("p.category_id = %s")
            params.append(int(category_id))
        if where:
            sql += " WHERE " + " AND ".join(where)
        sql += " ORDER BY p.created_at DESC"
        cur.execute(sql, tuple(params))
        rows = cur.fetchall()
        cur.close()
        conn.close()
        return jsonify({"success": True, "data": rows}), 200
    except Exception as e:
        return jsonify({"success": False, "message": str(e)}), 500


@app.route("/api/products/<int:product_id>", methods=["GET"])
def get_product(product_id):
    conn = get_db_connection()
    try:
        cur = conn.cursor(cursor_factory=RealDictCursor)
        cur.execute("SELECT id, name, description, price, stock, category_id, image_url FROM products WHERE id = %s", (product_id,))
        row = cur.fetchone()
        cur.close()
        conn.close()
        if not row:
            return jsonify({"success": False, "message": "Producto no encontrado"}), 404
        return jsonify({"success": True, "data": row}), 200
    except Exception as e:
        return jsonify({"success": False, "message": str(e)}), 500


@app.route("/api/products", methods=["POST"])
@auth_required
@admin_required
def create_product():
    data = request.get_json() or {}
    name = data.get("name", "").strip()
    description = data.get("description", "").strip()
    price = data.get("price", None)
    stock = int(data.get("stock", 0))
    category_id = data.get("category_id", None)
    image_url = data.get("image_url", "")

    if not name or price is None:
        return jsonify({"success": False, "message": "Nombre y precio son obligatorios"}), 400

    conn = get_db_connection()
    try:
        cur = conn.cursor()
        cur.execute(
            "INSERT INTO products (name, description, price, stock, category_id, image_url) VALUES (%s,%s,%s,%s,%s,%s) RETURNING id",
            (name, description, price, stock, category_id, image_url)
        )
        pid = cur.fetchone()[0]
        conn.commit()
        cur.close()
        conn.close()
        return jsonify({"success": True, "message": "Producto creado", "data": {"id": pid}}), 201
    except Exception as e:
        conn.rollback()
        return jsonify({"success": False, "message": str(e)}), 500


@app.route("/api/products/<int:product_id>", methods=["PUT"])
@auth_required
@admin_required
def update_product(product_id):
    data = request.get_json() or {}
    fields = []
    params = []
    for key in ("name", "description", "price", "stock", "category_id", "image_url"):
        if key in data:
            fields.append(f"{key} = %s")
            params.append(data[key])
    if not fields:
        return jsonify({"success": False, "message": "Nada para actualizar"}), 400
    params.append(product_id)
    sql = f"UPDATE products SET {', '.join(fields)} WHERE id = %s"
    conn = get_db_connection()
    try:
        cur = conn.cursor()
        cur.execute(sql, tuple(params))
        conn.commit()
        cur.close()
        conn.close()
        return jsonify({"success": True, "message": "Producto actualizado"}), 200
    except Exception as e:
        conn.rollback()
        return jsonify({"success": False, "message": str(e)}), 500


@app.route("/api/products/<int:product_id>", methods=["DELETE"])
@auth_required
@admin_required
def delete_product(product_id):
    conn = get_db_connection()
    try:
        cur = conn.cursor()
        cur.execute("DELETE FROM products WHERE id = %s", (product_id,))
        affected = cur.rowcount
        conn.commit()
        cur.close()
        conn.close()
        if affected == 0:
            return jsonify({"success": False, "message": "Producto no encontrado"}), 404
        return jsonify({"success": True, "message": "Producto eliminado"}), 200
    except Exception as e:
        conn.rollback()
        return jsonify({"success": False, "message": str(e)}), 500


# ---------------------------
# Cart endpoints (user)
# ---------------------------
@app.route("/api/cart", methods=["GET"])
@auth_required
def get_cart():
    user_id = request.user.get("sub")
    conn = get_db_connection()
    try:
        cur = conn.cursor(cursor_factory=RealDictCursor)
        cur.execute("""
            SELECT ci.id, ci.quantity, p.id as product_id, p.name, p.price, p.stock, p.image_url
            FROM cart_items ci
            JOIN products p ON ci.product_id = p.id
            WHERE ci.user_id = %s
        """, (user_id,))
        items = cur.fetchall()
        cur.close()
        conn.close()
        return jsonify({"success": True, "data": items}), 200
    except Exception as e:
        return jsonify({"success": False, "message": str(e)}), 500


@app.route("/api/cart", methods=["POST"])
@auth_required
def add_to_cart():
    user_id = request.user.get("sub")
    data = request.get_json() or {}
    product_id = data.get("product_id")
    quantity = int(data.get("quantity", 1))
    if not product_id or quantity <= 0:
        return jsonify({"success": False, "message": "product_id y quantity son requeridos"}), 400

    conn = get_db_connection()
    try:
        cur = conn.cursor()
        # check stock
        cur.execute("SELECT stock FROM products WHERE id = %s", (product_id,))
        r = cur.fetchone()
        if not r:
            cur.close()
            conn.close()
            return jsonify({"success": False, "message": "Producto no encontrado"}), 404
        stock = r[0]
        if stock < quantity:
            cur.close()
            conn.close()
            return jsonify({"success": False, "message": "Stock insuficiente"}), 409

        # insert or update
        cur.execute("SELECT id, quantity FROM cart_items WHERE user_id = %s AND product_id = %s", (user_id, product_id))
        row = cur.fetchone()
        if row:
            new_q = row[1] + quantity
            cur.execute("UPDATE cart_items SET quantity = %s WHERE id = %s", (new_q, row[0]))
        else:
            cur.execute("INSERT INTO cart_items (user_id, product_id, quantity) VALUES (%s,%s,%s)", (user_id, product_id, quantity))
        conn.commit()
        cur.close()
        conn.close()
        return jsonify({"success": True, "message": "Producto agregado al carrito"}), 201
    except Exception as e:
        conn.rollback()
        return jsonify({"success": False, "message": str(e)}), 500


@app.route("/api/cart/<int:item_id>", methods=["DELETE"])
@auth_required
def remove_cart_item(item_id):
    user_id = request.user.get("sub")
    conn = get_db_connection()
    try:
        cur = conn.cursor()
        cur.execute("DELETE FROM cart_items WHERE id = %s AND user_id = %s", (item_id, user_id))
        affected = cur.rowcount
        conn.commit()
        cur.close()
        conn.close()
        if affected == 0:
            return jsonify({"success": False, "message": "Elemento no encontrado"}), 404
        return jsonify({"success": True, "message": "Elemento eliminado del carrito"}), 200
    except Exception as e:
        conn.rollback()
        return jsonify({"success": False, "message": str(e)}), 500


# ---------------------------
# Orders
# ---------------------------
@app.route("/api/orders", methods=["POST"])
@auth_required
def create_order():
    user_id = request.user.get("sub")
    # toma los items actuales del carrito y crea una orden
    conn = get_db_connection()
    try:
        cur = conn.cursor(cursor_factory=RealDictCursor)
        cur.execute("""
            SELECT ci.product_id, ci.quantity, p.price, p.stock, p.name
            FROM cart_items ci
            JOIN products p ON ci.product_id = p.id
            WHERE ci.user_id = %s
        """, (user_id,))
        items = cur.fetchall()
        if not items:
            cur.close()
            conn.close()
            return jsonify({"success": False, "message": "El carrito está vacío"}), 400

        total = 0
        for it in items:
            if it["stock"] < it["quantity"]:
                cur.close()
                conn.close()
                return jsonify({"success": False, "message": f"Stock insuficiente para {it['name']}"}), 409
            total += float(it["price"]) * int(it["quantity"])

        # insertar orden
        cur.execute("INSERT INTO orders (user_id, total) VALUES (%s, %s) RETURNING id", (user_id, total))
        order_id = cur.fetchone()["id"]

        # insertar order_items y decrementar stock
        for it in items:
            cur.execute("INSERT INTO order_items (order_id, product_id, quantity, unit_price) VALUES (%s,%s,%s,%s)",
                        (order_id, it["product_id"], it["quantity"], it["price"]))
            cur.execute("UPDATE products SET stock = stock - %s WHERE id = %s", (it["quantity"], it["product_id"]))

        # limpiar carrito
        cur.execute("DELETE FROM cart_items WHERE user_id = %s", (user_id,))
        conn.commit()
        cur.close()
        conn.close()
        return jsonify({"success": True, "message": "Orden creada", "data": {"order_id": order_id, "total": total}}), 201
    except Exception as e:
        conn.rollback()
        return jsonify({"success": False, "message": str(e)}), 500


@app.route("/api/orders", methods=["GET"])
@auth_required
def list_orders():
    user_id = request.user.get("sub")
    conn = get_db_connection()
    try:
        cur = conn.cursor(cursor_factory=RealDictCursor)
        cur.execute("SELECT id, total, status, created_at FROM orders WHERE user_id = %s ORDER BY created_at DESC", (user_id,))
        orders = cur.fetchall()
        cur.close()
        conn.close()
        return jsonify({"success": True, "data": orders}), 200
    except Exception as e:
        return jsonify({"success": False, "message": str(e)}), 500


@app.route("/api/orders/<int:order_id>", methods=["GET"])
@auth_required
def get_order(order_id):
    user_id = request.user.get("sub")
    conn = get_db_connection()
    try:
        cur = conn.cursor(cursor_factory=RealDictCursor)
        cur.execute("SELECT id, total, status, created_at FROM orders WHERE id = %s AND user_id = %s", (order_id, user_id))
        order = cur.fetchone()
        if not order:
            cur.close()
            conn.close()
            return jsonify({"success": False, "message": "Orden no encontrada"}), 404
        cur.execute("SELECT oi.product_id, oi.quantity, oi.unit_price, p.name FROM order_items oi LEFT JOIN products p ON oi.product_id = p.id WHERE oi.order_id = %s", (order_id,))
        items = cur.fetchall()
        cur.close()
        conn.close()
        order["items"] = items
        return jsonify({"success": True, "data": order}), 200
    except Exception as e:
        return jsonify({"success": False, "message": str(e)}), 500


# ---------------------------
# Admin: List users (example)
# ---------------------------
@app.route("/api/admin/users", methods=["GET"])
@auth_required
@admin_required
def list_users():
    conn = get_db_connection()
    try:
        cur = conn.cursor(cursor_factory=RealDictCursor)
        cur.execute("SELECT id, email, name, is_admin, has_duoc_discount, created_at FROM users ORDER BY created_at DESC")
        rows = cur.fetchall()
        cur.close()
        conn.close()
        return jsonify({"success": True, "data": rows}), 200
    except Exception as e:
        return jsonify({"success": False, "message": str(e)}), 500


# ---------------------------
# Root / health
# ---------------------------
@app.route("/api/health", methods=["GET"])
def health():
    return jsonify({"success": True, "message": "API funcionando"}), 200


# ---------------------------
# Run server
# ---------------------------
if __name__ == "__main__":
    print("Iniciando servidor Flask...")
    create_tables()
    # ejecuta en 0.0.0.0 para ser accesible desde emulador y red local
    app.run(host="0.0.0.0", port=5000, debug=True)
