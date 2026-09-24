# Level Up Gamer · API Flask

API REST para la tienda Level Up Gamer. Proporciona autenticación con JWT y operaciones de catálogo, carrito y pedidos sobre PostgreSQL.

## Funcionalidades

- Registro e inicio de sesión.
- Autenticación y autorización mediante JWT.
- Gestión de usuarios y roles administrativos.
- Catálogo de productos y categorías.
- Carrito de compras.
- Creación y consulta de pedidos.
- Creación automática de las tablas necesarias.

## Tecnologías

- Python
- Flask
- PostgreSQL
- Psycopg
- PyJWT
- Flask-CORS

## Configuración

Requisitos: Python 3 y una instancia de PostgreSQL.

```bash
python -m venv .venv
```

Activa el entorno virtual e instala las dependencias:

```bash
pip install -r requirements.txt
```

Crea un archivo `.env` local con tu propia configuración:

```dotenv
DB_HOST=localhost
DB_PORT=5432
DB_NAME=levelup
DB_USER=postgres
DB_PASS=tu_contrasena
JWT_SECRET=una_clave_larga_y_aleatoria
JWT_EXP_HOURS=24
```

No publiques credenciales reales ni el archivo `.env`.

## Ejecución

```bash
python app.py
```

La API queda disponible en la dirección indicada por Flask.

## Seguridad

Este proyecto es una implementación académica. Antes de usarlo fuera de un entorno de desarrollo, rota cualquier credencial expuesta previamente y configura todos los secretos mediante variables de entorno.
