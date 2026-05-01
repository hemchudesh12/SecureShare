from .auth_routes import bp as auth_bp
from .file_routes import bp as file_bp
from .admin_routes import bp as admin_bp

def register_routes(app):
    app.register_blueprint(auth_bp)
    app.register_blueprint(file_bp)
    app.register_blueprint(admin_bp)
