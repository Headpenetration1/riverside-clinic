from flask import Flask


def register_blueprints(app: Flask) -> None:
    from . import admin, auth, documents, password_reset, patients

    app.register_blueprint(auth.bp)
    app.register_blueprint(password_reset.bp)
    app.register_blueprint(documents.bp)
    app.register_blueprint(patients.bp)
    app.register_blueprint(admin.bp)
