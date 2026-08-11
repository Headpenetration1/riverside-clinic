from flask import Flask


def register_blueprints(app: Flask) -> None:
    from . import admin, auth, patients

    app.register_blueprint(auth.bp)
    app.register_blueprint(patients.bp)
    app.register_blueprint(admin.bp)
