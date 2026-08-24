"""HTML interface (cookie auth + CSRF) and the GDPR data-subject endpoints."""
import io
import os

from app.extensions import db
from app.models import Document, User
from tests.conftest import TINY_PDF, csrf_from


def test_pages_redirect_to_login_when_not_authenticated(client):
    for path in ("/dashboard", "/board", "/chat"):
        resp = client.get(path)
        assert resp.status_code == 302 and resp.headers["Location"].endswith("/login")


def test_html_login_sets_httponly_cookie_and_dashboard_works(client, make_user, page_login):
    make_user("alice@example.com")
    page_login("alice@example.com")
    cookie = client.get_cookie("access_token")
    assert cookie is not None and cookie.http_only and cookie.same_site == "Lax"
    resp = client.get("/dashboard")
    assert resp.status_code == 200 and b"No documents yet" in resp.data


def test_html_login_rejects_wrong_password_and_missing_csrf(client, make_user):
    make_user("alice@example.com")
    assert client.post("/login", data={"email": "alice@example.com", "password": "x"}).status_code == 400
    token = csrf_from(client.get("/login").data)
    resp = client.post("/login", data={"csrf_token": token, "email": "alice@example.com", "password": "wrong-wrong-wrong"})
    assert resp.status_code == 401 and b"Invalid email or password" in resp.data


def test_html_upload_and_download(client, make_user, page_login):
    make_user("alice@example.com")
    token = page_login("alice@example.com")
    resp = client.post("/dashboard/upload", data={"csrf_token": token, "file": (io.BytesIO(TINY_PDF), "letter.pdf")},
                       content_type="multipart/form-data")
    assert resp.status_code == 302
    page = client.get("/dashboard").data.decode()
    assert "letter.pdf" in page
    download = client.get("/download/1")
    assert download.status_code == 200 and download.data == TINY_PDF


def test_registration_page_creates_patient(client, app):
    token = csrf_from(client.get("/register").data)
    resp = client.post("/register", data={"csrf_token": token, "email": "new@example.com",
                                          "full_name": "New Person", "password": "twelve-char-phrase"})
    assert resp.status_code == 302
    with app.app_context():
        assert db.session.scalar(db.select(User).where(User.email == "new@example.com")).role == "patient"


def test_export_returns_only_my_data(client, patient, other_patient, app):
    client.post("/api/documents", headers=patient["headers"],
                data={"file": (io.BytesIO(TINY_PDF), "mine.pdf")}, content_type="multipart/form-data")
    client.post("/api/messages", headers=patient["headers"], json={"body": "hello"})
    export = client.get("/api/me/export", headers=other_patient["headers"]).get_json()
    assert export["user"]["email"] == "mallory@example.com"
    assert export["documents"] == [] and export["messages"] == []
    mine = client.get("/api/me/export", headers=patient["headers"]).get_json()
    assert [d["filename"] for d in mine["documents"]] == ["mine.pdf"]
    assert [m["body"] for m in mine["messages"]] == ["hello"]
    assert any(e["action"] == "auth.login" for e in mine["audit_events"])
    assert "password_hash" not in str(mine)


def test_delete_account_removes_user_documents_and_files(client, patient, app):
    client.post("/api/documents", headers=patient["headers"],
                data={"file": (io.BytesIO(TINY_PDF), "mine.pdf")}, content_type="multipart/form-data")
    assert client.delete("/api/me", headers=patient["headers"]).status_code == 204
    assert client.get("/api/auth/me", headers=patient["headers"]).status_code == 401
    assert os.listdir(app.config["UPLOAD_DIR"]) == []
    with app.app_context():
        assert db.session.get(User, patient["id"]) is None
        assert db.session.scalars(db.select(Document)).all() == []


def test_unknown_api_route_returns_json_not_html(client):
    resp = client.get("/api/does-not-exist")
    assert resp.status_code == 404 and resp.mimetype == "application/json"
