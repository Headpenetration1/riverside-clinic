"""Task A.3.4 / A.4.3 - secure upload and download.

The second TDD scenario: "a patient can never read another patient's file".
"""
import io
import os

from app.extensions import db
from app.models import AuditEvent, Document
from tests.conftest import TINY_JPG, TINY_PDF, TINY_PNG


def upload(client, session, name="referral.pdf", data=TINY_PDF):
    return client.post("/api/documents", headers=session["headers"],
                       data={"file": (io.BytesIO(data), name)}, content_type="multipart/form-data")


# ---------- upload validation ----------

def test_upload_valid_files(client, patient):
    for name, data in (("referral.pdf", TINY_PDF), ("scan.png", TINY_PNG), ("photo.JPG", TINY_JPG)):
        resp = upload(client, patient, name, data)
        assert resp.status_code == 201, resp.get_json()
        body = resp.get_json()
        assert body["size_bytes"] == len(data) and len(body["sha256"]) == 64


def test_upload_rejects_disallowed_types(client, patient):
    for name in ("shell.php", "page.html", "script.js", "evil.pdf.exe", "noext"):
        resp = upload(client, patient, name, TINY_PDF)
        assert resp.status_code == 400, name


def test_upload_rejects_content_that_does_not_match_extension(client, patient):
    html_disguised = b"<html><script>alert('xss')</script></html>"
    resp = upload(client, patient, "innocent.pdf", html_disguised)
    assert resp.status_code == 400
    assert "does not match" in resp.get_json()["error"]


def test_upload_rejects_empty_and_oversized_files(client, patient, app):
    assert upload(client, patient, "empty.pdf", b"").status_code == 400
    too_big = b"%PDF-" + b"0" * (app.config["MAX_CONTENT_LENGTH"] + 1)
    assert upload(client, patient, "huge.pdf", too_big).status_code == 413


def test_upload_requires_authentication(client):
    resp = client.post("/api/documents", data={"file": (io.BytesIO(TINY_PDF), "x.pdf")},
                       content_type="multipart/form-data")
    assert resp.status_code == 401


def test_path_traversal_in_filename_is_neutralised(client, patient, app):
    resp = upload(client, patient, "../../etc/passwd.pdf", TINY_PDF)
    assert resp.status_code == 201
    assert resp.get_json()["filename"] == "etc_passwd.pdf"
    stored = os.listdir(app.config["UPLOAD_DIR"])
    assert len(stored) == 1 and "passwd" not in stored[0] and "/" not in stored[0]


# ---------- storage ----------

def test_file_is_encrypted_on_disk_and_readable_through_the_api(client, patient, app):
    doc_id = upload(client, patient).get_json()["id"]
    stored = os.listdir(app.config["UPLOAD_DIR"])[0]
    with open(os.path.join(app.config["UPLOAD_DIR"], stored), "rb") as fh:
        blob = fh.read()
    assert b"%PDF" not in blob                       # ciphertext, not the plaintext
    assert len(blob) == 12 + len(TINY_PDF) + 16      # nonce + ciphertext + GCM tag
    resp = client.get(f"/api/documents/{doc_id}/download", headers=patient["headers"])
    assert resp.status_code == 200 and resp.data == TINY_PDF


def test_download_headers_prevent_inline_rendering(client, patient):
    doc_id = upload(client, patient, "scan.png", TINY_PNG).get_json()["id"]
    resp = client.get(f"/api/documents/{doc_id}/download", headers=patient["headers"])
    assert resp.headers["Content-Disposition"].startswith("attachment")
    assert "scan.png" in resp.headers["Content-Disposition"]
    assert resp.headers["X-Content-Type-Options"] == "nosniff"
    assert resp.headers["Cache-Control"] == "no-store"
    assert resp.mimetype == "image/png"


def test_tampered_ciphertext_is_not_served(client, patient, app):
    doc_id = upload(client, patient).get_json()["id"]
    path = os.path.join(app.config["UPLOAD_DIR"], os.listdir(app.config["UPLOAD_DIR"])[0])
    with open(path, "r+b") as fh:
        fh.seek(20)
        fh.write(b"\x00\x00")
    resp = client.get(f"/api/documents/{doc_id}/download", headers=patient["headers"])
    assert resp.status_code == 500 and resp.get_json() == {"error": "Internal server error"}


# ---------- authorization (the TDD scenario) ----------

def test_patient_cannot_see_or_download_another_patients_file(client, patient, other_patient):
    doc_id = upload(client, patient).get_json()["id"]
    assert client.get("/api/documents", headers=other_patient["headers"]).get_json() == []
    assert client.get(f"/api/documents/{doc_id}", headers=other_patient["headers"]).status_code == 404
    assert client.get(f"/api/documents/{doc_id}/download", headers=other_patient["headers"]).status_code == 404
    assert client.delete(f"/api/documents/{doc_id}", headers=other_patient["headers"]).status_code == 404
    # and the file is still there for its owner
    assert client.get(f"/api/documents/{doc_id}", headers=patient["headers"]).status_code == 200


def test_clinician_can_read_but_not_delete_patient_files(client, patient, clinician):
    doc_id = upload(client, patient).get_json()["id"]
    assert client.get(f"/api/documents/{doc_id}/download", headers=clinician["headers"]).status_code == 200
    listing = client.get(f"/api/documents?patient_id={patient['id']}", headers=clinician["headers"]).get_json()
    assert [d["id"] for d in listing] == [doc_id]
    assert client.delete(f"/api/documents/{doc_id}", headers=clinician["headers"]).status_code == 403


def test_admin_has_no_access_to_clinical_documents(client, patient, admin):
    doc_id = upload(client, patient).get_json()["id"]
    assert upload(client, admin).status_code == 403
    assert client.get("/api/documents", headers=admin["headers"]).status_code == 403
    assert client.get(f"/api/documents/{doc_id}/download", headers=admin["headers"]).status_code == 403


def test_owner_can_delete_and_file_is_removed_from_disk(client, patient, app):
    doc_id = upload(client, patient).get_json()["id"]
    assert client.delete(f"/api/documents/{doc_id}", headers=patient["headers"]).status_code == 204
    assert os.listdir(app.config["UPLOAD_DIR"]) == []
    with app.app_context():
        assert db.session.get(Document, doc_id) is None


def test_uploads_and_downloads_are_audited(client, patient, clinician, app):
    doc_id = upload(client, patient).get_json()["id"]
    client.get(f"/api/documents/{doc_id}/download", headers=clinician["headers"])
    with app.app_context():
        actions = [(e.action, e.user_id) for e in db.session.scalars(db.select(AuditEvent).order_by(AuditEvent.id))]
    assert ("document.upload", patient["id"]) in actions
    assert ("document.download", clinician["id"]) in actions
