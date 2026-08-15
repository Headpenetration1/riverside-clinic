"""Document rules shared by the JSON API and the HTML pages.

Authorization matrix:
- patient   : own documents only (read, upload, delete)
- clinician : read any patient's documents, upload their own; cannot delete others'
- admin     : manages accounts, has NO access to clinical documents (least privilege)

Unauthorised access to a specific document returns 404, not 403, so an
attacker iterating over IDs cannot even learn which IDs exist.
"""
from flask import abort

from ..extensions import db
from ..models import Document, User
from .audit import record
from .files import (
    FileValidationError,
    load_decrypted,
    remove_stored,
    sha256_hex,
    store_encrypted,
    validate_upload,
)


def create_document(user: User, filename: str | None, data: bytes) -> Document:
    if user.role == "admin":
        abort(403, description="Administrators cannot upload clinical documents")
    safe_name, mime = validate_upload(filename, data)   # raises FileValidationError
    doc = Document(
        owner_id=user.id,
        original_name=safe_name,
        stored_name=store_encrypted(data),
        mime_type=mime,
        size_bytes=len(data),
        sha256=sha256_hex(data),
    )
    db.session.add(doc)
    db.session.flush()
    record("document.upload", target=f"document:{doc.id}", user=user)
    return doc


def list_documents(user: User, patient_id: int | None = None) -> list[Document]:
    if user.role == "admin":
        abort(403, description="Administrators cannot view clinical documents")
    stmt = db.select(Document).order_by(Document.uploaded_at.desc())
    if user.role == "patient":
        stmt = stmt.where(Document.owner_id == user.id)
    elif patient_id is not None:
        stmt = stmt.where(Document.owner_id == patient_id)
    return list(db.session.scalars(stmt))


def get_document(user: User, doc_id: int, *, write: bool = False) -> Document:
    if user.role == "admin":
        abort(403, description="Administrators cannot access clinical documents")
    doc = db.session.get(Document, doc_id)
    if doc is None:
        abort(404, description="Document not found")
    if user.role == "patient" and doc.owner_id != user.id:
        abort(404, description="Document not found")       # deliberately not 403
    if write and doc.owner_id != user.id:
        abort(403, description="Only the owner can modify this document")
    return doc


def read_document(user: User, doc_id: int) -> tuple[Document, bytes]:
    doc = get_document(user, doc_id)
    data = load_decrypted(doc.stored_name)
    record("document.download", target=f"document:{doc.id}", user=user)
    return doc, data


def delete_document(user: User, doc_id: int) -> None:
    doc = get_document(user, doc_id, write=True)
    remove_stored(doc.stored_name)
    db.session.delete(doc)
    record("document.delete", target=f"document:{doc_id}", user=user)


__all__ = [
    "FileValidationError", "create_document", "list_documents", "get_document",
    "read_document", "delete_document",
]
