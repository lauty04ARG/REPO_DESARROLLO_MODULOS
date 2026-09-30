"""
Controller de DOCUMENTOS — el recurso protegido (object-level + scopes).

┌─────────────────────────────────────────────────────────────────────────┐
│ 🔓 COMPLETÁS VOS: ESTE es el archivo más importante de la entrega.     │
│                                                                         │
│   POST   /api/documents            → crear     (scope "write")          │
│   GET    /api/documents            → listar    (públicos + los tuyos)   │
│   GET    /api/documents/{id}       → ver       (dueño / admin / público)│
│   PATCH  /api/documents/{id}       → editar    (dueño o admin, "write") │
│   DELETE /api/documents/{id}       → borrar    (admin, "write")         │
│   POST   /api/documents/{id}/publish → publicar (dueño o admin, "write")│
│                                                                         │
│ 🔴 El estado actual es el ATACANTE A01 del OWASP: **IDOR**.             │
│    Cualquier autenticado que conozca el id lee/edita/borra TODO.        │
│    Probalo: logueate como viewer@acme.com y pedí GET /api/documents/5   │
│    (el plan secreto de Globex) → responde 200. LUSTRADA.                │
│                                                                         │
│ ✅ TU TRABAJO, en cada endpoint:                                        │
│    1. SCOPE: los que modifican datos exigen Depends(require_scope("write"))│
│    2. TENANCY: si document.tenant_id != current_user.tenant_id → 403   │
│       (aplica SIEMPRE, incluso para documentos públicos)               │
│    3. OBJECT-LEVEL: si es privado → solo dueño (owner_id == tu id) o    │
│       admin del tenant. Si no → 403.                                   │
│    4. ROL: DELETE exige admin (matriz) — el resto de los GRISES salen  │
│       del scope: viewer tiene scope "read" → ya no llega a crear.      │
│                                                                         │
│ 🧠 Pregunta para la defensa: ¿por qué acá el 403 va DESPUÉS del 404?   │
│    (si un id no existe, no hay nada que proteger — pero en producción  │
│    algunos devuelven 404 también en cross-tenant para no filtrar       │
│    existencia. Acá usamos 403 para que la lección sea VISIBLE).        │
└─────────────────────────────────────────────────────────────────────────┘
"""

from fastapi import APIRouter, Depends, HTTPException, status

from app import storage
from app.dependencies import get_current_user, require_role, require_scope
from app.models import DocumentCreate, DocumentRead, DocumentUpdate, Role, User

router = APIRouter(prefix="/api", tags=["3 · Documentos"])


@router.post(
    "/documents",
    response_model=DocumentRead,
    status_code=status.HTTP_201_CREATED,
)
def create_document(
    body: DocumentCreate,
    # CODIGO VIEJO 
    # current_user: User = Depends(get_current_user),  
    
    # scope
    # Exigimos que el token del usuario tenga el permiso "write". 
    # Un token de solo lectura ("read") no debe poder crear recursos.
    current_user: User = Depends(require_scope("write")),
):
    """Crea un documento: draft privado a nombre tuyo, en TU empresa."""
    return storage.create_document(owner=current_user, body=body)


@router.get("/documents", response_model=list[DocumentRead])
def list_documents(
    current_user: User = Depends(get_current_user),
):
    """Lista lo que PODES ver: públicos de tu empresa + tus documentos."""
    # Este endpoint ya es seguro porque la funcion list_documents de storage
    # filtra internamente por current_user.tenant_id y current_user.id.
    return storage.list_documents(
        tenant_id=current_user.tenant_id,
        user_id=current_user.id,
    )


@router.get("/documents/{doc_id}", response_model=DocumentRead)
def get_document(
    doc_id: int,
    current_user: User = Depends(get_current_user),
):
    """Ve un documento por id. Aca se mitiga el IDOR."""
    doc = storage.get_document(doc_id)
    if doc is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Documento no encontrado")
    
    # CODIGO VIEJO 
    # return doc
    # (Permitia IDOR: cualquier usuario autenticado leia cualquier documento secreto)

    # CODIGO NUEVO (tenancy + object-level):
    # Tenancy: Bloqueamos inmediatamente si el documento es de otra empresa.
    if doc.tenant_id != current_user.tenant_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN, 
            detail="No puedes ver documentos de otra empresa"
        )

    # verificamos si es el dueño o un admin.
    # Si es publico, el if no se cumple y pasa directo al return.
    if doc.visibility == "private":
        is_owner = (doc.owner_id == current_user.id)
        is_admin = (current_user.role == Role.ADMIN)
        
        if not is_owner and not is_admin:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN, 
                detail="No tienes permiso para ver este documento privado"
            )

    return doc


@router.patch("/documents/{doc_id}", response_model=DocumentRead)
def update_document(
    doc_id: int,
    body: DocumentUpdate,
    # CODIGO VIEJO
    # current_user: User = Depends(get_current_user),
    
    # CODIGO NUEVO SCOPE
    # Modificar un documento requiere permisos de escritura en el token.
    current_user: User = Depends(require_scope("write")),
):
    """Edita un documento: solo el DUEÑO o un ADMIN de la empresa."""
    doc = storage.get_document(doc_id)
    if doc is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Documento no encontrado")
    
    # CODIGO NUEVO (aplico tenancy + object-level):
    if doc.tenant_id != current_user.tenant_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN, 
            detail="No puedes editar documentos de otra empresa"
        )
        
    is_owner = (doc.owner_id == current_user.id)
    is_admin = (current_user.role == Role.ADMIN)
    if not is_owner and not is_admin:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN, 
            detail="Solo el dueño o un administrador pueden editar este documento"
        )

    return storage.update_document(doc_id, body)


@router.delete("/documents/{doc_id}", response_model=DocumentRead)
def delete_document(
    doc_id: int,
    # viejo 
    # current_user: User = Depends(get_current_user),
    
    # CODIGO NUEVO (ROL + SCOPE):
    # Borrar es destructivo: exige que el usuario sea ADMIN y que el token tenga permiso write.
    current_user: User = Depends(require_role(Role.ADMIN)),
    _scope_check: User = Depends(require_scope("write")),
):
    """Borra un documento: SOLO admin."""
    doc = storage.get_document(doc_id)
    if doc is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Documento no encontrado")
    
    # TENANCY
    # Un admin solo tiene jurisdiccion destructiva en su propia empresa.
    if doc.tenant_id != current_user.tenant_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN, 
            detail="No puedes borrar documentos de otra empresa"
        )

    deleted = storage.delete_document(doc_id)
    return deleted


@router.post("/documents/{doc_id}/publish", response_model=DocumentRead)
def publish_document(
    doc_id: int,
    # COD  viejo
    # current_user: User = Depends(get_current_user),
    
    # SCOPE 
    current_user: User = Depends(require_scope("write")),
):
    """Publica un documento: el DUEÑO publica lo suyo; el admin, cualquiera."""
    doc = storage.get_document(doc_id)
    if doc is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Documento no encontrado")
    
    # CODIGO NUEVO (TENANCY + OBJECT-LEVEL):
    if doc.tenant_id != current_user.tenant_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN, 
            detail="No puedes publicar documentos de otra empresa"
        )
        
    is_owner = (doc.owner_id == current_user.id)
    is_admin = (current_user.role == Role.ADMIN)
    if not is_owner and not is_admin:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN, 
            detail="Solo el dueño o un administrador pueden publicar este documento"
        )

    return storage.set_document_published(doc_id, True)