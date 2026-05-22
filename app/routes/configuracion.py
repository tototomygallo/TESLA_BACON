from datetime import datetime
import re
from typing import Any
from uuid import uuid4

from fastapi import APIRouter, Depends, Header, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.database import get_db
from app.models import RolUsuario, Usuario
from app.routes.auth import hash_password, validar_password_fuerte

router = APIRouter(prefix="/configuracion", tags=["Configuración"])


class UsuarioResponse(BaseModel):
    id: str
    username: str
    name: str
    email: str
    rol: str
    active: bool


class UsuarioCrearRequest(BaseModel):
    username: str
    name: str
    email: str
    rol: RolUsuario
    password: str
    active: bool = True


class UsuarioActualizarRequest(BaseModel):
    username: Any = None
    name: Any = None
    email: Any = None
    rol: Any = None
    active: Any = None


class ResetPasswordRequest(BaseModel):
    passwordNueva: str


def _usuario_to_response(usuario: Usuario) -> UsuarioResponse:
    return UsuarioResponse(
        id=usuario.id,
        username=usuario.username,
        name=usuario.name,
        email=usuario.email,
        rol=usuario.rol,
        active=bool(usuario.active),
    )


def _campos_enviados(body: BaseModel) -> set[str]:
    return getattr(body, "model_fields_set", getattr(body, "__fields_set__", set()))


def _validar_email(email: str) -> bool:
    return re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", email) is not None


def _require_admin(
    db: Session,
    x_user_id: str | None,
) -> Usuario:
    if not x_user_id:
        raise HTTPException(status_code=401, detail="Falta X-User-Id")

    usuario = db.query(Usuario).filter(Usuario.id == x_user_id).first()
    if not usuario:
        usuario = (
            db.query(Usuario)
            .filter(Usuario.username == x_user_id.strip().lower())
            .first()
        )

    if not usuario or usuario.active == False:
        raise HTTPException(status_code=401, detail="Usuario no autorizado")

    if usuario.rol != RolUsuario.admin.value:
        raise HTTPException(status_code=403, detail="Solo administradores")

    return usuario


@router.get("/usuarios", response_model=list[UsuarioResponse])
def listar_usuarios(
    db: Session = Depends(get_db),
    x_user_id: str | None = Header(default=None),
):
    _require_admin(db, x_user_id)
    usuarios = db.query(Usuario).order_by(Usuario.username.asc()).all()
    return [_usuario_to_response(usuario) for usuario in usuarios]


@router.post("/usuarios", response_model=UsuarioResponse)
def crear_usuario(
    body: UsuarioCrearRequest,
    db: Session = Depends(get_db),
    x_user_id: str | None = Header(default=None),
):
    _require_admin(db, x_user_id)

    username = body.username.strip().lower()
    if len(username) < 3:
        raise HTTPException(status_code=422, detail="El usuario debe tener al menos 3 caracteres")
    validar_password_fuerte(body.password)

    existente = db.query(Usuario).filter(Usuario.username == username).first()
    if existente:
        raise HTTPException(status_code=409, detail="Ya existe un usuario con ese username")

    ahora = datetime.now()
    usuario = Usuario(
        id=str(uuid4()),
        username=username,
        name=body.name.strip(),
        email=str(body.email),
        rol=body.rol.value,
        password_hash=hash_password(body.password),
        active=body.active,
        password_changed_at=ahora,
        force_password_change=False,
        created_at=ahora,
        updated_at=ahora,
    )
    db.add(usuario)
    db.commit()
    db.refresh(usuario)
    return _usuario_to_response(usuario)


@router.patch("/usuarios/{usuario_id}", response_model=UsuarioResponse)
def actualizar_usuario(
    usuario_id: str,
    body: UsuarioActualizarRequest,
    db: Session = Depends(get_db),
    x_user_id: str | None = Header(default=None),
):
    _require_admin(db, x_user_id)

    usuario = db.query(Usuario).filter(Usuario.id == usuario_id).first()
    if not usuario:
        raise HTTPException(status_code=404, detail="Usuario no encontrado")

    campos = _campos_enviados(body)

    if "username" in campos:
        if not isinstance(body.username, str) or not body.username.strip():
            raise HTTPException(status_code=422, detail="El username no puede estar vacío")
        username = body.username.strip().lower()
        if len(username) < 3:
            raise HTTPException(status_code=422, detail="El usuario debe tener al menos 3 caracteres")
        existente = (
            db.query(Usuario)
            .filter(Usuario.username == username, Usuario.id != usuario_id)
            .first()
        )
        if existente:
            raise HTTPException(status_code=409, detail="Ya existe un usuario con ese username")
        usuario.username = username

    if "name" in campos:
        if not isinstance(body.name, str) or not body.name.strip():
            raise HTTPException(status_code=422, detail="El nombre no puede estar vacío")
        usuario.name = body.name.strip()

    if "email" in campos:
        if not isinstance(body.email, str) or not body.email.strip():
            raise HTTPException(status_code=422, detail="El email no puede estar vacío")
        email = body.email.strip()
        if not _validar_email(email):
            raise HTTPException(status_code=422, detail="El email debe tener un formato válido")
        usuario.email = email

    if "rol" in campos:
        roles_validos = {rol.value for rol in RolUsuario}
        if body.rol not in roles_validos:
            raise HTTPException(status_code=422, detail="El rol debe ser tecnico, bioquimico o admin")
        usuario.rol = body.rol

    if "active" in campos:
        if not isinstance(body.active, bool):
            raise HTTPException(status_code=422, detail="active debe ser boolean")
        usuario.active = body.active

    usuario.updated_at = datetime.now()

    db.commit()
    db.refresh(usuario)
    return _usuario_to_response(usuario)


@router.post("/usuarios/{usuario_id}/reset-password")
def reset_password_usuario(
    usuario_id: str,
    body: ResetPasswordRequest,
    db: Session = Depends(get_db),
    x_user_id: str | None = Header(default=None),
):
    _require_admin(db, x_user_id)

    validar_password_fuerte(body.passwordNueva)

    usuario = db.query(Usuario).filter(Usuario.id == usuario_id).first()
    if not usuario:
        raise HTTPException(status_code=404, detail="Usuario no encontrado")

    usuario.password_hash = hash_password(body.passwordNueva)
    usuario.password_changed_at = datetime.now()
    usuario.force_password_change = True
    usuario.updated_at = datetime.now()
    db.commit()
    return {"ok": True}


@router.delete("/usuarios/{usuario_id}")
def eliminar_usuario(
    usuario_id: str,
    db: Session = Depends(get_db),
    x_user_id: str | None = Header(default=None),
):
    admin = _require_admin(db, x_user_id)
    if admin.id == usuario_id:
        raise HTTPException(status_code=422, detail="No podés eliminar tu propio usuario")

    usuario = db.query(Usuario).filter(Usuario.id == usuario_id).first()
    if not usuario:
        raise HTTPException(status_code=404, detail="Usuario no encontrado")

    db.delete(usuario)
    db.commit()
    return {"ok": True}
