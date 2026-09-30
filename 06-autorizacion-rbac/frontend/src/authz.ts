/**
 * 🔓 COMPLETÁS VOS — la autorización en la INTERFAZ.
 *
 * El módulo te enseñó que la SEGURIDAD vive en el SERVER (dependencies.py
 * y los controllers): si el server está roto, ocultar botones no protege
 * nada. PERO una UI profesional también respeta la matriz — no es
 * seguridad, es UX honesta: no mostrás una acción que el server va a
 * rechazar con 403.
 *
 * ESTADO ACTUAL (como el backend): TODO devuelve `true` a propósito.
 * La UI "dice que sí" siempre: te muestra el botón BORRAR aunque seas
 * viewer, el panel de USUARIOS a cualquiera, y acciones de escritura
 * aunque tu token sea "read" solamente.
 *
 * 🔴 Probalo ANTES de completar: logueate como viewer, mirá cómo la UI
 * te ofrece BORRAR y ADMINISTRAR USUARIOS. Clickleá: el server (recién
 * cuando completes el backend) responde 403. La UI y el server deben
 * quedar ALINEADOS.
 *
 * ✅ TU TRABAJO: que cada helper devuelva lo que la MATRIZ (SPEC.md,
 * sección 3) espera. Son 6 funciones; el resto de la UI ya las usa.
 * Compará SIEMPRE con lo que responde el server en vivo.
 *
 * La matriz en una línea:
 *
 *   | helper              | admin | editor | viewer |
 *   |---------------------|:-----:|:------:|:------:|
 *   | scopeAllowsWrite    |  ✅   |   ✅   |   ❌   |  (depende del TOKEN, no del rol)
 *   | canManageUsers      |  ✅   |   ❌   |   ❌   |
 *   | canChangeRole       |  ✅   |   ❌   |   ❌   |
 *   | canDelete           |  ✅   |   ❌   |   ❌   |
 *   | canEdit (doc ajeno) |  ✅   |   ❌   |   ❌   |
 *   | canEdit (doc propio)|  ✅   |   ✅   |   ✅   |
 *   | canPublish          |  ✅   |  ✅ (lo suyo) | ❌ |
 */

import type { DocumentRead, Role } from "./types";

/**
 * ¿Este TOKEN puede escribir? El scope viaja en el JWT
 * ("read" | "read write") y lo limita el LOGIN, no el rol:
 * un admin puede loguearse con scope "read" y quedar SOLO LECTURA.
 */
export function scopeAllowsWrite(scope: string | undefined): boolean {
  // CODIGO VIEJO:
  // return true;
  
  // CODIGO NUEVO (UX: Scope):
  // Comprueba si el string del scope existe y si al separarlo por espacios incluye "write".
  if (!scope) return false;
  return scope.split(" ").includes("write");
}

/** ¿Puede ver el panel de usuarios (GET /api/users)? Solo admin. */
export function canManageUsers(role: Role | undefined): boolean {
  // CODIGO VIEJO:
  // return true;

  // CODIGO NUEVO (UX: Deny-by-default):
  // Oculta el panel a cualquier rol que no sea explícitamente "admin".
  return role === "admin";
}

/** ¿Puede cambiar el rol de otro usuario (PATCH /users/{id}/role)? Solo admin. */
export function canChangeRole(role: Role | undefined): boolean {
  // CODIGO VIEJO:
  // return true;

  // CODIGO NUEVO (UX: Deny-by-default):
  return role === "admin";
}

/** ¿Puede BORRAR documentos (DELETE /api/documents/{id})? Solo admin. */
export function canDelete(role: Role | undefined): boolean {
  // CODIGO VIEJO:
  // return true;

  // CODIGO NUEVO (UX: Deny-by-default):
  return role === "admin";
}

/**
 * ¿Puede EDITAR un documento? Regla de la matriz:
 *   - el DUEÑO siempre puede (object-level)
 *   - el ADMIN puede editar cualquiera de su empresa
 *   - un editor NO edita el privado de otro → false
 */
export function canEdit(userId: number, doc: DocumentRead, role: Role | undefined): boolean {
  // CODIGO VIEJO:
  // return true;

  // NUEVO (UX: Object-level y Rol):
  // Habilita el botón si sos el dueño legítimo del documento o si sos administrador.
  return doc.owner_id === userId || role === "admin";
}

/**
 * ¿Puede PUBLICAR un documento? Misma regla que editar
 * (dueño o admin) — pero fijate que el viewer queda afuera
 * por su scope "read", que también bloquea la UI con scopeAllowsWrite.
 */
export function canPublish(userId: number, doc: DocumentRead, role: Role | undefined): boolean {
  // CODIGO VIEJO:
  // return true;

  // CODIGO NUEVO (UX: Object-level y Rol):
  return doc.owner_id === userId || role === "admin";
}