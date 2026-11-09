# API de Tareas

API RESTful para gestionar una lista de tareas con **Node.js** y **Express**. Las tareas se guardan en `tareas.json` con `fs.promises`, las contraseñas se cifran con **bcryptjs** y las rutas de tareas se protegen con **JWT**.

## Cómo ejecutarla

Requiere Node.js 18 o superior.

```bash
npm install
npm start
```

El servidor escucha en http://localhost:3000.

Para fijar el secreto de los tokens, define la variable `JWT_SECRET` antes de iniciar. Si no está definida, el servidor genera una temporal y los tokens dejan de servir al reiniciarlo.

## Rutas

| Método | Ruta | Token | Descripción |
|---|---|---|---|
| POST | `/register` | No | Registra un usuario: `{ "usuario", "password" }` |
| POST | `/login` | No | Devuelve un JWT válido por 1 hora |
| GET | `/tareas` | Sí | Lista todas las tareas |
| POST | `/tareas` | Sí | Crea una tarea: `{ "titulo", "descripcion" }` |
| PUT | `/tareas/:id` | Sí | Actualiza `titulo`, `descripcion` o `completada` |
| DELETE | `/tareas/:id` | Sí | Elimina una tarea |

El token se envía en el encabezado `Authorization: Bearer <token>`. Los errores responden con `{ "error": "...", "detalles": [...] }` y su código HTTP: 400, 401, 404, 409 o 500.

## Depuración

```bash
npm run debug
```

Inicia el servidor con `node --inspect`. Abre `chrome://inspect` en Chrome y haz clic en **inspect** para poner puntos de interrupción. Además, cada petición se registra en la consola con su código y duración.

## Pruebas con Postman

Importa `postman/API-Tareas.postman_collection.json` y ejecútala con **Run collection** con el servidor encendido.

## Archivos

- `server.js`: servidor, rutas, middleware, autenticación y manejo de errores.
- `tareas.json`: tareas almacenadas por la API.
- `usuarios.json`: se crea al registrar el primer usuario. No se sube al repositorio.
