// =========================================================
//  API de Tareas — Node.js, Express, fs.promises y JWT
// =========================================================
const http = require('http');
const path = require('path');
const crypto = require('crypto');
const fs = require('fs').promises;
const express = require('express');
const bodyParser = require('body-parser');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const PUERTO = Number(process.env.PORT) || 3000;
const ARCHIVO_TAREAS = path.join(__dirname, 'tareas.json');
const ARCHIVO_USUARIOS = path.join(__dirname, 'usuarios.json');
const JWT_EXPIRA = '1h';

// Sin JWT_SECRET se genera uno al arrancar: los tokens dejan de servir al reiniciar
const JWT_SECRET = process.env.JWT_SECRET || crypto.randomBytes(32).toString('hex');
if (!process.env.JWT_SECRET) {
  console.warn('[aviso] JWT_SECRET no está definido; se usará uno temporal.');
}

// ---------- Error con código HTTP ----------
class ErrorHttp extends Error {
  constructor(status, mensaje, detalles) {
    super(mensaje);
    this.status = status;
    this.detalles = detalles;
  }
}

// =========================================================
//  Acceso a archivos JSON con fs.promises
// =========================================================
const leerJSON = async (archivo) => {
  try {
    const contenido = await fs.readFile(archivo, 'utf8');
    return JSON.parse(contenido);
  } catch (error) {
    if (error.code === 'ENOENT') return []; // el archivo aún no existe
    throw error;
  }
};

// Escribe en un archivo temporal y luego lo renombra: si el proceso
// se interrumpe a la mitad, el archivo original no queda dañado
const escribirJSON = async (archivo, datos) => {
  const temporal = `${archivo}.tmp`;
  await fs.writeFile(temporal, JSON.stringify(datos, null, 2));
  await fs.rename(temporal, archivo);
};

// Las peticiones llegan en paralelo; esta cola hace que cada
// "leer -> modificar -> escribir" termine antes de que empiece el siguiente
const colas = new Map();
const modificarJSON = (archivo, cambio) => {
  const anterior = colas.get(archivo) || Promise.resolve();
  const siguiente = anterior.then(async () => {
    const datos = await leerJSON(archivo);
    const resultado = await cambio(datos);
    await escribirJSON(archivo, datos);
    return resultado;
  });
  colas.set(archivo, siguiente.catch(() => {}));
  return siguiente;
};

// =========================================================
//  Middleware personalizado
// =========================================================

// Registra cada petición con su código y duración
const registrarPeticiones = (req, res, next) => {
  const inicio = Date.now();
  res.on('finish', () => {
    console.log(`${req.method} ${req.originalUrl} -> ${res.statusCode} (${Date.now() - inicio} ms)`);
  });
  next();
};

// Permite usar async en las rutas: cualquier error llega al manejador
const asincrono = (fn) => (req, res, next) => Promise.resolve(fn(req, res, next)).catch(next);

// Exige "Authorization: Bearer <token>" con un JWT válido
const autenticar = (req, res, next) => {
  const [tipo, token] = (req.headers.authorization || '').split(' ');
  if (tipo !== 'Bearer' || !token) {
    return next(new ErrorHttp(401, 'Acceso denegado: falta el token'));
  }
  try {
    const { sub, usuario } = jwt.verify(token, JWT_SECRET, { algorithms: ['HS256'] });
    req.usuario = { id: sub, usuario };
    return next();
  } catch {
    return next(new ErrorHttp(401, 'Token inválido o expirado'));
  }
};

const esTexto = (valor) => typeof valor === 'string' && valor.trim() !== '';

const validarCredenciales = (req, res, next) => {
  const { usuario, password } = req.body;
  const errores = [];
  if (!esTexto(usuario) || !/^[a-zA-Z0-9_.-]{3,30}$/.test(usuario)) {
    errores.push('El usuario debe tener de 3 a 30 caracteres: letras, números, punto, guion o guion bajo');
  }
  if (typeof password !== 'string' || password.length < 6) {
    errores.push('La contraseña debe tener al menos 6 caracteres');
  }
  if (errores.length > 0) return next(new ErrorHttp(400, 'Datos inválidos', errores));
  return next();
};

// En POST todos los campos son obligatorios; en PUT basta con uno
const validarTarea = (req, res, next) => {
  const parcial = req.method === 'PUT';
  const { titulo, descripcion, completada } = req.body;
  const errores = [];

  if (titulo !== undefined || !parcial) {
    if (!esTexto(titulo)) errores.push('El título es obligatorio');
    else if (titulo.trim().length > 100) errores.push('El título no puede superar 100 caracteres');
  }
  if (descripcion !== undefined || !parcial) {
    if (!esTexto(descripcion)) errores.push('La descripción es obligatoria');
    else if (descripcion.trim().length > 500) errores.push('La descripción no puede superar 500 caracteres');
  }
  if (completada !== undefined && typeof completada !== 'boolean') {
    errores.push('"completada" debe ser true o false');
  }
  if (parcial && [titulo, descripcion, completada].every((campo) => campo === undefined)) {
    errores.push('Envía al menos un campo: titulo, descripcion o completada');
  }

  if (errores.length > 0) return next(new ErrorHttp(400, 'Datos inválidos', errores));
  return next();
};

const validarId = (req, res, next) => {
  const id = Number(req.params.id);
  if (!Number.isInteger(id) || id < 1) return next(new ErrorHttp(400, 'El id debe ser un número entero positivo'));
  req.idTarea = id;
  return next();
};

// =========================================================
//  Aplicación y rutas
// =========================================================
const app = express();
app.use(registrarPeticiones);
app.use(bodyParser.json({ limit: '50kb' }));

app.get('/', (req, res) => {
  res.json({
    mensaje: 'API de Tareas',
    rutas: ['POST /register', 'POST /login', 'GET /tareas', 'POST /tareas', 'PUT /tareas/:id', 'DELETE /tareas/:id'],
  });
});

// ---------- Autenticación ----------
app.post('/register', validarCredenciales, asincrono(async (req, res) => {
  const usuario = req.body.usuario.trim().toLowerCase();
  // El hash se calcula fuera de la cola: bcrypt es lento y no debe frenar otras escrituras
  const hash = await bcrypt.hash(req.body.password, 10);

  const nuevo = await modificarJSON(ARCHIVO_USUARIOS, (usuarios) => {
    if (usuarios.some((u) => u.usuario === usuario)) {
      throw new ErrorHttp(409, 'Ese nombre de usuario ya está registrado');
    }
    const registro = { id: crypto.randomUUID(), usuario, password: hash, creadoEn: new Date().toISOString() };
    usuarios.push(registro);
    return registro;
  });

  res.status(201).json({ mensaje: 'Usuario registrado', usuario: { id: nuevo.id, usuario: nuevo.usuario } });
}));

app.post('/login', validarCredenciales, asincrono(async (req, res) => {
  const usuarios = await leerJSON(ARCHIVO_USUARIOS);
  const registro = usuarios.find((u) => u.usuario === req.body.usuario.trim().toLowerCase());

  // Mismo mensaje en ambos casos para no revelar qué usuarios existen
  if (!registro || !(await bcrypt.compare(req.body.password, registro.password))) {
    throw new ErrorHttp(401, 'Usuario o contraseña incorrectos');
  }

  const token = jwt.sign({ usuario: registro.usuario }, JWT_SECRET, {
    subject: registro.id,
    expiresIn: JWT_EXPIRA,
    algorithm: 'HS256',
  });
  res.json({ mensaje: 'Inicio de sesión correcto', token, expiraEn: JWT_EXPIRA });
}));

// ---------- Tareas (todas protegidas) ----------
const rutasTareas = express.Router();
rutasTareas.use(autenticar);

rutasTareas.get('/', asincrono(async (req, res) => {
  res.json(await leerJSON(ARCHIVO_TAREAS));
}));

rutasTareas.post('/', validarTarea, asincrono(async (req, res) => {
  const { titulo, descripcion } = req.body;
  const tarea = await modificarJSON(ARCHIVO_TAREAS, (tareas) => {
    const nueva = {
      id: tareas.reduce((max, t) => Math.max(max, t.id), 0) + 1,
      titulo: titulo.trim(),
      descripcion: descripcion.trim(),
      completada: false,
      creadaPor: req.usuario.usuario,
      creadaEn: new Date().toISOString(),
      actualizadaEn: null,
    };
    tareas.push(nueva);
    return nueva;
  });
  res.status(201).json(tarea);
}));

rutasTareas.put('/:id', validarId, validarTarea, asincrono(async (req, res) => {
  const { titulo, descripcion, completada } = req.body;
  const tarea = await modificarJSON(ARCHIVO_TAREAS, (tareas) => {
    const encontrada = tareas.find((t) => t.id === req.idTarea);
    if (!encontrada) throw new ErrorHttp(404, `No existe la tarea con id ${req.idTarea}`);
    if (titulo !== undefined) encontrada.titulo = titulo.trim();
    if (descripcion !== undefined) encontrada.descripcion = descripcion.trim();
    if (completada !== undefined) encontrada.completada = completada;
    encontrada.actualizadaEn = new Date().toISOString();
    return encontrada;
  });
  res.json(tarea);
}));

rutasTareas.delete('/:id', validarId, asincrono(async (req, res) => {
  const eliminada = await modificarJSON(ARCHIVO_TAREAS, (tareas) => {
    const indice = tareas.findIndex((t) => t.id === req.idTarea);
    if (indice === -1) throw new ErrorHttp(404, `No existe la tarea con id ${req.idTarea}`);
    return tareas.splice(indice, 1)[0];
  });
  res.json({ mensaje: 'Tarea eliminada', tarea: eliminada });
}));

app.use('/tareas', rutasTareas);

// =========================================================
//  Manejo de errores (siempre al final)
// =========================================================
app.use((req, res, next) => {
  next(new ErrorHttp(404, `Ruta no encontrada: ${req.method} ${req.originalUrl}`));
});

// eslint-disable-next-line no-unused-vars
app.use((error, req, res, next) => {
  let { status = 500, message: mensaje, detalles } = error;

  if (error.type === 'entity.parse.failed') {
    status = 400;
    mensaje = 'El cuerpo de la petición no es un JSON válido';
  } else if (error.type === 'entity.too.large') {
    status = 413;
    mensaje = 'El cuerpo de la petición es demasiado grande';
  } else if (status >= 500) {
    console.error('[error]', error);
    mensaje = 'Error interno del servidor';
  }

  res.status(status).json({ error: mensaje, ...(detalles && { detalles }) });
});

// =========================================================
//  Servidor HTTP
// =========================================================
const servidor = http.createServer(app);

if (require.main === module) {
  servidor.listen(PUERTO, () => {
    console.log(`Servidor escuchando en http://localhost:${PUERTO}`);
  });
}

module.exports = { app, servidor };
