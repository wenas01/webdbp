import express from 'express';
import admin from 'firebase-admin';
import fetch from 'node-fetch';
import cookieParser from 'cookie-parser';
import dotenv from 'dotenv';
import path from 'path';

dotenv.config();

// ------------ Configuración Firebase Admin -------------
const serviceAccount = JSON.parse(process.env.SERVICE_ACCOUNT_JSON);
admin.initializeApp({
  credential: admin.credential.cert(serviceAccount),
});

const db = admin.firestore();

const app = express();
// ---------------- Configuración Express ----------------
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser(process.env.COOKIE_SECRET));
app.use(express.static(path.resolve('public')));
app.set('view engine', 'ejs');
app.set('views', path.resolve('views'));

app.use((req, res, next) => {
  if (Buffer.isBuffer(req.body)) {
    const contentType = req.headers['content-type'];

    try {
      if (contentType?.includes('application/json')) {
        req.body = JSON.parse(req.body.toString('utf8'));
      } else if (contentType?.includes('application/x-www-form-urlencoded')) {
        req.body = Object.fromEntries(new URLSearchParams(req.body.toString('utf8')));
      }
    } catch (err) {
      console.error('Error parsing body:', err.message);
      return res.status(400).json({ error: 'Invalid body format' });
    }
  }

  next();
});

// ---------------- Middleware ----------------
async function checkAuth(req, res, next) {
  const token = req.signedCookies.__session;
  if (!token) return res.redirect('/login');
  try {
    const decoded = await admin.auth().verifyIdToken(token);
    req.user = decoded;
    next();
  } catch (error) {
    console.error('Token inválido:', error);
    res.redirect('/login');
  }
}

export async function addUserToLocals(req, res, next) {
  const token = req.signedCookies.__session;
  if (token) {
    try {
      const decoded = await admin.auth().verifyIdToken(token);
      res.locals.user = decoded;
      req.user = decoded;
    } catch (error) {
      res.locals.user = null;
    }
  } else {
    res.locals.user = null;
  }
  next();
}

app.use(addUserToLocals);

// ---------------- Rutas ----------------

// Página principal
app.get('/', async (req, res) => {
  try {
    const snapshot = await db.collection("temas").get();
    const temas = snapshot.docs.map(doc => ({
      id: doc.id,
      ...doc.data()
    }));
    res.render('index', { title: 'Estrés Académico - Información, Causas y Soluciones', temas });
  } catch (error) {
    res.status(500).send(error.message);
  }
});

// Registro
app.get('/signup', (req, res) => {
  res.render('signup', {
    title: 'Registro de Usuario',
    error: null
  });
});


app.post('/signup', async (req, res) => {
  const { email, password, nombre, fechaNacimiento } = req.body;
  try {
    const userRecord = await admin.auth().createUser({
      email,
      password,
      displayName: nombre,
    });

    await db.collection('usuarios').doc(userRecord.uid).set({
      nombre,
      correo: email,
      fechaNacimiento,
      puntaje: 0,
      comentariosRecibidos: [],
    });

    res.redirect('/login');
  } catch (error) {
    console.error('Error al registrar usuario:', error.message);
    res.render('signup', { 
      title: 'Registro de Usuario',
      error: error.message 
    });
  }
});

// Login
app.get('/login', (req, res) => {
  res.render('login', {
    title: 'Iniciar Sesión',
    error: null
  });
});


app.post('/login', async (req, res) => {
  const { idToken } = req.body;
  try {
    const decodedToken = await admin.auth().verifyIdToken(idToken);
    const expiresIn = 60 * 60 * 24 * 5 * 1000;

    res.cookie('__session', idToken, {
      maxAge: expiresIn,
      httpOnly: true,
      secure: true,
      signed: true,
    });

    res.status(200).json({ message: 'Inicio de sesión exitoso' });
  } catch (error) {
    console.error('Error al iniciar sesión:', error.message);
    res.status(401).render('login', {
      title: 'Iniciar Sesión',
      error: 'Token inválido'
    });
  }
});


// Perfil
app.get('/perfil', checkAuth, async (req, res) => {
  try {
    const uid = req.user.uid;
    const userDoc = await db.collection('usuarios').doc(uid).get();

    if (!userDoc.exists) {
      return res.status(404).send('Usuario no encontrado.');
    }

    const userData = userDoc.data();
    const puntaje = userData.puntaje || 0;

    let resultadoQuiz = '';
    let consejo = '';

    if (puntaje <= 10) {
      resultadoQuiz = 'ESTRÉS BAJO';
      consejo = 'Sigue con tu ritmo. Mantén la calma y organiza bien tus tareas.';
    } else if (puntaje <= 20) {
      resultadoQuiz = 'ESTRÉS MODERADO';
      consejo = 'Intenta tomar pequeños descansos y practicar técnicas de relajación.';
    } else if (puntaje <= 30) {
      resultadoQuiz = 'ESTRÉS ALTO';
      consejo = 'Considera hablar con un consejero o tomar descansos más largos.';
    } else {
      resultadoQuiz = 'ESTRÉS MUY ALTO';
      consejo = 'Es importante que busques ayuda profesional para manejar el estrés.';
    }

    res.render('perfil', {
      title: 'Estrés Académico - Perfil',
      nombre: userData.nombre || 'Sin nombre',
      correo: userData.correo || 'Sin correo',
      fechaNacimiento: userData.fechaNacimiento || 'No especificada',
      resultadoQuiz,
      puntaje,
      consejo,
      comentariosRecibidos: userData.comentariosRecibidos || [],
    });
  } catch (err) {
    console.error('Error cargando perfil:', err.message);
    res.status(500).send('Error al cargar el perfil');
  }
});

// Guardar puntaje
app.post('/guardar-puntaje', checkAuth, async (req, res) => {
  try {
    const uid = req.user.uid;
    const { puntaje } = req.body;
    const userRef = db.collection('usuarios').doc(uid);
    await userRef.set({ puntaje: Number(puntaje) }, { merge: true });
    res.status(200).json({ message: 'Puntaje actualizado' });
  } catch (err) {
    console.error('Error al guardar el puntaje:', err);
    res.status(500).json({ error: 'Error interno del servidor' });
  }
});

// Logout
app.get('/logout', (req, res) => {
  res.clearCookie('__session');
  res.redirect('/login');
});

export { app };
