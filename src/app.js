// Se importa la librería Express para manejar rutas y servidores HTTP
import express from 'express';

// Se importa Firebase Admin para interactuar con Firebase y manejar autenticación, base de datos y notificaciones
import admin from 'firebase-admin';

// Se importa node-fetch para hacer solicitudes HTTP a APIs externas
import fetch from 'node-fetch';

// Se importa cookie-parser para manejar cookies en el servidor
import cookieParser from 'cookie-parser';

// Se importa dotenv para cargar las variables de entorno desde un archivo .env
import dotenv from 'dotenv';

// Se importa path para manejar rutas de archivos en el sistema operativo
import path from 'path';

// Cargar las variables de entorno del archivo .env
dotenv.config();


// ------------ Configuración Firebase Admin -------------
const serviceAccount = JSON.parse(process.env.SERVICE_ACCOUNT_JSON);

admin.initializeApp({
  credential: admin.credential.cert(serviceAccount),
  storageBucket: 'estres-5ab99.appspot.com', // <--- Aquí
});

const bucket = admin.storage().bucket();
const db = admin.firestore();

const app = express();
//----------Ruta de consejos---------
app.get('/consejos', (req, res) => {
  res.render('consejos', {
    title: 'Consejos para el Estrés Académico'
  });
});
//-----------Ruta a pomodoro--------------
app.get('/pomodoro', (req, res) => {
  res.render('pomodoro', {
    title: 'Temporizador Pomodoro'
  });
});
// ---------------- Configuración Express ----------------
// Middleware para procesar JSON y datos formateados como URL
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Middleware para procesar cookies firmadas
app.use(cookieParser(process.env.COOKIE_SECRET));

// Middleware para servir archivos estáticos (como imágenes y CSS) desde el directorio 'public'
app.use(express.static(path.resolve('public')));

// Configuración de la vista para que utilice el motor de plantillas 'ejs' y la carpeta 'views' para las vistas
app.set('view engine', 'ejs');
app.set('views', path.resolve('views'));

// Middleware que se asegura de que el cuerpo de las solicitudes sea procesado correctamente
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
// Middleware para verificar si el usuario está autenticado a través del token en las cookies
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

// Middleware para agregar la información del usuario autenticado en las vistas
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

// Aplicar el middleware addUserToLocals a todas las rutas
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

// Ruta para crear un nuevo tema (protegida con autenticación)
app.post('/temas', checkAuth, async(req, res) => {
    try {
        // Validar los datos recibidos
        const { title, content, tags } = req.body;
        
        if (!title || !content) {
            return res.status(400).json({ error: 'El título y contenido son obligatorios' });
        }
        
        // Obtener información del usuario autenticado
        const uid = req.user.uid;
        const userDisplayName = req.user.name || req.user.displayName || 'Usuario ' + uid.substring(0, 5);
        
        // Crear el nuevo documento en Firestore
        const newTema = {
            title,
            content,
            tags: Array.isArray(tags) ? tags : [],
            author: userDisplayName,
            authorId: uid,
            comments: [],
            views: 0,
            createdAt: new Date().toISOString()
        };
        
        const docRef = await db.collection("temas").add(newTema);
        
        res.status(201).json({
            id: docRef.id,
            ...newTema
        });
    } catch (error) {
        console.error('Error al crear tema:', error);
        res.status(500).json({ error: error.message });
    }
});

// Ruta para añadir un comentario a un tema (protegida con autenticación)
app.post('/temas/:id/comentarios', checkAuth, async(req, res) => {
    try {
        const temaId = req.params.id;
        const { text } = req.body;
        
        if (!text) {
            return res.status(400).json({ error: 'El texto del comentario es obligatorio' });
        }
        
        // Obtener la información del usuario autenticado
        const uid = req.user.uid;
        const userDisplayName = req.user.name || req.user.displayName || 'Usuario Anónimo';
        
        // Obtener el documento del tema
        const temaRef = db.collection("temas").doc(temaId);
        const temaDoc = await temaRef.get();
        
        if (!temaDoc.exists) {
            return res.status(404).json({ error: 'Tema no encontrado' });
        }
        
        // Crear el nuevo comentario
        const commentId = Date.now().toString() + '-' + uid.substring(0, 8);
        const newComment = {
            id: commentId,
            text,
            authorId: uid,
            author: userDisplayName,
            date: new Date().toISOString(),
            likes: 0
        };
        
        // Actualizar el documento con el nuevo comentario
        await temaRef.update({
            comments: admin.firestore.FieldValue.arrayUnion(newComment)
        });
        
        res.status(201).json(newComment);
    } catch (error) {
        console.error('Error al añadir comentario:', error);
        res.status(500).json({ error: error.message });
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
	console.log('body:', req.body);
	const { email, password } = req.body;
	try {
		console.log('Logging in with email:', email);
		const resp = await fetch(
			`https://identitytoolkit.googleapis.com/v1/accounts:signInWithPassword?key=${process.env.FIREBASE_API_KEY}`,
			{
				method: 'POST',
				headers: { 'Content-Type': 'application/json' },
				body: JSON.stringify({ email, password, returnSecureToken: true }),
			}
		);
		const data = await resp.json();
		if (data.error) throw new Error(data.error.message);

		res.cookie('__session', data.idToken, { httpOnly: true, signed: true });
		res.redirect('/');
	} catch (err) {
		res.render('login', { title: 'Estrés Académico - Iniciar Sesión', error: err.message });
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

    // Obtener los síntomas desde la colección resultados_quiz
    const resultadoDoc = await db.collection('resultados_quiz').doc(uid).get();
    let sintomas = [];

    if (resultadoDoc.exists) {
      const data = resultadoDoc.data();
      // Convertimos el objeto { sintoma1: valor, sintoma2: valor } en un arreglo de claves
      sintomas = Object.entries(data.sintomas || {});
    }

    res.render('perfil', {
      title: 'Estrés Académico - Perfil',
      nombre: userData.nombre || 'Sin nombre',
      correo: userData.correo || 'Sin correo',
      fechaNacimiento: userData.fechaNacimiento || 'No especificada',
      resultadoQuiz,
      puntaje,
      consejo,
      sintomas,
      comentariosRecibidos: userData.comentariosRecibidos || [],
    });
  } catch (err) {
    console.error('Error cargando perfil:', err.message);
    res.status(500).send('Error al cargar el perfil');
  }
});


// Ruta protegida
app.get('/quiz', checkAuth, (req, res) => {
  res.render('quiz', { title: 'Estrés Académico - Quiz' });
});
app.get('/nivel_bajo', (req, res) => {
	res.render('nivel_bajo', { title: 'Quiz - Nivel_bajo' });
});
app.get('/nivel_moderado', (req, res) => {
	res.render('nivel_moderado', { title: 'Quiz - Nivel_moderado' });
});
app.get('/nivel_alto', (req, res) => {
	res.render('nivel_alto', { title: 'Quiz - Nivel_alto' });
});
app.get('/nivel_muy_alto', (req, res) => {
	res.render('nivel_muy_alto', { title: 'Quiz - Nivel_muy_alto' });
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
app.post('/guardar-sintomas', checkAuth, async (req, res) => {
  try {
    const uid = req.user.uid;
    const { respuestas } = req.body; // Debe ser un objeto con sintoma: puntaje

    // Filtrar los síntomas presentes (puntaje >= 2) y conservar el puntaje
    const sintomasFiltrados = Object.entries(respuestas)
      .filter(([_, valor]) => Number(valor) >= 2)
      .reduce((acc, [clave, valor]) => {
        acc[clave] = Number(valor);
        return acc;
      }, {});

    // Guardar en la colección 'resultados_quiz' bajo el UID
    const ref = db.collection('resultados_quiz').doc(uid);
    await ref.set({
      sintomas: sintomasFiltrados, // ahora es un objeto {sintoma1: puntaje1, sintoma2: puntaje2}
      fecha: new Date().toISOString()
    });

    res.status(200).json({ message: 'Síntomas y puntajes guardados correctamente' });
  } catch (err) {
    console.error('Error al guardar los síntomas:', err);
    res.status(500).json({ error: 'Error interno del servidor' });
  }
});
// Logout
app.get('/logout', (req, res) => {
  res.clearCookie('__session');
  res.redirect('/login');
});

import { Store, DataFactory, Writer } from 'n3';
import { Storage } from '@google-cloud/storage';
const { namedNode, literal, quad } = DataFactory;

const storage = new Storage(); // Usa credenciales de Firebase Admin

const symptomMappings = {
  alteraciones_sueno: "Sleep_disorder",
  ansiedad_evaluaciones: "Test_anxiety",
  fatiga_cronica: "Chronic_fatigue_syndrome",
  dificultad_concentrarse: "Concentration_(psychology)",
  cambios_alimentacion: "Eating_disorder",
  procrastinacion: "Procrastination",
  irritabilidad: "Irritability",
  pensamiento_catastrofico: "Catastrophizing",
  sintomas_fisicos: "Somatic_symptom_disorder",
  aislamiento_social: "Social_withdrawal"
};

app.get('/perfil/rdf', checkAuth, async (req, res) => {
  try {
    const uid = req.user.uid;
    const doc = await db.collection('resultados_quiz').doc(uid).get();

    if (!doc.exists) return res.status(404).send('No hay resultados para este usuario.');

    const data = doc.data();
    const sintomas = data.sintomas || {};

    const writer = new Writer({
      prefixes: {
        ex: 'http://example.org/',
        rdf: 'http://www.w3.org/1999/02/22-rdf-syntax-ns#',
        dbpedia: 'http://dbpedia.org/resource/',
      }
    });

    for (const [sintoma, valor] of Object.entries(sintomas)) {
      const sintomaURI = sintoma.replace(/\s+/g, '_');

      writer.addQuad(
        namedNode(`http://example.org/user_${uid}`),
        namedNode('http://example.org/hasSymptom'),
        namedNode(`http://dbpedia.org/resource/${sintomaURI}`)
      );

      writer.addQuad(
        namedNode(`http://dbpedia.org/resource/${sintomaURI}`),
        namedNode('http://example.org/severity'),
        literal(valor.toString(), namedNode('http://www.w3.org/2001/XMLSchema#integer'))
      );
    }

    const rdfString = await new Promise((resolve, reject) => {
      writer.end((error, result) => {
        if (error) reject(error);
        else resolve(result);
      });
    });

    const file = bucket.file(`rdf/${uid}.ttl`);
    await file.save(rdfString, {
      contentType: 'text/turtle',
      metadata: {
        firebaseStorageDownloadTokens: uid
      }
    });

    res.set('Content-Type', 'text/turtle');
    res.send(rdfString);
  } catch (error) {
    console.error('Error generando RDF:', error);
    res.status(500).send('Error interno del servidor');
  }
});

export { app };
