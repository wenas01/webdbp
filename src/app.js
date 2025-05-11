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


// ---------------- Middleware protected ----------------
// Middleware checkAuth
async function checkAuth(req, res, next) {
  const token = req.signedCookies.__session;  // Asegúrate de que el token esté bien guardado en la cookie
  if (!token) return res.redirect('/login');  // Redirige a login si no hay token
  try {
    const decoded = await admin.auth().verifyIdToken(token);
    req.user = decoded;
    next();
  } catch (error) {
    console.error('Token inválido:', error);
    res.redirect('/login');  // Si el token no es válido, redirige al login
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

// Rutas públicas
// Rutas que necesitarás añadir a tu servidor Express

// Ruta para obtener la página principal
app.get('/', async(req, res) => {
    try {
        const snapshot = await db.collection("temas").get();
        const temas = snapshot.docs.map(doc => {
            return {
                id: doc.id,
                ...doc.data()
            };
        });
        res.render('index', { title: 'Estrés Académico - Información, Causas y Soluciones', temas });
    } catch (error) {
        res.status(500).send(error.message);
    }
});

// Ruta para crear un nuevo tema
app.post('/temas', async(req, res) => {
    try {
        // Validar los datos recibidos
        const { title, content, tags, author } = req.body;
        
        if (!title || !content) {
            return res.status(400).json({ error: 'El título y contenido son obligatorios' });
        }
        
        // Crear el nuevo documento en Firestore
        const newTema = {
            title,
            content,
            tags: Array.isArray(tags) ? tags : [],
            author: author || 'Usuario Anónimo',
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

// Ruta para añadir un comentario a un tema
app.post('/temas/:id/comentarios', async(req, res) => {
    try {
        const temaId = req.params.id;
        const { text } = req.body;
        
        if (!text) {
            return res.status(400).json({ error: 'El texto del comentario es obligatorio' });
        }
        
        // Obtener el documento del tema
        const temaRef = db.collection("temas").doc(temaId);
        const temaDoc = await temaRef.get();
        
        if (!temaDoc.exists) {
            return res.status(404).json({ error: 'Tema no encontrado' });
        }
        
        // Crear el nuevo comentario
        const newComment = {
            id: Date.now().toString(), // ID simple para el ejemplo
            text,
            author: 'Usuario Anónimo', // Podrías obtener el usuario autenticado
            date: new Date().toISOString(),
            likes: 0,
            accepted: false
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

// Ruta para dar "me gusta" a un comentario
app.post('/comentarios/:temaId/:commentId/like', async(req, res) => {
    try {
        const { temaId, commentId } = req.params;
        
        // Obtener el documento del tema
        const temaRef = db.collection("temas").doc(temaId);
        const temaDoc = await temaRef.get();
        
        if (!temaDoc.exists) {
            return res.status(404).json({ error: 'Tema no encontrado' });
        }
        
        const temaData = temaDoc.data();
        const comments = temaData.comments || [];
        
        // Encontrar el comentario y actualizar los likes
        const commentIndex = comments.findIndex(c => c.id === commentId);
        
        if (commentIndex === -1) {
            return res.status(404).json({ error: 'Comentario no encontrado' });
        }
        
        // Incrementar los likes
        comments[commentIndex].likes = (comments[commentIndex].likes || 0) + 1;
        
        // Actualizar el documento
        await temaRef.update({ comments });
        
        res.status(200).json({ likes: comments[commentIndex].likes });
    } catch (error) {
        console.error('Error al dar like:', error);
        res.status(500).json({ error: error.message });
    }
});

app.get('/signup', (req, res) => {
	res.render('signup', { title: 'Estrés Académico - Crear Cuenta', error: null });
});

app.post('/signup', async (req, res) => {
	const { email, password } = req.body;
	try {
		// 1. Crear el usuario en Firebase Auth
		const userRecord = await admin.auth().createUser({ email, password });

		// 2. Guardar datos del usuario en Firestore
		await db.collection('usuarios').doc(userRecord.uid).set({
			nombre: email.split('@')[0], // Puedes pedir el nombre en el formulario también
			correo: email,
			puntaje: 0
		});

		res.redirect('/login');
	} catch (err) {
		res.render('signup', { title: 'Estrés Académico - Crear Cuenta', error: err.message });
	}
});

app.get('/login', (req, res) => {
	res.render('login', { title: 'Estrés Académico - Iniciar Sesión', error: null });
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

app.get('/perfil', checkAuth, async (req, res) => {
  try {
    const uid = req.user.uid;

    // Buscar al usuario por UID en Firestore
    const userDoc = await db.collection('usuarios').doc(uid).get();

    if (!userDoc.exists) {
      return res.status(404).send('Usuario no encontrado.');
    }

    const userData = userDoc.data();

    res.render('perfil', {
      title: 'Estrés Académico - Perfil',
      nombre: userData.nombre || 'Sin nombre',
      correo: userData.correo || 'Sin correo',
      puntaje: userData.puntaje || 0
    });
  } catch (err) {
    console.error('Error cargando perfil:', err.message);
    res.status(500).send('Error al cargar el perfil');
  }
});

// Ruta protegida
app.get('/quiz', (req, res) => {
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
