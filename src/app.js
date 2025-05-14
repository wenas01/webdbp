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

// Ruta para crear un nuevo tema
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

// Mejora para la ruta de "me gusta" con verificación de un solo like por usuario
app.post('/comentarios/:temaId/:commentId/like', checkAuth, async(req, res) => {
    try {
        const { temaId, commentId } = req.params;
        const uid = req.user.uid; // ID del usuario autenticado
        
        // Obtener el documento del tema
        const temaRef = db.collection("temas").doc(temaId);
        const temaDoc = await temaRef.get();
        
        if (!temaDoc.exists) {
            return res.status(404).json({ error: 'Tema no encontrado' });
        }
        
        const temaData = temaDoc.data();
        const comments = temaData.comments || [];
        
        // Función recursiva para buscar el comentario en comentarios y respuestas
        const findAndUpdateLike = (commentsArray) => {
            let found = false;
            
            // Buscar primero en comentarios principales
            for (let i = 0; i < commentsArray.length; i++) {
                // Verificar si es el comentario principal
                if (commentsArray[i].id === commentId) {
                    // Verificar si ya dio like
                    if (!commentsArray[i].likedBy) {
                        commentsArray[i].likedBy = [];
                    }
                    
                    if (commentsArray[i].likedBy.includes(uid)) {
                        throw { status: 400, message: 'Ya has dado "me gusta" a este comentario' };
                    }
                    
                    // Incrementar likes y registrar usuario
                    commentsArray[i].likes = (commentsArray[i].likes || 0) + 1;
                    commentsArray[i].likedBy.push(uid);
                    
                    // Notificar al autor del comentario
                    if (commentsArray[i].authorId && commentsArray[i].authorId !== uid) {
                        notifyUser(commentsArray[i].authorId, uid, temaId, 'dio me gusta a tu comentario');
                    }
                    
                    return { likes: commentsArray[i].likes };
                }
                
                // Buscar en respuestas anidadas si existen
                if (commentsArray[i].replies && commentsArray[i].replies.length > 0) {
                    for (let j = 0; j < commentsArray[i].replies.length; j++) {
                        if (commentsArray[i].replies[j].id === commentId) {
                            // Verificar si ya dio like
                            if (!commentsArray[i].replies[j].likedBy) {
                                commentsArray[i].replies[j].likedBy = [];
                            }
                            
                            if (commentsArray[i].replies[j].likedBy.includes(uid)) {
                                throw { status: 400, message: 'Ya has dado "me gusta" a esta respuesta' };
                            }
                            
                            // Incrementar likes y registrar usuario
                            commentsArray[i].replies[j].likes = (commentsArray[i].replies[j].likes || 0) + 1;
                            commentsArray[i].replies[j].likedBy.push(uid);
                            
                            // Notificar al autor de la respuesta
                            if (commentsArray[i].replies[j].authorId && commentsArray[i].replies[j].authorId !== uid) {
                                notifyUser(commentsArray[i].replies[j].authorId, uid, temaId, 'dio me gusta a tu respuesta');
                            }
                            
                            return { likes: commentsArray[i].replies[j].likes };
                        }
                    }
                }
            }
            
            throw { status: 404, message: 'Comentario no encontrado' };
        };
        
        // Función para notificar al usuario
        const notifyUser = async (targetUid, sourceUid, temaId, action) => {
            try {
                // Obtener información del usuario que da like
                const sourceUserInfo = req.user;
                const sourceUserName = sourceUserInfo.name || sourceUserInfo.displayName || 'Usuario Anónimo';
                
                // Actualizar la colección de usuarios con la notificación
                const userRef = db.collection('usuarios').doc(targetUid);
                const userDoc = await userRef.get();
                
                if (userDoc.exists) {
                    const userData = userDoc.data();
                    const comentariosRecibidos = userData.comentariosRecibidos || [];
                    
                    comentariosRecibidos.push({
                        autorUid: sourceUserName,
                        mensaje: `${sourceUserName} ${action}`,
                        fecha: new Date().toISOString(),
                        temaId: temaId
                    });
                    
                    await userRef.update({ comentariosRecibidos });
                }
            } catch (err) {
                console.error('Error al notificar:', err);
                // Continuamos aunque falle la notificación
            }
        };
        
        // Buscar y actualizar el like
        const result = findAndUpdateLike(comments);
        
        // Actualizar el documento
        await temaRef.update({ comments });
        
        res.status(200).json(result);
        
    } catch (error) {
        console.error('Error al dar like:', error);
        res.status(error.status || 500).json({ error: error.message || 'Error interno del servidor' });
    }
});

// Modificación para el backend de Node.js (añadir al archivo server.js)

// Ruta para responder a un comentario específico (protegida con autenticación)
app.post('/temas/:id/comentarios/:commentId/respuesta', checkAuth, async(req, res) => {
    try {
        const { id: temaId, commentId } = req.params;
        const { text } = req.body;
        
        if (!text) {
            return res.status(400).json({ error: 'El texto de la respuesta es obligatorio' });
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
        
        const temaData = temaDoc.data();
        const comments = temaData.comments || [];
        
        // Encontrar el comentario al que se está respondiendo
        const commentIndex = comments.findIndex(c => c.id === commentId);
        
        if (commentIndex === -1) {
            return res.status(404).json({ error: 'Comentario no encontrado' });
        }
        
        // Verificar si el comentario ya tiene respuestas
        if (comments[commentIndex].replies && comments[commentIndex].replies.length > 0) {
            return res.status(400).json({ error: 'Este comentario ya tiene una respuesta. No se permiten múltiples respuestas.' });
        }
        
        // Crear la nueva respuesta
        const replyId = Date.now().toString() + '-reply-' + uid.substring(0, 8);
        const newReply = {
            id: replyId,
            text,
            authorId: uid,
            author: userDisplayName,
            date: new Date().toISOString(),
            likes: 0,
            likedBy: []
        };
        
        // Añadir la respuesta al comentario
        if (!comments[commentIndex].replies) {
            comments[commentIndex].replies = [];
        }
        
        comments[commentIndex].replies.push(newReply);
        
        // Actualizar el documento con la nueva respuesta
        await temaRef.update({ comments });
        
        // Si el comentario original no es del usuario actual, notificar al autor original
        const originalAuthorId = comments[commentIndex].authorId;
        if (originalAuthorId && originalAuthorId !== uid) {
            try {
                const userRef = db.collection('usuarios').doc(originalAuthorId);
                const userDoc = await userRef.get();
                
                if (userDoc.exists) {
                    const userData = userDoc.data();
                    const comentariosRecibidos = userData.comentariosRecibidos || [];
                    
                    comentariosRecibidos.push({
                        autorUid: userDisplayName,
                        mensaje: `Te respondió en un tema: "${text.substring(0, 50)}${text.length > 50 ? '...' : ''}"`,
                        fecha: new Date().toISOString(),
                        likes: 0,
                        temaId: temaId
                    });
                    
                    await userRef.update({ comentariosRecibidos });
                }
            } catch (notifyError) {
                console.error('Error al notificar al autor original:', notifyError);
                // Continuamos el flujo aunque la notificación falle
            }
        }
        
        res.status(201).json(newReply);
    } catch (error) {
        console.error('Error al añadir respuesta:', error);
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

// Logout
app.get('/logout', (req, res) => {
  res.clearCookie('__session');
  res.redirect('/login');
});

export { app };
