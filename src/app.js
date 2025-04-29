import admin from 'firebase-admin';
import fetch from 'node-fetch';
import cookieParser from 'cookie-parser';
import dotenv from 'dotenv';
import path from 'path';
import express from 'express';

dotenv.config();

// ------------ Configuración Firebase Admin -------------
const serviceAccount = JSON.parse(process.env.SERVICE_ACCOUNT_JSON);
admin.initializeApp({
    credential: admin.credential.cert(serviceAccount),
});

// ---------------- Configuración Express ----------------
const app = express();
const puerto = process.env.PORT || 3000; // Define el puerto

app.use(express.urlencoded({ extended: true }));
app.use(cookieParser(process.env.COOKIE_SECRET));
app.use(express.static(path.resolve('public')));
app.set('view engine', 'ejs');
app.set('views', path.resolve('views'));

app.use((req, res, next) => {
    if (Buffer.isBuffer(req.body)) {
        const text = req.body.toString('utf8');
        req.body = Object.fromEntries(new URLSearchParams(text));
    }
    next();
});

// ---------------- Middleware protected ----------------
async function checkAuth(req, res, next) {
    const token = req.signedCookies.__session;
    if (!token) return res.redirect('/login');
    try {
        const decoded = await admin.auth().verifyIdToken(token);
        req.user = decoded;
        next();
    } catch {
        res.redirect('/login');
    }
}

async function addUserToLocals(req, res, next) {
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
app.get('/', (req, res) => {
    res.render('index', { title: 'Estrés Académico - Información, Causas y Soluciones' });
});

// Añade la ruta para /quiz
app.get('/quiz', (req, res) => {
    res.render('quiz');
});

// Añade rutas para resultados del quiz
app.get('/nivel_bajo', (req, res) => {
    res.render('nivel_bajo');
});

app.get('/nivel_moderado', (req, res) => {
    res.render('nivel_moderado');
});

app.get('/nivel_alto', (req, res) => {
    res.render('nivel_alto');
});

app.get('/nivel_muy_alto', (req, res) => {
    res.render('nivel_muy_alto');
});

app.get('/signup', (req, res) => {
    res.render('signup', { title: 'Estrés Académico - Crear Cuenta', error: null });
});

// Resto de tus rutas...

// Iniciar el servidor
app.listen(puerto, () => {
    console.log(`Servidor corriendo en el puerto ${puerto}`);
});

export { app };