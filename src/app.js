import express from 'express';
import admin from 'firebase-admin';
import fetch from 'node-fetch';
import cookieParser from 'cookie-parser';
import dotenv from 'dotenv';
import path from 'path';

dotenv.config();

// Inicializar Firebase Admin
const serviceAccount = JSON.parse(process.env.SERVICE_ACCOUNT_JSON);

admin.initializeApp({
	credential: admin.credential.cert(serviceAccount),
});

const app = express();

app.use(express.urlencoded({ extended: true }));

app.use(cookieParser(process.env.COOKIE_SECRET));

app.use(express.static(path.resolve('public')));

app.set('view engine', 'ejs');

app.set('views', path.resolve('views'));

app.use((req, res, next) => {
  // si req.body llegó como Buffer…
  if (Buffer.isBuffer(req.body)) {
    // lo convertimos a string
    const text = req.body.toString('utf8');
    // y lo parseamos como URLSearchParams (form-urlencoded)
    req.body = Object.fromEntries(new URLSearchParams(text));
  }
  next();
});


// Middleware de autenticación
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

// Rutas públicas
app.get('/', (req, res) => {
	res.render('index', { error: null });
});

app.get('/register', (req, res) => {
	res.render('register', { error: null });
});

app.post('/register', async (req, res) => {
	const { email, password } = req.body;
	try {
		await admin.auth().createUser({ email, password });
		res.redirect('/login');
	} catch (err) {
		res.render('register', { error: err.message });
	}
});

app.get('/login', (req, res) => {
	res.render('login', { error: null });
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
		res.redirect('/tests');
	} catch (err) {
		res.render('login', { error: err.message });
	}
});

// Ruta protegida
app.get('/tests', checkAuth, (req, res) => {
	res.render('tests', { email: req.user.email });
});

// Logout
app.post('/logout', (req, res) => {
	res.clearCookie('__session');
	res.redirect('/login');
});

export { app };