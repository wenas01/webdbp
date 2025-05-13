// Importamos la aplicación Express desde el archivo principal app.js
// Esta aplicación contiene todas las rutas, middlewares y configuraciones
import { app } from '../../src/app.js';

// Importamos serverless-http, una biblioteca que permite ejecutar aplicaciones Express 
// en entornos serverless como AWS Lambda o Netlify Functions
import serverless from 'serverless-http';

// Exportamos la función handler que envuelve nuestra aplicación Express 
// para que pueda ser ejecutada como una función serverless
// Esto permite que nuestra aplicación Express tradicional funcione 
// en la arquitectura de funciones sin servidor de Netlify
export const handler = serverless(app);
