// Importamos la aplicación Express desde el archivo principal
// Esta aplicación contiene todas las rutas, middlewares y configuraciones
const { app } = require('../../src/app.js');

// Importamos serverless-http, una biblioteca que permite ejecutar aplicaciones Express 
// en entornos serverless como AWS Lambda o Netlify Functions
const serverless = require('serverless-http');

// Exportamos la función handler que envuelve nuestra aplicación Express 
// para que pueda ser ejecutada como una función serverless
// Esto permite que nuestra aplicación Express tradicional funcione 
// en la arquitectura de funciones sin servidor de Netlify
exports.handler = serverless(app);
