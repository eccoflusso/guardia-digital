// Entrypoint HTTP para Cloud Run — reemplaza el invocador Lambda/API Gateway.
// La lógica del webhook vive en handler.js (processWebhook), sin duplicar nada.
'use strict';
const express = require('express');
const { processWebhook } = require('./handler.js');

const app = express();

// Body crudo preservado tal cual (Content-Type cualquiera): parseLogBody ya
// maneja tanto JSON único como NDJSON — parsearlo acá lo rompería dos veces.
app.use(express.text({ type: '*/*' }));

app.post('/webhooks/auth0', async (req, res) => {
  const result = await processWebhook(req.headers['authorization'], req.body);
  res.status(result.statusCode).type('application/json').send(result.body);
});

// Cloud Run healthcheck / verificación manual rápida.
app.get('/', (_req, res) => res.status(200).send('guardia-auth0-webhook: ok'));

const port = process.env.PORT || 8080;
app.listen(port, () => {
  console.log(JSON.stringify({ msg: 'guardia-auth0-webhook listening', port }));
});
