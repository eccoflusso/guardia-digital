// Cloud Function Gen2 (Pub/Sub trigger) — reenvía cada evento de log del
// sink de Cloud Logging directo a la API HTTP de Datadog. Reemplaza al
// Datadog Lambda Forwarder (CloudFormation) usado en AWS; ver nota de diseño
// en infra/datadog_forwarder.tf sobre por qué no se usa el Dataflow oficial.
'use strict';

const functions = require('@google-cloud/functions-framework');

functions.cloudEvent('forwardToDatadog', async (cloudEvent) => {
  const apiKey = process.env.DD_API_KEY;
  const site = process.env.DD_SITE || 'datadoghq.com';

  const base64Data = cloudEvent.data?.message?.data;
  if (!base64Data) {
    console.log(JSON.stringify({ msg: 'mensaje Pub/Sub sin payload, se omite' }));
    return;
  }

  const decoded = Buffer.from(base64Data, 'base64').toString('utf-8');
  let logEntry;
  try {
    logEntry = JSON.parse(decoded);
  } catch (err) {
    console.error(JSON.stringify({ msg: 'payload de Cloud Logging no es JSON válido', error: err.message }));
    return;
  }

  // El sink entrega el LogEntry completo de Cloud Logging; el evento real
  // emitido por processWebhook (handler.js) vive en jsonPayload o textPayload
  // según cómo Cloud Run haya escrito la línea a stdout.
  const payload = logEntry.jsonPayload ?? logEntry.textPayload ?? logEntry;

  const res = await fetch(`https://http-intake.logs.${site}/api/v2/logs`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'DD-API-KEY': apiKey,
    },
    body: JSON.stringify([
      {
        ddsource: 'gcp.cloud_run',
        service: 'guardia-iam',
        message: payload,
      },
    ]),
  });

  if (!res.ok) {
    const body = await res.text();
    throw new Error(`Datadog intake respondió ${res.status}: ${body}`);
  }
});
