// guardia-auth0-webhook — Receptor de Log Streams de Auth0 vía API Gateway
// Runtime: nodejs20.x | Sin dependencias externas (optimización cold-start)
'use strict';
const crypto = require('crypto');

const RELEVANT_EVENTS = new Set(['s', 'f', 'fp', 'slo', 'limit_mu']); // success, failed, failed pwd, logout, blocked

function isValidToken(header, secret) {
  const expected = Buffer.from(`Bearer ${secret}`);
  const actual = Buffer.from(header || '');
  // Longitud debe compararse antes de timingSafeEqual (exige buffers del mismo tamaño),
  // pero comparar largo primero ya filtra la gran mayoría de intentos sin timing-leak útil.
  if (actual.length !== expected.length) return false;
  return crypto.timingSafeEqual(actual, expected);
}

// Auth0 Log Streams (Custom Webhook) puede entregar el body como JSON Lines
// (un objeto por línea, sin arreglo envolvente) en vez de un único JSON válido
// -- depende del "Formato de contenido" configurado en el stream. Soportamos
// ambos: un JSON único (objeto o array) o NDJSON de varias líneas.
function parseLogBody(rawBody) {
  const text = (rawBody || '').trim();
  if (!text) return [];

  try {
    const parsed = JSON.parse(text);
    return Array.isArray(parsed) ? parsed : [parsed];
  } catch {
    // No es un único JSON válido: probamos como JSON Lines.
  }

  const lines = text.split('\n').map((l) => l.trim()).filter(Boolean);
  return lines.map((line) => JSON.parse(line)); // deja que un JSON inválido siga lanzando
}

exports.handler = async (event) => {
  // 1. Validar autenticidad del webhook (header compartido configurado en Auth0)
  const token = event.headers?.['authorization'] || '';
  if (!isValidToken(token, process.env.AUTH0_WEBHOOK_SECRET)) {
    return { statusCode: 401, body: JSON.stringify({ error: 'unauthorized' }) };
  }

  let logs;
  try {
    logs = parseLogBody(event.body);
  } catch {
    return { statusCode: 400, body: JSON.stringify({ error: 'invalid_json' }) };
  }

  // 2. Procesar eventos de inicio de sesión
  const processed = logs
    .filter((l) => RELEVANT_EVENTS.has(l?.data?.type))
    .map((l) => {
      const d = l.data;
      return {
        // Determinístico a partir de auth0_log_id: si Auth0 reintenta la entrega
        // del mismo log (ej. tras un timeout), el downstream (SQS/Datadog) puede
        // deduplicar por event_id en vez de procesar el mismo evento dos veces.
        event_id: crypto.createHash('sha256').update(String(d.log_id)).digest('hex'),
        auth0_log_id: d.log_id,
        type: d.type,                       // 's' = login exitoso, 'f' = fallido
        user_id: d.user_id || null,
        connection: d.connection || null,   // ej: AD de la sucursal / contratistas
        ip: d.ip,
        geo: d.location_info || null,       // insumo para anomalías geográficas
        user_agent: d.user_agent,
        // "auth0_timestamp" (no "timestamp"): Datadog reserva ese nombre para su
        // propio atributo de ingesta y, si coinciden, devuelve un array [iso, epoch_ms]
        // en vez de un string, rompiendo el parseo aguas abajo (ver Sesión #7).
        auth0_timestamp: d.date,
        tenant: d.tenant_name,
      };
    });

  // 3. Emitir a stdout en JSON -> CloudWatch Logs -> Datadog Forwarder (SIEM)
  for (const evt of processed) {
    console.log(JSON.stringify({ source: 'auth0', service: 'guardia-iam', ...evt }));
  }

  // TODO: encolar en SQS/Kinesis para el batch de /ia_models si el volumen crece
  return { statusCode: 200, body: JSON.stringify({ received: logs.length, processed: processed.length }) };
};
