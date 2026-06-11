// guardia-auth0-webhook — Receptor de Log Streams de Auth0 vía API Gateway
// Runtime: nodejs20.x | Sin dependencias externas (optimización cold-start)
'use strict';
const crypto = require('crypto');

const RELEVANT_EVENTS = new Set(['s', 'f', 'fp', 'slo', 'limit_mu']); // success, failed, failed pwd, logout, blocked

exports.handler = async (event) => {
  // 1. Validar autenticidad del webhook (header compartido configurado en Auth0)
  const token = event.headers?.['authorization'] || '';
  if (token !== `Bearer ${process.env.AUTH0_WEBHOOK_SECRET}`) {
    return { statusCode: 401, body: JSON.stringify({ error: 'unauthorized' }) };
  }

  let logs;
  try {
    const body = JSON.parse(event.body || '[]');
    logs = Array.isArray(body) ? body : [body];
  } catch {
    return { statusCode: 400, body: JSON.stringify({ error: 'invalid_json' }) };
  }

  // 2. Procesar eventos de inicio de sesión
  const processed = logs
    .filter((l) => RELEVANT_EVENTS.has(l?.data?.type))
    .map((l) => {
      const d = l.data;
      return {
        event_id: crypto.randomUUID(),
        auth0_log_id: d.log_id,
        type: d.type,                       // 's' = login exitoso, 'f' = fallido
        user_id: d.user_id || null,
        connection: d.connection || null,   // ej: AD de la sucursal / contratistas
        ip: d.ip,
        geo: d.location_info || null,       // insumo para anomalías geográficas
        user_agent: d.user_agent,
        timestamp: d.date,
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
