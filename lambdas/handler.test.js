'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { handler } = require('./handler.js');

const SECRET = 'test-secret-123';
const AUTH_HEADER = `Bearer ${SECRET}`;

function makeEvent({ headers = {}, body }) {
  return {
    headers: { authorization: AUTH_HEADER, ...headers },
    body: typeof body === 'string' ? body : JSON.stringify(body),
  };
}

function withSecret(fn) {
  const prev = process.env.AUTH0_WEBHOOK_SECRET;
  process.env.AUTH0_WEBHOOK_SECRET = SECRET;
  return Promise.resolve(fn()).finally(() => {
    process.env.AUTH0_WEBHOOK_SECRET = prev;
  });
}

test('rechaza sin header Authorization', async () => {
  await withSecret(async () => {
    const res = await handler({ headers: {}, body: '[]' });
    assert.equal(res.statusCode, 401);
  });
});

test('rechaza con Bearer secret incorrecto', async () => {
  await withSecret(async () => {
    const res = await handler(makeEvent({ headers: { authorization: 'Bearer wrong' }, body: '[]' }));
    assert.equal(res.statusCode, 401);
  });
});

test('rechaza con Bearer de distinto largo al esperado', async () => {
  await withSecret(async () => {
    const res = await handler(makeEvent({ headers: { authorization: 'Bearer x' }, body: '[]' }));
    assert.equal(res.statusCode, 401);
  });
});

test('rechaza JSON inválido en el body', async () => {
  await withSecret(async () => {
    const res = await handler(makeEvent({ body: '{not-json' }));
    assert.equal(res.statusCode, 400);
    assert.equal(JSON.parse(res.body).error, 'invalid_json');
  });
});

test('acepta body vacío/ausente como lista vacía', async () => {
  await withSecret(async () => {
    const res = await handler({ headers: { authorization: AUTH_HEADER } });
    assert.equal(res.statusCode, 200);
    assert.equal(JSON.parse(res.body).received, 0);
  });
});

test('filtra eventos irrelevantes y procesa solo los tipos conocidos', async () => {
  await withSecret(async () => {
    const logs = [
      { data: { type: 's', log_id: 'a1', ip: '1.1.1.1', tenant_name: 't1', date: '2026-01-01T00:00:00Z' } },
      { data: { type: 'unknown_type', log_id: 'a2' } }, // debe filtrarse
      { data: { type: 'f', log_id: 'a3', ip: '2.2.2.2', tenant_name: 't1', date: '2026-01-01T00:01:00Z' } },
    ];
    const res = await handler(makeEvent({ body: logs }));
    const parsed = JSON.parse(res.body);
    assert.equal(res.statusCode, 200);
    assert.equal(parsed.received, 3);
    assert.equal(parsed.processed, 2);
  });
});

test('acepta un solo objeto (no-array) como body', async () => {
  await withSecret(async () => {
    const single = { data: { type: 's', log_id: 'single-1' } };
    const res = await handler(makeEvent({ body: single }));
    const parsed = JSON.parse(res.body);
    assert.equal(parsed.received, 1);
    assert.equal(parsed.processed, 1);
  });
});

test('event_id es determinístico para el mismo auth0_log_id (idempotencia)', async () => {
  await withSecret(async () => {
    const logsRun1 = [{ data: { type: 's', log_id: 'stable-id-1' } }];
    const logsRun2 = [{ data: { type: 's', log_id: 'stable-id-1' } }];

    const originalLog = console.log;
    const captured = [];
    console.log = (line) => captured.push(line);
    try {
      await handler(makeEvent({ body: logsRun1 }));
      await handler(makeEvent({ body: logsRun2 }));
    } finally {
      console.log = originalLog;
    }

    const eventIds = captured.map((line) => JSON.parse(line).event_id);
    assert.equal(eventIds.length, 2);
    assert.equal(eventIds[0], eventIds[1], 'event_id debe repetirse ante reintentos del mismo log_id');
  });
});

test('acepta JSON Lines (NDJSON): varios objetos separados por salto de línea', async () => {
  await withSecret(async () => {
    const ndjson = [
      JSON.stringify({ data: { type: 's', log_id: 'nd-1' } }),
      JSON.stringify({ data: { type: 'f', log_id: 'nd-2' } }),
      JSON.stringify({ data: { type: 'unknown', log_id: 'nd-3' } }),
    ].join('\n');
    const res = await handler(makeEvent({ body: ndjson }));
    const parsed = JSON.parse(res.body);
    assert.equal(res.statusCode, 200);
    assert.equal(parsed.received, 3);
    assert.equal(parsed.processed, 2);
  });
});

test('NDJSON con una línea inválida devuelve 400', async () => {
  await withSecret(async () => {
    const ndjson = '{"data":{"type":"s","log_id":"ok"}}\n{not-json}';
    const res = await handler(makeEvent({ body: ndjson }));
    assert.equal(res.statusCode, 400);
  });
});

test('event_id difiere para log_id distintos', async () => {
  await withSecret(async () => {
    const logs = [
      { data: { type: 's', log_id: 'id-a' } },
      { data: { type: 's', log_id: 'id-b' } },
    ];
    const originalLog = console.log;
    const captured = [];
    console.log = (line) => captured.push(line);
    try {
      await handler(makeEvent({ body: logs }));
    } finally {
      console.log = originalLog;
    }
    const eventIds = captured.map((line) => JSON.parse(line).event_id);
    assert.notEqual(eventIds[0], eventIds[1]);
  });
});
