"""
Crea los monitores/alertas reales de Guardia Digital en Datadog, con las
queries correctas (no las del placeholder original de bootstrap, que tenían
el mismo bug de facet que _fetch_pending_logs() — ver Sesión #7).

Uso: python build_monitors.py
"""
import os

import requests

DD_API_KEY = os.environ["DD_API_KEY"]
DD_APP_KEY = os.environ["DD_APP_KEY"]
DD_SITE = os.environ.get("DD_SITE", "datadoghq.com")

LOGIN_SVC = "guardia-auth0-webhook-staging"
IA_SVC = "guardia-ia-pipeline"

MONITORS = [
    {
        "name": "[Guardia Digital] Ráfaga de logins fallidos",
        "type": "log alert",
        "query": f'logs("service:{LOGIN_SVC} @type:f").index("*").rollup("count").last("5m") > 20',
        "message": "Más de 20 logins fallidos en 5 minutos — posible ataque de fuerza bruta sobre Guardia Digital.",
        "tags": [],
        "options": {"thresholds": {"critical": 20}, "notify_no_data": False},
    },
    {
        "name": "[Guardia Digital] Anomalía de acceso detectada por IA",
        "type": "log alert",
        "query": f'logs("service:{IA_SVC} @event_type:anomaly_detected").index("*").rollup("count").last("15m") > 0',
        "message": "Vertex AI detectó al menos un acceso anómalo (viaje imposible / fuera de turno / geo-IP nueva) en los últimos 15 minutos.",
        "tags": [],
        "options": {"thresholds": {"critical": 0}, "notify_no_data": False},
    },
    {
        "name": "[Guardia Digital] Error en el pipeline de detección de anomalías",
        "type": "log alert",
        "query": f'logs("service:{IA_SVC} @event_type:error").index("*").rollup("count").last("15m") > 0',
        "message": "El job de detección de anomalías reportó un error (ingesta de Datadog, endpoint de Vertex, o Auth0 Management API) en los últimos 15 minutos. Revisar `modal app logs guardia-anomaly-detector`.",
        "tags": [],
        "options": {"thresholds": {"critical": 0}, "notify_no_data": False},
    },
]

for m in MONITORS:
    resp = requests.post(
        f"https://api.{DD_SITE}/api/v1/monitor",
        headers={"DD-API-KEY": DD_API_KEY, "DD-APPLICATION-KEY": DD_APP_KEY, "Content-Type": "application/json"},
        json=m,
        timeout=20,
    )
    if not resp.ok:
        print(f"ERROR creando '{m['name']}':", resp.status_code, resp.text)
        continue
    result = resp.json()
    print(f"Monitor creado: {result['name']} (id={result['id']})")
