"""
Job batch en Modal — Detección de anomalías de acceso vía Vertex AI.
Despliegue:  modal deploy anomaly_detector.py
Ejecución:   modal run anomaly_detector.py
Requiere secrets en Modal:
  - gcp-credentials: GCP_SERVICE_ACCOUNT_JSON (contenido completo del JSON de la
    cuenta de servicio, como string), GCP_PROJECT, VERTEX_REGION, VERTEX_ENDPOINT_ID.
    No basta con Application Default Credentials: un contenedor Modal no tiene
    gcloud configurado ni metadata server, así que las credenciales se
    construyen explícitamente desde el JSON (ver _vertex_credentials()).
  - datadog-api: DD_API_KEY, DD_APP_KEY, DD_SITE (ingesta de logs pendientes).
  - auth0-management: AUTH0_DOMAIN, AUTH0_M2M_CLIENT_ID, AUTH0_M2M_CLIENT_SECRET
    (cierre del lazo de respuesta sobre el usuario anómalo).
"""
import json
import os
import time
from datetime import datetime, timedelta, timezone

import modal

app = modal.App("guardia-anomaly-detector")

image = modal.Image.debian_slim().pip_install("google-cloud-aiplatform", "requests")

# Persiste el cursor de paginación de Datadog entre ejecuciones del batch
# (evita reprocesar los mismos logs en cada ciclo de 15 min).
cursor_store = modal.Dict.from_name("guardia-datadog-cursor", create_if_missing=True)

ANOMALY_THRESHOLD = 0.8       # re-MFA (step-up)
BLOCK_THRESHOLD = 0.95        # bloqueo directo — anomalía extrema
FORCE_MFA_WINDOW_HOURS = 6    # cuánto tiempo queda "forzado" el re-MFA tras una anomalía

# El endpoint de Vertex corre con min_replica_count=0 (escala a cero, ver
# costos.html): si no hubo tráfico reciente, la primera predicción de cada
# ciclo puede pegarle a un endpoint "frío" y Vertex responde 429 mientras
# levanta la réplica. Se reintenta en vez de dejar que la excepción tumbe
# todo el ciclo (bug real encontrado en Sesión #7: sin retry, el evento se
# perdía porque el cursor de Datadog ya había avanzado).
PREDICT_MAX_RETRIES = 8
PREDICT_RETRY_DELAY_SECONDS = 15


@app.function(
    image=image,
    secrets=[
        modal.Secret.from_name("gcp-credentials"),
        modal.Secret.from_name("datadog-api"),
        modal.Secret.from_name("auth0-management"),
    ],
    schedule=modal.Period(minutes=15),  # batch cada 15 min: balance costo/latencia
    timeout=600,
)
def detect_anomalies(log_batch: list | None = None) -> list:
    """Toma un batch de logs de acceso y consulta el endpoint de Vertex AI.

    Cada log esperado: {user_id, ip, geo:{lat,lng,country}, timestamp, type}
    Retorna la lista de eventos clasificados como anómalos, ya con la
    respuesta (re-MFA/bloqueo) aplicada sobre Auth0.
    """
    from google.api_core.exceptions import ResourceExhausted
    from google.cloud import aiplatform

    project = os.environ["GCP_PROJECT"]
    region = os.environ.get("VERTEX_REGION", "us-central1")
    endpoint_id = os.environ["VERTEX_ENDPOINT_ID"]

    pending_cursor = None
    if log_batch is None:
        log_batch, pending_cursor = _fetch_pending_logs()

    if not log_batch:
        print("Sin logs pendientes en este ciclo.")
        return []

    aiplatform.init(project=project, location=region, credentials=_vertex_credentials())
    endpoint = aiplatform.Endpoint(endpoint_name=endpoint_id)

    instances = [
        {
            "user_id": l.get("user_id"),
            "ip": l.get("ip"),
            "lat": (l.get("geo") or {}).get("latitude"),
            "lng": (l.get("geo") or {}).get("longitude"),
            "country": (l.get("geo") or {}).get("country_code"),
            "hour_local": l.get("hour_local"),
            "event_type": l.get("type"),
        }
        for l in log_batch
    ]

    prediction = None
    for attempt in range(1, PREDICT_MAX_RETRIES + 1):
        try:
            prediction = endpoint.predict(instances=instances)
            break
        except ResourceExhausted:
            print(f"Endpoint frío (escalando desde cero) — reintento {attempt}/{PREDICT_MAX_RETRIES} "
                  f"en {PREDICT_RETRY_DELAY_SECONDS}s.")
            time.sleep(PREDICT_RETRY_DELAY_SECONDS)

    if prediction is None:
        # No se pudo predecir tras agotar los reintentos: NO avanzamos el cursor
        # de Datadog, para que el próximo ciclo vuelva a tomar estos mismos logs
        # en vez de perderlos silenciosamente.
        print(json.dumps({"service": "guardia-ia", "error": "vertex_endpoint_unavailable_after_retries"}))
        return []

    if pending_cursor is not None:
        cursor_store["last_run_at"] = pending_cursor

    anomalies = []
    for log, score in zip(log_batch, prediction.predictions):
        anomaly_score = float(score.get("anomaly_score", score) if isinstance(score, dict) else score)
        if anomaly_score >= ANOMALY_THRESHOLD:
            anomalies.append({**log, "anomaly_score": anomaly_score})

    if anomalies:
        # stdout JSON -> Datadog (alertas tempranas SIEM)
        print(json.dumps({"service": "guardia-ia", "anomalies": anomalies}))
        for anomaly in anomalies:
            _enforce_auth0_response(anomaly)

    return anomalies


def _vertex_credentials():
    """Construye credenciales de GCP explícitas desde el JSON de la cuenta de
    servicio (secret `gcp-credentials`, variable GCP_SERVICE_ACCOUNT_JSON).

    No se puede depender de Application Default Credentials: un contenedor
    Modal no tiene gcloud configurado ni metadata server de GCP disponible.
    """
    from google.oauth2 import service_account

    info = json.loads(os.environ["GCP_SERVICE_ACCOUNT_JSON"])
    return service_account.Credentials.from_service_account_info(
        info, scopes=["https://www.googleapis.com/auth/cloud-platform"]
    )


def _fetch_pending_logs() -> tuple[list, str | None]:
    """Ingesta real: consulta la Datadog Logs Search API por eventos de login
    de Auth0 emitidos desde el último cursor guardado, y los devuelve en el
    formato esperado por `detect_anomalies` (user_id, ip, geo, hour_local, type).

    Requiere DD_API_KEY, DD_APP_KEY (Application Key, distinto del API Key —
    la Logs Search API v2 exige ambos) y DD_SITE en el secret `datadog-api`.

    Devuelve (logs, cursor_pendiente): el cursor NO se confirma acá — lo hace
    el llamador (`detect_anomalies`) solo si la predicción de Vertex tuvo
    éxito, para no perder eventos si el endpoint está frío (ver Sesión #7).
    """
    import requests

    api_key = os.environ.get("DD_API_KEY")
    app_key = os.environ.get("DD_APP_KEY")
    site = os.environ.get("DD_SITE", "datadoghq.com")

    if not api_key or not app_key:
        print("Datadog no configurado (DD_API_KEY/DD_APP_KEY ausentes) — sin ingesta este ciclo.")
        return [], None

    last_run_iso = cursor_store.get("last_run_at")
    query_from = last_run_iso or (datetime.now(timezone.utc) - timedelta(minutes=20)).isoformat()
    query_to = datetime.now(timezone.utc).isoformat()

    url = f"https://api.{site}/api/v2/logs/events/search"
    headers = {
        "DD-API-KEY": api_key,
        "DD-APPLICATION-KEY": app_key,
        "Content-Type": "application/json",
    }
    # "service:guardia-iam" NO funciona: ese es el nombre de un campo anidado
    # dentro de nuestro JSON (attributes.attributes.service), pero el facet
    # reservado `service:` de Datadog usa el que asigna el Forwarder desde el
    # nombre real de la Lambda (ver DD_LAMBDA_SERVICE). Bug real encontrado en
    # Sesión #7: la query devolvía 0 resultados en todos los ciclos.
    lambda_service = os.environ.get("DD_LAMBDA_SERVICE", "guardia-auth0-webhook-staging")
    body = {
        "filter": {
            "query": f"service:{lambda_service} @type:(s OR f OR fp)",
            "from": query_from,
            "to": query_to,
        },
        "sort": "timestamp",
        "page": {"limit": 1000},
    }

    logs: list[dict] = []
    cursor = None
    try:
        while True:
            if cursor:
                body["page"]["cursor"] = cursor
            resp = requests.post(url, headers=headers, json=body, timeout=20)
            resp.raise_for_status()
            payload = resp.json()

            for item in payload.get("data", []):
                attrs = item.get("attributes", {}).get("attributes", {})
                geo = attrs.get("geo") or {}
                # "auth0_timestamp" es nuestro campo (ver handler.js). Si Datadog
                # igual lo devuelve como lista (colisión de nombre con su propio
                # atributo reservado), tomamos el primer valor (el string ISO).
                ts = attrs.get("auth0_timestamp")
                if isinstance(ts, list):
                    ts = ts[0] if ts else None
                logs.append({
                    "user_id": attrs.get("user_id"),
                    "ip": attrs.get("ip"),
                    "geo": {
                        "latitude": geo.get("latitude"),
                        "longitude": geo.get("longitude"),
                        "country_code": geo.get("country_code"),
                    },
                    "hour_local": _hour_local_santiago(ts),
                    "type": attrs.get("type"),
                    "auth0_log_id": attrs.get("auth0_log_id"),
                })

            cursor = payload.get("meta", {}).get("page", {}).get("after")
            if not cursor:
                break
    except requests.RequestException as e:
        print(json.dumps({"service": "guardia-ia", "datadog_fetch_error": str(e)}))
        return [], None

    print(f"Ingesta Datadog: {len(logs)} logs entre {query_from} y {query_to}.")
    return logs, query_to


def _hour_local_santiago(iso_timestamp: str | None) -> int | None:
    if not iso_timestamp:
        return None
    try:
        from zoneinfo import ZoneInfo
        dt = datetime.fromisoformat(iso_timestamp.replace("Z", "+00:00"))
        return dt.astimezone(ZoneInfo("America/Santiago")).hour
    except (ValueError, TypeError):
        return None


def _enforce_auth0_response(anomaly: dict) -> None:
    """Cierra el lazo de respuesta: dado un acceso anómalo, actúa sobre el
    usuario en Auth0 vía Management API.

    - anomaly_score >= BLOCK_THRESHOLD: bloquea la cuenta (`blocked: true`).
    - anomaly_score >= ANOMALY_THRESHOLD: fuerza re-MFA por `FORCE_MFA_WINDOW_HOURS`
      horas, seteando `app_metadata.force_mfa_until` (leído por
      `auth0/post-login-mfa-adaptativo.js` en el próximo login).

    Requiere una Auth0 Application M2M autorizada para la Management API
    con scopes `read:users update:users`.
    """
    import requests

    user_id = anomaly.get("user_id")
    score = anomaly.get("anomaly_score", 0)
    if not user_id:
        print(json.dumps({"service": "guardia-ia", "enforce_error": "missing_user_id", "anomaly": anomaly}))
        return

    domain = os.environ.get("AUTH0_DOMAIN")
    client_id = os.environ.get("AUTH0_M2M_CLIENT_ID")
    client_secret = os.environ.get("AUTH0_M2M_CLIENT_SECRET")
    if not all([domain, client_id, client_secret]):
        print("Auth0 Management API no configurado — no se puede cerrar el lazo este ciclo.")
        return

    try:
        token_resp = requests.post(
            f"https://{domain}/oauth/token",
            json={
                "grant_type": "client_credentials",
                "client_id": client_id,
                "client_secret": client_secret,
                "audience": f"https://{domain}/api/v2/",
            },
            timeout=10,
        )
        token_resp.raise_for_status()
        access_token = token_resp.json()["access_token"]

        patch_body = {}
        if score >= BLOCK_THRESHOLD:
            patch_body["blocked"] = True
            action = "blocked"
        else:
            force_until = (datetime.now(timezone.utc) + timedelta(hours=FORCE_MFA_WINDOW_HOURS)).isoformat()
            patch_body["app_metadata"] = {"force_mfa_until": force_until}
            action = "force_mfa"

        patch_resp = requests.patch(
            f"https://{domain}/api/v2/users/{user_id}",
            headers={"Authorization": f"Bearer {access_token}"},
            json=patch_body,
            timeout=10,
        )
        patch_resp.raise_for_status()
        print(json.dumps({
            "service": "guardia-ia", "enforce_action": action,
            "user_id": user_id, "anomaly_score": score,
        }))
    except requests.RequestException as e:
        print(json.dumps({
            "service": "guardia-ia", "enforce_error": str(e),
            "user_id": user_id, "anomaly_score": score,
        }))


@app.local_entrypoint()
def main():
    sample = [{
        "user_id": "auth0|demo123",
        "ip": "200.27.1.10",
        "geo": {"latitude": -33.45, "longitude": -70.66, "country_code": "CL"},
        "hour_local": 3,
        "type": "s",
    }]
    print(detect_anomalies.remote(sample))
