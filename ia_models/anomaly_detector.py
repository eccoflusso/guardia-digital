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

image = modal.Image.debian_slim().pip_install("google-cloud-aiplatform", "requests", "fastapi[standard]")

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
        event = {"event_type": "error", "error": "vertex_endpoint_unavailable_after_retries"}
        print(json.dumps(event))
        _ship_to_datadog(event)
        return []

    if pending_cursor is not None:
        cursor_store["last_run_at"] = pending_cursor

    anomalies = []
    for log, score in zip(log_batch, prediction.predictions):
        anomaly_score = float(score.get("anomaly_score", score) if isinstance(score, dict) else score)
        if anomaly_score >= ANOMALY_THRESHOLD:
            anomalies.append({**log, "anomaly_score": anomaly_score})

    if anomalies:
        print(json.dumps({"event_type": "anomaly_detected", "anomalies": anomalies}))
        for anomaly in anomalies:
            # Un evento por anomalía (no una lista embebida) para que
            # anomaly_score/country/etc. sean facets planos y graficables.
            _ship_to_datadog({
                "event_type": "anomaly_detected",
                "user_id": anomaly.get("user_id"),
                "anomaly_score": anomaly.get("anomaly_score"),
                "country_code": (anomaly.get("geo") or {}).get("country_code"),
                "hour_local": anomaly.get("hour_local"),
                "auth0_log_id": anomaly.get("auth0_log_id"),
            })
            anomaly["enforcement"] = _enforce_auth0_response(anomaly)
            _emitir_evento_noc(anomaly, anomaly["enforcement"])

    return anomalies


# Atributo diferenciador #2 (ver archivos/atributos.md) — mapeo directo a la
# Ley 21.595 (delitos informáticos como delitos económicos base) y al lenguaje
# del Encargado de Prevención de Delitos (EPD), no solo del CISO. Un acceso
# anómalo o un bloqueo automático no es únicamente una alerta de seguridad:
# es la ejecución de un control preventivo del Modelo de Prevención de
# Delitos (MPD), y debe quedar etiquetado como tal en la propia telemetría
# para que un dashboard de compliance (o un auditor) pueda filtrar/reportar
# por esta categoría sin depender de que alguien lo explique después.
MPD_CONTROL_CATEGORY = {
    "anomaly_detected": "control_preventivo_mpd:mitigacion_fraude_informatico",
    "enforcement":      "control_preventivo_mpd:mitigacion_acceso_ilicito",
    "ingestion_cycle":  "control_preventivo_mpd:trazabilidad_supervision",
    "error":            "control_preventivo_mpd:falla_control_a_revisar",
}
MPD_LEGAL_BASIS = "ley_20393;ley_21595"


def _ship_to_datadog(event: dict) -> None:
    """Envía telemetría del propio pipeline (ingesta, anomalías, enforcement,
    errores) a Datadog vía su API de intake de logs. Sin esto, esos datos
    solo vivían en los logs de Modal (`modal app logs`) — invisibles para
    cualquier dashboard o alerta, y la razón por la que el bug de ingesta
    de la Sesión #7 pasó desapercibido tanto tiempo.

    Usa el nombre de servicio "guardia-ia-pipeline" (no "guardia-iam", que
    ya sabemos que colisiona con el facet reservado `service:` de Datadog
    cuando se anida dentro del JSON en vez de ir en el campo top-level).
    """
    import requests

    api_key = os.environ.get("DD_API_KEY")
    site = os.environ.get("DD_SITE", "datadoghq.com")
    if not api_key:
        return

    # Etiquetado legal: cada evento relevante para el MPD lleva su categoría
    # de control preventivo y la base legal aplicable como campos propios
    # (no solo como texto libre), para que Datadog los trate como facets
    # filtrables/graficables en un dashboard orientado al EPD.
    event_type = event.get("event_type")
    mpd_category = MPD_CONTROL_CATEGORY.get(event_type)
    tagged_event = dict(event)
    if mpd_category:
        tagged_event["mpd_control_category"] = mpd_category
        tagged_event["legal_basis"] = MPD_LEGAL_BASIS

    try:
        requests.post(
            f"https://http-intake.logs.{site}/api/v2/logs",
            headers={"DD-API-KEY": api_key, "Content-Type": "application/json"},
            json=[{
                "ddsource": "modal",
                "service": "guardia-ia-pipeline",
                "ddtags": "env:staging,project:guardia-digital-inteligente",
                "message": json.dumps(tagged_event),
            }],
            timeout=10,
        )
    except Exception as e:  # nunca dejar que un fallo de telemetría tumbe el job real
        print(f"(no se pudo enviar telemetría a Datadog: {e})")


# Mapeo user_id → sucursal, invertido desde DEMO_USERS_BY_SUCURSAL (definido
# más abajo). Se resuelve en runtime dentro de _emitir_evento_noc() para no
# depender del orden de definición del módulo — DEMO_USERS_BY_SUCURSAL es la
# única fuente de verdad de qué user_id pertenece a qué sucursal (Sesión #11).
def _resolver_sitio(user_id: str | None) -> str:
    """Traduce un user_id de Auth0 a su nombre de sucursal para el campo
    `sitio` del contrato de evento del NOC Hub. El ciclo real programado
    (detect_anomalies con logs de Datadog) no trae `sucursal` explícita en el
    log — a diferencia del endpoint de demo (simulate_attack) — así que se
    reutiliza el mismo mapa que ya distingue sucursales reales en Auth0."""
    if not user_id:
        return "desconocido"
    for sucursal_nombre, mapped_user_id in DEMO_USERS_BY_SUCURSAL.items():
        if mapped_user_id == user_id:
            return sucursal_nombre
    return "desconocido"


def _emitir_evento_noc(anomaly: dict, enforcement_result: dict) -> None:
    """Emite el evento hacia el Cognitive NOC Hub, siguiendo el contrato
    definido en noc-esval/CONTRATO_EVENTO.md (repo proyectos-wayweb, fuera de
    este proyecto). Es la implementación real de la conexión más barata del
    círculo de 5 piezas de ciberseguridad de Wayweb (ver
    Estrategia_Ventas_Wayweb.md, secciones 8-9, repo ia-agents).

    Envío best-effort, fire-and-forget en la práctica: un fallo acá nunca debe
    afectar el resultado real de detección/enforcement sobre Auth0 — mismo
    criterio que _ship_to_datadog(). Requiere las variables de entorno
    NOC_HUB_API_ENDPOINT y NOC_HUB_API_SECRET (secret `noc-hub-integration`);
    si no están configuradas, no se envía nada (el NOC Hub es opcional para
    Guardia Digital, no una dependencia dura).

    Args:
        anomaly: dict del log anómalo, incluyendo anomaly_score y geo.
        enforcement_result: resultado real de _enforce_auth0_response()
            ({"success", "action", "error"}) — nunca se asume éxito solo por
            haber superado el umbral de anomalía.
    """
    import requests

    endpoint = os.environ.get("NOC_HUB_API_ENDPOINT")
    secret = os.environ.get("NOC_HUB_API_SECRET")
    if not endpoint:
        return  # NOC Hub no configurado — integración opcional, no un requisito.

    score = anomaly.get("anomaly_score", 0)
    action = enforcement_result.get("action")
    country_code = (anomaly.get("geo") or {}).get("country_code")

    if score >= BLOCK_THRESHOLD:
        severidad = "critical"
    elif score >= ANOMALY_THRESHOLD:
        severidad = "high"
    else:
        return  # Sin anomalía real, no hay nada que correlacionar en el NOC Hub.

    evento = {
        "sitio": _resolver_sitio(anomaly.get("user_id")),
        "tipo_evento": anomaly.get("type") or "anomaly_detected",
        "severidad": severidad,
        "dispositivo": anomaly.get("user_id"),
        "origen_ot": False,  # Guardia Digital es IAM puro, sin redes OT.
        "mensaje": f"Login anómalo — {country_code} — acción: {action}",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "producto_origen": "guardia-digital",
        "metadata": {
            "anomaly_score": score,
            "enforce_action": action,
            "enforce_success": enforcement_result.get("success", False),
            "country_code": country_code,
        },
    }

    headers = {"Content-Type": "application/json"}
    if secret:
        headers["Authorization"] = f"Bearer {secret}"

    try:
        requests.post(endpoint, json=evento, headers=headers, timeout=10)
    except Exception as e:  # nunca dejar que un fallo de integración tumbe el job real
        print(f"(no se pudo enviar evento al NOC Hub: {e})")


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
        event = {"event_type": "error", "error": "datadog_fetch_error", "detail": str(e)}
        print(json.dumps(event))
        _ship_to_datadog(event)
        return [], None

    print(f"Ingesta Datadog: {len(logs)} logs entre {query_from} y {query_to}.")
    _ship_to_datadog({
        "event_type": "ingestion_cycle", "logs_found": len(logs),
        "from": query_from, "to": query_to,
    })
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


def _enforce_auth0_response(anomaly: dict) -> dict:
    """Cierra el lazo de respuesta: dado un acceso anómalo, actúa sobre el
    usuario en Auth0 vía Management API.

    - anomaly_score >= BLOCK_THRESHOLD: bloquea la cuenta (`blocked: true`).
    - anomaly_score >= ANOMALY_THRESHOLD: fuerza re-MFA por `FORCE_MFA_WINDOW_HOURS`
      horas, seteando `app_metadata.force_mfa_until` (leído por
      `auth0/post-login-mfa-adaptativo.js` en el próximo login).

    Requiere una Auth0 Application M2M autorizada para la Management API
    con scopes `read:users update:users`.

    Retorna {"success": bool, "action": str, "error": str|None} — el
    llamador (ej. el endpoint de demo) debe usar esto para reportar el
    resultado real, no asumir éxito solo porque el score superó el umbral
    (bug real: antes se reportaba "blocked" aunque el PATCH a Auth0 fallara
    con 404 por user_id inexistente).
    """
    import requests

    user_id = anomaly.get("user_id")
    score = anomaly.get("anomaly_score", 0)
    if not user_id:
        event = {"event_type": "error", "error": "missing_user_id", "anomaly": anomaly}
        print(json.dumps(event))
        _ship_to_datadog(event)
        return {"success": False, "action": None, "error": "missing_user_id"}

    domain = os.environ.get("AUTH0_DOMAIN")
    client_id = os.environ.get("AUTH0_M2M_CLIENT_ID")
    client_secret = os.environ.get("AUTH0_M2M_CLIENT_SECRET")
    if not all([domain, client_id, client_secret]):
        print("Auth0 Management API no configurado — no se puede cerrar el lazo este ciclo.")
        return {"success": False, "action": None, "error": "auth0_management_not_configured"}

    action = "blocked" if score >= BLOCK_THRESHOLD else "force_mfa"
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
        if action == "blocked":
            patch_body["blocked"] = True
        else:
            force_until = (datetime.now(timezone.utc) + timedelta(hours=FORCE_MFA_WINDOW_HOURS)).isoformat()
            patch_body["app_metadata"] = {"force_mfa_until": force_until}

        patch_resp = requests.patch(
            f"https://{domain}/api/v2/users/{user_id}",
            headers={"Authorization": f"Bearer {access_token}"},
            json=patch_body,
            timeout=10,
        )
        patch_resp.raise_for_status()
        event = {
            "event_type": "enforcement", "enforce_action": action,
            "user_id": user_id, "anomaly_score": score,
        }
        print(json.dumps(event))
        _ship_to_datadog(event)
        return {"success": True, "action": action, "error": None}
    except requests.RequestException as e:
        event = {
            "event_type": "error", "error": "enforce_error", "detail": str(e),
            "user_id": user_id, "anomaly_score": score,
        }
        print(json.dumps(event))
        _ship_to_datadog(event)
        return {"success": False, "action": action, "error": str(e)}


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


# ── Endpoint del botón "Simular ataque" (demo interactiva) ─────────────────
# Dispara el motor real bajo demanda, en vez de esperar el ciclo de 15 min o
# depender de que Datadog tenga logs pendientes. Usa SIEMPRE cuentas de
# prueba dedicadas (nunca una cuenta de cliente real) y un secreto
# compartido simple para que no cualquiera en internet pueda dispararlo y
# gastar cuota de Vertex AI. Sin `schedule`: Modal solo cobra por
# invocación real, cero costo mientras nadie hace clic en el botón.
DEMO_USER_ID = "auth0|6a6502df64e370d02f83c713"  # cuenta de prueba real, verificada en Sesión #7

# Prueba real de aislamiento multi-sucursal (Sesión #11): una cuenta Auth0
# real y distinta por sucursal — no el mismo user_id con una etiqueta
# narrativa distinta. Un ataque simulado contra "valparaiso" ejecuta
# _enforce_auth0_response() sobre ESE user_id específico; las cuentas de
# las otras sucursales nunca son tocadas por esa llamada, porque Auth0
# Management API opera por user_id explícito, no por un scope compartido.
DEMO_USERS_BY_SUCURSAL = {
    "matriz": "auth0|6a6502df64e370d02f83c713",
    "valparaiso": "auth0|6a66818a8f2f8a096272ebe1",
    "contratistas": "auth0|6a66819637ffd32c55db0b19",
}

DEMO_SCENARIOS = {
    "viaje_imposible": {
        "ip": "5.188.10.44", "country_code": "RU",
        "latitude": 55.75, "longitude": 37.62, "hour_local": 19,
    },
    "fuera_de_turno": {
        "ip": "181.43.20.5", "country_code": "CL",
        "latitude": -33.45, "longitude": -70.66, "hour_local": 3,
    },
    "geo_nueva": {
        "ip": "41.58.10.20", "country_code": "NG",
        "latitude": 9.08, "longitude": 8.68, "hour_local": 2,
    },
}


# Contador persistente entre invocaciones (mismo patrón que cursor_store).
# El secreto del endpoint vive embebido en el HTML público de la demo —
# cualquiera que abra el código fuente de la página puede leerlo y llamar
# al endpoint por su cuenta. Este límite acota el peor caso de abuso a un
# costo fijo y bajo (5 predicciones de Vertex AI) en vez de ilimitado.
demo_call_counter = modal.Dict.from_name("guardia-demo-call-counter", create_if_missing=True)
DEMO_CALL_LIMIT = 5
DEMO_CALL_WINDOW_HOURS = 24  # el contador se reinicia solo pasadas 24h desde el primer llamado


@app.function(
    image=image,
    secrets=[
        modal.Secret.from_name("gcp-credentials"),
        modal.Secret.from_name("datadog-api"),
        modal.Secret.from_name("auth0-management"),
        modal.Secret.from_name("demo-endpoint-auth"),  # DEMO_ENDPOINT_SECRET
    ],
    # 240s (no 120s): el endpoint de Vertex AI corre con min_replica_count=0
    # (escalado a cero deliberadamente por costo, ver scale_to_zero.py /
    # archivos/costos.html). La primera llamada tras inactividad hace un
    # cold start real que puede superar 120s (visto en producción: 8
    # reintentos de 15s = 120s ya agotados solo esperando el endpoint).
    timeout=240,
)
@modal.fastapi_endpoint(method="POST")
def simulate_attack(payload: dict) -> dict:
    """Endpoint HTTP para el botón "Simular ataque" del sitio público.

    Body esperado: {"scenario": "viaje_imposible" | "fuera_de_turno" | "geo_nueva",
                     "sucursal": "matriz" | "valparaiso" | "contratistas" (opcional, default "matriz"),
                     "secret": "<DEMO_ENDPOINT_SECRET>"}.
    Genera un evento de login sintético con esos parámetros, sobre la cuenta
    de prueba de la sucursal indicada (cada sucursal tiene su propio user_id
    real en Auth0 — ver DEMO_USERS_BY_SUCURSAL), lo pasa por el mismo
    `detect_anomalies` que usa el job real (Vertex AI + enforcement real
    sobre Auth0), y devuelve el resultado para que la página lo muestre en vivo.

    Limitado a DEMO_CALL_LIMIT llamadas por ventana de DEMO_CALL_WINDOW_HOURS
    horas (contador persistente en modal.Dict, compartido entre sucursales)
    — protege contra que alguien lea el secreto del HTML público y agote la
    cuota de Vertex AI.
    """
    from fastapi import HTTPException

    expected_secret = os.environ.get("DEMO_ENDPOINT_SECRET")
    if not expected_secret or payload.get("secret") != expected_secret:
        raise HTTPException(status_code=401, detail="unauthorized")

    sucursal_name = payload.get("sucursal", "matriz")
    target_user_id = DEMO_USERS_BY_SUCURSAL.get(sucursal_name)
    if not target_user_id:
        raise HTTPException(status_code=400, detail=f"unknown sucursal: {sucursal_name}")

    now = datetime.now(timezone.utc)
    window_start_iso = demo_call_counter.get("window_start")
    count = demo_call_counter.get("count", 0)

    window_start = datetime.fromisoformat(window_start_iso) if window_start_iso else None
    if window_start is None or (now - window_start) > timedelta(hours=DEMO_CALL_WINDOW_HOURS):
        # Ventana nueva: reinicia el contador.
        window_start = now
        count = 0

    if count >= DEMO_CALL_LIMIT:
        remaining_seconds = DEMO_CALL_WINDOW_HOURS * 3600 - (now - window_start).total_seconds()
        raise HTTPException(
            status_code=429,
            detail=f"Límite de {DEMO_CALL_LIMIT} simulaciones alcanzado. "
                    f"Disponible de nuevo en ~{int(remaining_seconds / 60)} min.",
        )

    demo_call_counter["window_start"] = window_start.isoformat()
    demo_call_counter["count"] = count + 1

    scenario_name = payload.get("scenario", "viaje_imposible")
    scenario = DEMO_SCENARIOS.get(scenario_name)
    if not scenario:
        raise HTTPException(status_code=400, detail=f"unknown scenario: {scenario_name}")

    log_batch = [{
        "user_id": target_user_id,
        "ip": scenario["ip"],
        "geo": {
            "latitude": scenario["latitude"],
            "longitude": scenario["longitude"],
            "country_code": scenario["country_code"],
        },
        "hour_local": scenario["hour_local"],
        "type": "s",
    }]

    anomalies = detect_anomalies.local(log_batch)
    calls_remaining = DEMO_CALL_LIMIT - demo_call_counter["count"]

    if not anomalies:
        return {
            "anomaly_detected": False, "scenario": scenario_name,
            "sucursal": sucursal_name, "calls_remaining": calls_remaining,
        }

    result = anomalies[0]
    enforcement = result.get("enforcement") or {}
    return {
        "anomaly_detected": True,
        "scenario": scenario_name,
        "sucursal": sucursal_name,
        "anomaly_score": result.get("anomaly_score"),
        "country_code": scenario["country_code"],
        "action": enforcement.get("action"),
        "enforced": enforcement.get("success", False),
        "enforce_error": enforcement.get("error"),
        "calls_remaining": calls_remaining,
    }


# ── Endpoint del botón "Reiniciar cuenta de prueba" (demo interactiva) ─────
# Simétrico a simulate_attack: revierte DEMO_USER_ID a un estado limpio
# (desbloqueada, sin re-MFA forzado) para que el presentador pueda repetir
# la simulación en la misma sesión sin depender de que alguien entre por
# SSH a arreglarlo a mano (como fue necesario la primera vez que se probó
# el endpoint real). Mismo secreto que simulate_attack, con su propio
# contador de rate-limit — no consume cupo de simulaciones.
demo_reset_counter = modal.Dict.from_name("guardia-demo-reset-counter", create_if_missing=True)
DEMO_RESET_LIMIT = 10
DEMO_RESET_WINDOW_HOURS = 24


@app.function(
    image=image,
    secrets=[
        modal.Secret.from_name("auth0-management"),
        modal.Secret.from_name("demo-endpoint-auth"),
    ],
    timeout=30,
)
@modal.fastapi_endpoint(method="POST")
def reset_demo_account(payload: dict) -> dict:
    """Endpoint HTTP para el botón "Reiniciar cuenta de prueba" de la demo.

    Body esperado: {"secret": "<DEMO_ENDPOINT_SECRET>", "sucursal": "matriz" (opcional)}.
    Sin "sucursal", reinicia las 3 cuentas de sucursal a la vez. Desbloquea
    (blocked: false) y limpia app_metadata.force_mfa_until, vía Auth0
    Management API — el mismo tipo de llamada que _enforce_auth0_response
    pero en sentido inverso.
    """
    import requests
    from fastapi import HTTPException

    expected_secret = os.environ.get("DEMO_ENDPOINT_SECRET")
    if not expected_secret or payload.get("secret") != expected_secret:
        raise HTTPException(status_code=401, detail="unauthorized")

    now = datetime.now(timezone.utc)
    window_start_iso = demo_reset_counter.get("window_start")
    count = demo_reset_counter.get("count", 0)
    window_start = datetime.fromisoformat(window_start_iso) if window_start_iso else None
    if window_start is None or (now - window_start) > timedelta(hours=DEMO_RESET_WINDOW_HOURS):
        window_start = now
        count = 0

    if count >= DEMO_RESET_LIMIT:
        remaining_seconds = DEMO_RESET_WINDOW_HOURS * 3600 - (now - window_start).total_seconds()
        raise HTTPException(
            status_code=429,
            detail=f"Límite de {DEMO_RESET_LIMIT} reinicios alcanzado. "
                    f"Disponible de nuevo en ~{int(remaining_seconds / 60)} min.",
        )

    demo_reset_counter["window_start"] = window_start.isoformat()
    demo_reset_counter["count"] = count + 1

    domain = os.environ.get("AUTH0_DOMAIN")
    client_id = os.environ.get("AUTH0_M2M_CLIENT_ID")
    client_secret = os.environ.get("AUTH0_M2M_CLIENT_SECRET")
    if not all([domain, client_id, client_secret]):
        raise HTTPException(status_code=500, detail="Auth0 Management API no configurado")

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

        sucursal_name = payload.get("sucursal")
        targets = (
            [DEMO_USERS_BY_SUCURSAL[sucursal_name]]
            if sucursal_name in DEMO_USERS_BY_SUCURSAL
            else list(DEMO_USERS_BY_SUCURSAL.values())
        )

        reset_ids = []
        for user_id in targets:
            patch_resp = requests.patch(
                f"https://{domain}/api/v2/users/{user_id}",
                headers={"Authorization": f"Bearer {access_token}"},
                json={"blocked": False, "app_metadata": {"force_mfa_until": None}},
                timeout=10,
            )
            patch_resp.raise_for_status()
            reset_ids.append(user_id)
        return {"reset": True, "user_ids": reset_ids}
    except requests.RequestException as e:
        raise HTTPException(status_code=502, detail=f"No se pudo reiniciar la cuenta: {e}")
