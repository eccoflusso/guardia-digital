"""
Job batch en Modal — Detección de anomalías de acceso vía Vertex AI.
Despliegue:  modal deploy anomaly_detector.py
Ejecución:   modal run anomaly_detector.py
Requiere secrets en Modal: gcp-credentials (JSON de service account),
y variables GCP_PROJECT, VERTEX_REGION, VERTEX_ENDPOINT_ID.
"""
import json
import os

import modal

app = modal.App("guardia-anomaly-detector")

image = modal.Image.debian_slim().pip_install("google-cloud-aiplatform")


@app.function(
    image=image,
    secrets=[modal.Secret.from_name("gcp-credentials")],
    schedule=modal.Period(minutes=15),  # batch cada 15 min: balance costo/latencia
    timeout=600,
)
def detect_anomalies(log_batch: list | None = None) -> list:
    """Toma un batch de logs de acceso y consulta el endpoint de Vertex AI.

    Cada log esperado: {user_id, ip, geo:{lat,lng,country}, timestamp, type}
    Retorna la lista de eventos clasificados como anómalos.
    """
    from google.cloud import aiplatform

    project = os.environ["GCP_PROJECT"]
    region = os.environ.get("VERTEX_REGION", "us-central1")
    endpoint_id = os.environ["VERTEX_ENDPOINT_ID"]

    if log_batch is None:
        log_batch = _fetch_pending_logs()  # stub: leer desde SQS/S3/Datadog API

    if not log_batch:
        print("Sin logs pendientes en este ciclo.")
        return []

    aiplatform.init(project=project, location=region)
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

    prediction = endpoint.predict(instances=instances)

    anomalies = []
    for log, score in zip(log_batch, prediction.predictions):
        anomaly_score = float(score.get("anomaly_score", score) if isinstance(score, dict) else score)
        if anomaly_score >= 0.8:  # umbral: viajes imposibles / fuera de turno
            anomalies.append({**log, "anomaly_score": anomaly_score})

    if anomalies:
        # stdout JSON -> Datadog (alertas tempranas SIEM)
        print(json.dumps({"service": "guardia-ia", "anomalies": anomalies}))
        # TODO: webhook a Auth0 Management API para bloquear sesión/forzar re-MFA

    return anomalies


def _fetch_pending_logs() -> list:
    """Stub de ingesta. Reemplazar por lectura real (SQS, S3, Datadog Logs API)."""
    return []


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
