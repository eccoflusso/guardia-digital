"""
Registra el contenedor de predicción ya construido y subido a Artifact
Registry como un Vertex AI Model, crea un Endpoint y despliega el modelo ahí.
Se ejecuta una sola vez (o cada vez que se sube una versión nueva de la imagen).

Uso: python deploy_vertex.py
"""
import os

from google.cloud import aiplatform

PROJECT = "guardia-digital-503518"
REGION = "us-central1"
IMAGE_URI = "us-central1-docker.pkg.dev/guardia-digital-503518/guardia-digital-models/anomaly-detector:v1"

aiplatform.init(project=PROJECT, location=REGION)

print("Registrando el modelo en Vertex AI...")
model = aiplatform.Model.upload(
    display_name="guardia-anomaly-detector",
    serving_container_image_uri=IMAGE_URI,
    serving_container_predict_route="/predict",
    serving_container_health_route="/health",
    serving_container_ports=[8080],
)
print(f"Modelo registrado: {model.resource_name}")

print("Creando el endpoint...")
endpoint = aiplatform.Endpoint.create(display_name="guardia-anomaly-endpoint")
print(f"Endpoint creado: {endpoint.resource_name}")

print("Desplegando el modelo en el endpoint (puede tardar varios minutos)...")
model.deploy(
    endpoint=endpoint,
    deployed_model_display_name="guardia-anomaly-detector-v1",
    machine_type="n1-standard-2",
    min_replica_count=1,
    max_replica_count=1,
    traffic_percentage=100,
)

endpoint_id = endpoint.resource_name.split("/")[-1]
print(f"\n=== LISTO ===")
print(f"VERTEX_ENDPOINT_ID={endpoint_id}")
