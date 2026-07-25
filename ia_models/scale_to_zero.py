"""
Reduce el endpoint de Vertex AI a min_replica_count=0 (escala a cero) para
no pagar cómputo 24/7 mientras el proyecto no tiene tráfico real. Ver
archivos/costos.html, sección "Costo real actual".

Uso: python scale_to_zero.py
"""
from google.cloud import aiplatform
from google.cloud.aiplatform_v1.types import DedicatedResources, MachineSpec

PROJECT = "guardia-digital-503518"
REGION = "us-central1"
ENDPOINT_ID = "5938704743932100608"

aiplatform.init(project=PROJECT, location=REGION)

endpoint = aiplatform.Endpoint(endpoint_name=ENDPOINT_ID)
deployed_models = endpoint.list_models()
print(f"Modelos desplegados en el endpoint: {len(deployed_models)}")

client = aiplatform.gapic.EndpointServiceClient(
    client_options={"api_endpoint": f"{REGION}-aiplatform.googleapis.com"}
)

for dm in deployed_models:
    print(f"Actualizando deployed_model_id={dm.id} -> min_replica_count=0")
    updated_deployed_model = {
        "id": dm.id,
        "dedicated_resources": DedicatedResources(
            machine_spec=MachineSpec(machine_type="n1-standard-2"),
            min_replica_count=0,
            max_replica_count=1,
        ),
    }
    operation = client.mutate_deployed_model(
        request={
            "endpoint": endpoint.resource_name,
            "deployed_model": updated_deployed_model,
            "update_mask": {"paths": ["dedicated_resources.min_replica_count"]},
        }
    )
    result = operation.result(timeout=120)
    print("Listo:", result)

print("\n=== Endpoint actualizado a min_replica_count=0 (escala a cero) ===")
