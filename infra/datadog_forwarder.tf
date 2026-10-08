# Fase 3 — Observabilidad / SIEM: ruta a Datadog, reemplaza el stack
# CloudFormation (Datadog Lambda Forwarder) usado en AWS.
#
# El mecanismo "oficial" de Datadog para GCP (Cloud Logging Sink -> Pub/Sub ->
# Dataflow job con su template) requiere una VPC con Private Google Access,
# Cloud Router + Cloud NAT, y un worker de Dataflow corriendo PERMANENTEMENTE
# (no escala a cero) — costo fijo mensual no trivial, injustificado en esta
# fase sin clientes activos (mismo criterio ya aplicado a Reverb en
# RESILIENCE I.A. y app.eccoflusso.cl: no pagar infraestructura "siempre
# encendida" hasta que haya tracción real).
#
# En su lugar: Cloud Logging Sink -> Pub/Sub -> Cloud Function Gen2 (escala a
# cero, solo cobra por invocación) que reenvía cada log directo a la API HTTP
# de Datadog. Mismo destino final (Datadog Log Explorer), sin el costo fijo
# del Dataflow. El código del forwarder es propio (no un producto empaquetado
# de Datadog), documentado como deuda técnica aceptada — ver
# archivos/bitacora.html.

resource "google_pubsub_topic" "datadog_logs" {
  name = "guardia-digital-datadog-logs-${var.environment}"
}

# --- Sink: logs del servicio Cloud Run -> Pub/Sub (en paralelo al sink WORM) ---
resource "google_logging_project_sink" "datadog_forwarder" {
  name        = "guardia-digital-datadog-sink-${var.environment}"
  destination = "pubsub.googleapis.com/${google_pubsub_topic.datadog_logs.id}"
  filter      = "resource.type=\"cloud_run_revision\" AND resource.labels.service_name=\"${google_cloud_run_v2_service.auth0_webhook.name}\""

  unique_writer_identity = true
}

resource "google_pubsub_topic_iam_member" "sink_publisher" {
  topic  = google_pubsub_topic.datadog_logs.name
  role   = "roles/pubsub.publisher"
  member = google_logging_project_sink.datadog_forwarder.writer_identity
}

# --- Secreto de la API key de Datadog, mismo patrón que el webhook secret ---
resource "google_secret_manager_secret" "datadog_api_key" {
  secret_id = "guardia-digital-datadog-api-key-${var.environment}"
  replication {
    auto {}
  }
}

resource "google_secret_manager_secret_version" "datadog_api_key" {
  secret      = google_secret_manager_secret.datadog_api_key.id
  secret_data = var.datadog_api_key
}

# --- Service Account de la Cloud Function: solo lo mínimo necesario ---
resource "google_service_account" "datadog_forwarder" {
  account_id   = "guardia-dd-forwarder-${var.environment}"
  display_name = "Guardia Digital — Datadog Forwarder (${var.environment})"
}

resource "google_secret_manager_secret_iam_member" "forwarder_secret_access" {
  secret_id = google_secret_manager_secret.datadog_api_key.secret_id
  role      = "roles/secretmanager.secretAccessor"
  member    = "serviceAccount:${google_service_account.datadog_forwarder.email}"
}

# --- Código de la Cloud Function empaquetado (ver infra/datadog_forwarder_src/) ---
data "archive_file" "datadog_forwarder_zip" {
  type        = "zip"
  source_dir  = "${path.module}/datadog_forwarder_src"
  output_path = "${path.module}/datadog_forwarder.zip"
}

resource "google_storage_bucket" "function_source" {
  name                        = "guardia-digital-fn-source-${var.environment}"
  location                    = var.gcp_region
  uniform_bucket_level_access = true
}

resource "google_storage_bucket_object" "datadog_forwarder_zip" {
  name   = "datadog-forwarder-${data.archive_file.datadog_forwarder_zip.output_md5}.zip"
  bucket = google_storage_bucket.function_source.name
  source = data.archive_file.datadog_forwarder_zip.output_path
}

resource "google_cloudfunctions2_function" "datadog_forwarder" {
  name     = "guardia-digital-datadog-forwarder-${var.environment}"
  location = var.gcp_region

  build_config {
    runtime     = "nodejs20"
    entry_point = "forwardToDatadog"
    source {
      storage_source {
        bucket = google_storage_bucket.function_source.name
        object = google_storage_bucket_object.datadog_forwarder_zip.name
      }
    }
  }

  service_config {
    max_instance_count   = 3
    min_instance_count   = 0 # escala a cero entre eventos, sin costo fijo
    available_memory     = "128Mi"
    timeout_seconds       = 30
    service_account_email = google_service_account.datadog_forwarder.email

    environment_variables = {
      DD_SITE = var.datadog_site
    }

    secret_environment_variables {
      key        = "DD_API_KEY"
      secret     = google_secret_manager_secret.datadog_api_key.secret_id
      version    = "latest"
      project_id = var.gcp_project
    }
  }

  event_trigger {
    trigger_region        = var.gcp_region
    event_type             = "google.cloud.pubsub.topic.v1.messagePublished"
    pubsub_topic           = google_pubsub_topic.datadog_logs.id
    retry_policy           = "RETRY_POLICY_RETRY"
    # Sin esto, Eventarc usa el Service Account por defecto de Compute Engine
    # para el push, que no tiene permiso de invocar este servicio Cloud Run
    # (política IAM vacía) — el trigger queda "activo" pero nunca llega a
    # ejecutar la función, reintentando en backoff silenciosamente.
    service_account_email = google_service_account.datadog_forwarder.email
  }

  depends_on = [google_secret_manager_secret_iam_member.forwarder_secret_access]
}

# Permiso explícito de invocación: el SA del trigger (arriba) necesita poder
# invocar el servicio Cloud Run subyacente de esta Cloud Function Gen2.
resource "google_cloud_run_v2_service_iam_member" "datadog_forwarder_invoker" {
  name     = google_cloudfunctions2_function.datadog_forwarder.name
  location = var.gcp_region
  role     = "roles/run.invoker"
  member   = "serviceAccount:${google_service_account.datadog_forwarder.email}"
}
