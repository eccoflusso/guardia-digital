# Atributo diferenciador #1 (ver archivos/atributos.md) — Inmutabilidad de
# logs (estándar probatorio). Los eventos de acceso normalizados por el
# servicio Cloud Run (guardia-auth0-webhook) ya viajan a Datadog para
# SIEM/observabilidad, pero Datadog no ofrece retención en modo WORM. Este
# archivo agrega una segunda ruta, en paralelo, hacia un bucket GCS con
# retention policy bloqueada: una vez escrito, ningún usuario ni rol
# (incluido el dueño del proyecto) puede modificar o borrar un objeto antes
# de que venza el retention period. Eso es lo que permite invocar estos logs
# como evidencia ante un fiscal o auditor de la Ley 20.393: no es que "no se
# pueda", es que GCP lo rechaza a nivel de API aunque alguien tenga rol Owner.
#
# Reemplaza el diseño anterior en AWS (CloudWatch Logs -> Kinesis Firehose ->
# S3 con Object Lock modo COMPLIANCE). Cloud Logging Sink es el equivalente
# nativo de GCP: escribe directo a GCS sin necesitar una pieza intermedia
# tipo Firehose.

# --- Bucket WORM (retention policy, bloqueado en un paso manual post-apply) ---
resource "google_storage_bucket" "worm_archive" {
  name                        = "guardia-digital-worm-archive-${var.environment}"
  location                    = var.gcp_region
  uniform_bucket_level_access = true

  versioning {
    enabled = true # mismo requisito que en S3: versioning habilitado para inmutabilidad real
  }

  retention_policy {
    retention_period = var.worm_retention_years * 365 * 24 * 60 * 60 # años -> segundos
    # NOTA DE SEGURIDAD CRÍTICA: esta retention_policy, por sí sola, es
    # borrable por cualquier Owner del proyecto (equivalente a Object Lock
    # modo GOVERNANCE en S3, no COMPLIANCE). Para igualar la garantía legal
    # del diseño original hay que BLOQUEAR el bucket manualmente, fuera de
    # Terraform, después del primer apply:
    #
    #   gcloud storage buckets update gs://guardia-digital-worm-archive-<env> \
    #     --lock-retention-period
    #
    # Esta acción es intencionalmente manual e IRREVERSIBLE (igual que Object
    # Lock en S3 solo podía habilitarse en la creación del bucket) — nunca se
    # automatiza en el apply para que quede como una decisión explícita,
    # documentada en la bitácora, no un efecto colateral de `terraform apply`.
  }

  public_access_prevention = "enforced"
}

# --- Service Account del sink: solo permiso de escritura al bucket WORM ---
resource "google_logging_project_sink" "worm_archive" {
  name        = "guardia-digital-worm-sink-${var.environment}"
  destination = "storage.googleapis.com/${google_storage_bucket.worm_archive.name}"

  # Todos los eventos de acceso del servicio, sin excepción — la evidencia no
  # se filtra. Equivalente al filter_pattern = "" del subscription filter
  # original de CloudWatch Logs.
  filter = "resource.type=\"cloud_run_revision\" AND resource.labels.service_name=\"${google_cloud_run_v2_service.auth0_webhook.name}\""

  unique_writer_identity = true
}

resource "google_storage_bucket_iam_member" "sink_writer" {
  bucket = google_storage_bucket.worm_archive.name
  role   = "roles/storage.objectCreator"
  member = google_logging_project_sink.worm_archive.writer_identity
}
