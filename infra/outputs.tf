output "webhook_url" {
  description = "URL a configurar en el Log Stream (HTTP) de Auth0."
  value       = "${google_cloud_run_v2_service.auth0_webhook.uri}/webhooks/auth0"
}

output "webhook_service_name" {
  description = "Nombre del servicio Cloud Run del receptor de webhooks."
  value       = google_cloud_run_v2_service.auth0_webhook.name
}

output "worm_archive_bucket" {
  description = "Bucket GCS con retención bloqueada (Bucket Lock) donde se archivan, de forma inmutable, todos los eventos de acceso — evidencia probatoria para Ley 20.393."
  value       = google_storage_bucket.worm_archive.name
}

output "worm_retention_years" {
  description = "Años configurados de retención inmutable del archivo WORM."
  value       = var.worm_retention_years
}

output "datadog_forwarder_function" {
  description = "Nombre de la Cloud Function que reenvía logs a Datadog."
  value       = google_cloudfunctions2_function.datadog_forwarder.name
}
