terraform {
  required_version = ">= 1.5"

  required_providers {
    google  = { source = "hashicorp/google", version = "~> 5.0" }
    archive = { source = "hashicorp/archive", version = "~> 2.4" }
  }

  # Backend remoto de estado (GCS con versioning + locking nativo de Terraform
  # ≥1.5, sin tabla de lock aparte como requería DynamoDB en AWS). El bucket se
  # crea una sola vez fuera de Terraform. Ver infra/backend.example.hcl.
  backend "gcs" {}
}

provider "google" {
  project = var.gcp_project
  region  = var.gcp_region
}

# --- Service Account del servicio Cloud Run (principio de mínimo privilegio) ---
resource "google_service_account" "webhook_receiver" {
  account_id   = "guardia-webhook-${var.environment}"
  display_name = "Guardia Digital — Webhook Receiver (${var.environment})"
}

# --- Secreto compartido del webhook (header Authorization: Bearer ...) ---
resource "google_secret_manager_secret" "auth0_webhook_secret" {
  secret_id = "guardia-auth0-webhook-secret-${var.environment}"
  replication {
    auto {}
  }
}

resource "google_secret_manager_secret_version" "auth0_webhook_secret" {
  secret      = google_secret_manager_secret.auth0_webhook_secret.id
  secret_data = var.auth0_webhook_secret
}

resource "google_secret_manager_secret_iam_member" "webhook_sa_access" {
  secret_id = google_secret_manager_secret.auth0_webhook_secret.secret_id
  role      = "roles/secretmanager.secretAccessor"
  member    = "serviceAccount:${google_service_account.webhook_receiver.email}"
}

# --- Cloud Run: receptor de webhooks Auth0 (reemplaza Lambda + API Gateway) ---
resource "google_cloud_run_v2_service" "auth0_webhook" {
  name     = "guardia-auth0-webhook-${var.environment}"
  location = var.gcp_region

  template {
    service_account = google_service_account.webhook_receiver.email

    scaling {
      min_instance_count = 0 # escala a cero: sin tráfico, sin costo (fase pre-piloto)
      max_instance_count = 3
    }

    containers {
      image = var.webhook_image

      resources {
        limits = {
          # Cloud Run v2 exige >=512Mi cuando la CPU está "always allocated"
          # (no solo durante requests) — 128Mi (equivalente a la Lambda
          # original) no es un valor válido aquí.
          memory = "512Mi"
          cpu    = "1"
        }
      }

      env {
        name = "AUTH0_WEBHOOK_SECRET"
        value_source {
          secret_key_ref {
            secret  = google_secret_manager_secret.auth0_webhook_secret.secret_id
            version = "latest"
          }
        }
      }
    }

    timeout = "10s" # mismo timeout que la Lambda original
  }

  depends_on = [google_secret_manager_secret_iam_member.webhook_sa_access]
}

# Auth0 llama al webhook sin credenciales GCP — la autenticación es propia
# (Bearer secret validado en processWebhook), así que el servicio debe ser
# invocable públicamente a nivel de transporte.
resource "google_cloud_run_v2_service_iam_member" "public_invoke" {
  name     = google_cloud_run_v2_service.auth0_webhook.name
  location = var.gcp_region
  role     = "roles/run.invoker"
  member   = "allUsers"
}
