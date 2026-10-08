variable "gcp_project" {
  description = "Project ID de GCP donde se despliega la infraestructura."
  type        = string
  default     = "ley-20393"
}

variable "gcp_region" {
  description = "Región GCP de despliegue. southamerica-east1 (São Paulo) recomendada por latencia y residencia de datos LATAM — mismo criterio que sa-east-1 en el diseño AWS anterior."
  type        = string
  default     = "southamerica-east1"
}

variable "environment" {
  description = "Nombre del ambiente (staging | prod). Usado en nombres de recursos y tags."
  type        = string
  default     = "staging"
}

variable "webhook_image" {
  description = "Imagen Docker del servicio Cloud Run del webhook (Artifact Registry), ej. southamerica-east1-docker.pkg.dev/<project>/guardia-digital/webhook:latest."
  type        = string
}

variable "auth0_webhook_secret" {
  description = "Secreto compartido para validar el webhook de Auth0 Log Streams (header Authorization: Bearer ...)."
  type        = string
  sensitive   = true
}

variable "log_retention_days" {
  description = "Retención de logs del servicio en Cloud Logging, en días (configurado a nivel de bucket de logging del proyecto, no por recurso individual)."
  type        = number
  default     = 30
}

variable "datadog_api_key" {
  description = "API Key de Datadog usada por la Cloud Function forwarder."
  type        = string
  sensitive   = true
}

variable "datadog_site" {
  description = "Sitio de Datadog donde se envían los logs (ej. datadoghq.com, us5.datadoghq.com)."
  type        = string
  default     = "datadoghq.com"
}

variable "worm_retention_years" {
  description = "Años de retención bloqueada (Bucket Lock) del archivo WORM de logs de acceso. 5 años por defecto, en línea con plazos habituales de prescripción de delitos económicos base de la Ley 20.393; ajustar con el equipo legal del cliente antes de un despliegue real."
  type        = number
  default     = 5
}

locals {
  common_labels = {
    project     = "guardia-digital-inteligente"
    environment = var.environment
    managed-by  = "terraform"
  }
}
