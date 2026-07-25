variable "aws_region" {
  description = "Región AWS de despliegue. sa-east-1 (São Paulo) recomendada por latencia y residencia de datos LATAM."
  type        = string
  default     = "sa-east-1"
}

variable "environment" {
  description = "Nombre del ambiente (staging | prod). Usado en nombres de recursos y tags."
  type        = string
  default     = "staging"
}

variable "auth0_webhook_secret" {
  description = "Secreto compartido para validar el webhook de Auth0 Log Streams (header Authorization: Bearer ...)."
  type        = string
  sensitive   = true
}

variable "log_retention_days" {
  description = "Retención de CloudWatch Logs del handler, en días."
  type        = number
  default     = 30
}

variable "datadog_api_key" {
  description = "API Key de Datadog para el Forwarder oficial (CloudWatch Logs -> Datadog)."
  type        = string
  sensitive   = true
}

variable "datadog_site" {
  description = "Sitio de Datadog donde se envían los logs (ej. datadoghq.com, us5.datadoghq.com)."
  type        = string
  default     = "datadoghq.com"
}

locals {
  common_tags = {
    Project     = "guardia-digital-inteligente"
    Environment = var.environment
    ManagedBy   = "terraform"
  }
}
