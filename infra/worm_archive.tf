# Atributo diferenciador #1 (ver archivos/atributos.md) — Inmutabilidad de
# logs (estándar probatorio). Los eventos de acceso normalizados por la Lambda
# (guardia-auth0-webhook) ya viajan a Datadog para SIEM/observabilidad, pero
# Datadog no ofrece retención en modo WORM. Este archivo agrega una segunda
# ruta, en paralelo, hacia un bucket S3 con Object Lock en modo COMPLIANCE:
# una vez escrito, ningún usuario ni rol (incluido el dueño de la cuenta AWS)
# puede modificar o borrar un objeto antes de que venza el retention period.
# Eso es lo que permite invocar estos logs como evidencia ante un fiscal o
# auditor de la Ley 20.393: no es que "no se pueda", es que AWS lo rechaza a
# nivel de API aunque alguien tenga las credenciales root.
#
# CloudWatch Logs no puede escribir a S3 directamente vía subscription filter
# (solo admite Lambda, Kinesis Data Streams o Kinesis Data Firehose como
# destino) — se usa Firehose porque es el camino nativo sin mantener código
# propio para el archivador.

# --- Bucket WORM (Object Lock, modo COMPLIANCE) ---
resource "aws_s3_bucket" "worm_archive" {
  bucket = "guardia-digital-worm-archive-${var.environment}"

  # Object Lock solo puede habilitarse en la creación del bucket, no después.
  object_lock_enabled = true

  tags = local.common_tags
}

resource "aws_s3_bucket_versioning" "worm_archive" {
  bucket = aws_s3_bucket.worm_archive.id
  versioning_configuration {
    status = "Enabled" # requisito de Object Lock: el bucket debe tener versioning
  }
}

resource "aws_s3_bucket_object_lock_configuration" "worm_archive" {
  bucket = aws_s3_bucket.worm_archive.id

  rule {
    default_retention {
      mode  = "COMPLIANCE" # ni el root de la cuenta puede borrar/sobrescribir antes del plazo
      years = var.worm_retention_years
    }
  }

  depends_on = [aws_s3_bucket_versioning.worm_archive]
}

resource "aws_s3_bucket_public_access_block" "worm_archive" {
  bucket                  = aws_s3_bucket.worm_archive.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# --- Rol de Firehose: solo permiso de escritura al bucket WORM ---
resource "aws_iam_role" "firehose_worm" {
  name = "guardia-digital-firehose-worm-${var.environment}"
  assume_role_policy = jsonencode({
    Version = "2012-10-17",
    Statement = [{
      Action    = "sts:AssumeRole",
      Effect    = "Allow",
      Principal = { Service = "firehose.amazonaws.com" }
    }]
  })
  tags = local.common_tags
}

resource "aws_iam_role_policy" "firehose_worm_s3" {
  name = "s3-write-worm-archive"
  role = aws_iam_role.firehose_worm.id
  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [{
      Effect = "Allow",
      Action = [
        "s3:PutObject",
        "s3:GetBucketLocation",
        "s3:ListBucket",
      ],
      Resource = [
        aws_s3_bucket.worm_archive.arn,
        "${aws_s3_bucket.worm_archive.arn}/*",
      ]
    }]
  })
}

resource "aws_cloudwatch_log_group" "firehose_worm_errors" {
  name              = "/aws/kinesisfirehose/guardia-digital-worm-${var.environment}"
  retention_in_days = var.log_retention_days
  tags              = local.common_tags
}

# --- Firehose: CloudWatch Logs -> S3 (WORM), sin transformación ---
resource "aws_kinesis_firehose_delivery_stream" "worm_archive" {
  name        = "guardia-digital-worm-archive-${var.environment}"
  destination = "extended_s3"

  extended_s3_configuration {
    role_arn            = aws_iam_role.firehose_worm.arn
    bucket_arn          = aws_s3_bucket.worm_archive.arn
    prefix              = "auth0-access-events/year=!{timestamp:yyyy}/month=!{timestamp:MM}/day=!{timestamp:dd}/"
    error_output_prefix = "auth0-access-events-errors/year=!{timestamp:yyyy}/month=!{timestamp:MM}/day=!{timestamp:dd}/!{firehose:error-output-type}/"

    cloudwatch_logging_options {
      enabled         = true
      log_group_name  = aws_cloudwatch_log_group.firehose_worm_errors.name
      log_stream_name = "s3-delivery"
    }
  }

  tags = local.common_tags
}

# --- Rol para que CloudWatch Logs pueda invocar Firehose ---
resource "aws_iam_role" "cwl_to_firehose" {
  name = "guardia-digital-cwl-to-firehose-${var.environment}"
  assume_role_policy = jsonencode({
    Version = "2012-10-17",
    Statement = [{
      Action    = "sts:AssumeRole",
      Effect    = "Allow",
      Principal = { Service = "logs.${var.aws_region}.amazonaws.com" }
    }]
  })
  tags = local.common_tags
}

resource "aws_iam_role_policy" "cwl_to_firehose" {
  name = "put-record-worm-firehose"
  role = aws_iam_role.cwl_to_firehose.id
  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [{
      Effect   = "Allow",
      Action   = ["firehose:PutRecord", "firehose:PutRecordBatch"],
      Resource = aws_kinesis_firehose_delivery_stream.worm_archive.arn
    }]
  })
}

resource "aws_cloudwatch_log_subscription_filter" "auth0_webhook_to_worm" {
  name            = "guardia-digital-to-worm-archive-${var.environment}"
  log_group_name  = aws_cloudwatch_log_group.auth0_webhook.name
  filter_pattern  = "" # todos los eventos de acceso, sin excepción — la evidencia no se filtra
  destination_arn = aws_kinesis_firehose_delivery_stream.worm_archive.arn
  role_arn        = aws_iam_role.cwl_to_firehose.arn
}
