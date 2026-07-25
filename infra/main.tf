terraform {
  required_version = ">= 1.5"

  required_providers {
    aws     = { source = "hashicorp/aws", version = "~> 5.0" }
    archive = { source = "hashicorp/archive", version = "~> 2.4" }
  }

  # Backend remoto de estado (S3 + DynamoDB lock). El bucket/tabla se crean una
  # sola vez fuera de Terraform (o en un stack bootstrap aparte) y se pasan acá
  # vía `terraform init -backend-config=backend.<env>.hcl` para no hardcodear
  # nombres de cuenta en el repo. Ver infra/backend.example.hcl.
  backend "s3" {}
}

provider "aws" {
  region = var.aws_region
}

# --- IAM Role para Lambda ---
resource "aws_iam_role" "lambda_exec" {
  name = "guardia-digital-lambda-exec-${var.environment}"
  assume_role_policy = jsonencode({
    Version = "2012-10-17",
    Statement = [{
      Action    = "sts:AssumeRole",
      Effect    = "Allow",
      Principal = { Service = "lambda.amazonaws.com" }
    }]
  })
  tags = local.common_tags
}

resource "aws_iam_role_policy_attachment" "lambda_logs" {
  role       = aws_iam_role.lambda_exec.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}

# --- Lambda: receptor de webhooks Auth0 ---
data "archive_file" "handler_zip" {
  type        = "zip"
  source_file = "${path.module}/../lambdas/handler.js"
  output_path = "${path.module}/handler.zip"
}

resource "aws_cloudwatch_log_group" "auth0_webhook" {
  name              = "/aws/lambda/guardia-auth0-webhook-${var.environment}"
  retention_in_days = var.log_retention_days
  tags              = local.common_tags
}

resource "aws_lambda_function" "auth0_webhook" {
  function_name    = "guardia-auth0-webhook-${var.environment}"
  role             = aws_iam_role.lambda_exec.arn
  runtime          = "nodejs20.x"
  handler          = "handler.handler"
  filename         = data.archive_file.handler_zip.output_path
  source_code_hash = data.archive_file.handler_zip.output_base64sha256
  timeout          = 10
  memory_size      = 128 # mínimo: optimización de costos serverless

  environment {
    variables = {
      AUTH0_WEBHOOK_SECRET = var.auth0_webhook_secret
    }
  }

  # Asegura que el log group (con retención definida) exista antes que la
  # Lambda cree el suyo propio por defecto (retención infinita).
  depends_on = [aws_cloudwatch_log_group.auth0_webhook]

  tags = local.common_tags
}

# --- API Gateway HTTP API (más barato que REST API) ---
resource "aws_apigatewayv2_api" "main" {
  name          = "guardia-digital-api-${var.environment}"
  protocol_type = "HTTP"
  tags          = local.common_tags
}

resource "aws_apigatewayv2_integration" "lambda" {
  api_id                 = aws_apigatewayv2_api.main.id
  integration_type       = "AWS_PROXY"
  integration_uri        = aws_lambda_function.auth0_webhook.invoke_arn
  payload_format_version = "2.0"
}

resource "aws_apigatewayv2_route" "webhook" {
  api_id    = aws_apigatewayv2_api.main.id
  route_key = "POST /webhooks/auth0"
  target    = "integrations/${aws_apigatewayv2_integration.lambda.id}"
}

resource "aws_apigatewayv2_stage" "default" {
  api_id      = aws_apigatewayv2_api.main.id
  name        = "$default"
  auto_deploy = true
  tags        = local.common_tags
}

resource "aws_lambda_permission" "apigw" {
  statement_id  = "AllowAPIGatewayInvoke"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.auth0_webhook.function_name
  principal     = "apigateway.amazonaws.com"
  source_arn    = "${aws_apigatewayv2_api.main.execution_arn}/*/*"
}
