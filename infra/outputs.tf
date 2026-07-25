output "webhook_url" {
  description = "URL a configurar en el Log Stream (HTTP) de Auth0."
  value       = "${aws_apigatewayv2_api.main.api_endpoint}/webhooks/auth0"
}

output "lambda_function_name" {
  description = "Nombre de la función Lambda del receptor de webhooks."
  value       = aws_lambda_function.auth0_webhook.function_name
}

output "lambda_log_group" {
  description = "Log group de CloudWatch a suscribir en el Datadog Forwarder."
  value       = aws_cloudwatch_log_group.auth0_webhook.name
}
