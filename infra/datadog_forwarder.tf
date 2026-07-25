# Fase 3 — Observabilidad / SIEM: Datadog Forwarder oficial (CloudFormation
# empaquetado, gestionado vía Terraform) + suscripción del log group de la
# Lambda de Guardia Digital, para que los eventos de login lleguen a Datadog.

resource "aws_cloudformation_stack" "datadog_forwarder" {
  name         = "guardia-digital-datadog-forwarder-${var.environment}"
  capabilities = ["CAPABILITY_IAM", "CAPABILITY_AUTO_EXPAND"]
  template_url = "https://datadog-cloudformation-template.s3.amazonaws.com/aws/forwarder/latest.yaml"

  parameters = {
    DdApiKey     = var.datadog_api_key
    DdSite       = var.datadog_site
    FunctionName = "guardia-digital-datadog-forwarder-${var.environment}"
  }

  tags = local.common_tags
}

resource "aws_lambda_permission" "datadog_forwarder_from_logs" {
  statement_id  = "AllowCloudWatchLogsInvokeDatadogForwarder"
  action        = "lambda:InvokeFunction"
  function_name = aws_cloudformation_stack.datadog_forwarder.outputs["DatadogForwarderArn"]
  principal     = "logs.${var.aws_region}.amazonaws.com"
  source_arn    = "${aws_cloudwatch_log_group.auth0_webhook.arn}:*"
}

resource "aws_cloudwatch_log_subscription_filter" "auth0_webhook_to_datadog" {
  name            = "guardia-digital-to-datadog-${var.environment}"
  log_group_name  = aws_cloudwatch_log_group.auth0_webhook.name
  filter_pattern  = "" # todos los eventos del log group
  destination_arn = aws_cloudformation_stack.datadog_forwarder.outputs["DatadogForwarderArn"]

  depends_on = [aws_lambda_permission.datadog_forwarder_from_logs]
}
