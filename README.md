# Guardia Digital Inteligente — B2B IAM SaaS (Chile)

Plataforma modular de Gestión de Identidades y Accesos (IAM/IGA) orientada a
Mid-Market chileno: Zero-Trust, reducción de costos TI y cumplimiento de
auditorías (Ley 20.393).

## Apertura en VS Code
```bash
unzip proyecto_guardia_digital.zip
code guardia_digital_inteligente
```

## Estructura
| Carpeta       | Componente                                              |
|---------------|---------------------------------------------------------|
| `/infra`      | Terraform: API Gateway + Lambda (AWS, serverless)       |
| `/lambdas`    | Handler Node.js para webhooks de Auth0 (Log Streams)    |
| `/auth0`      | Auth0 Action: MFA adaptativo post-login                 |
| `/ia_models`  | Job batch en Modal -> Vertex AI (detección de anomalías)|
| `/monitoring` | Datadog: forwarder de logs AWS + dashboard compliance   |
| `/support`    | Widget/bot de Intercom embebido en el login             |

## Dependencias por carpeta
```bash
# /infra
cd infra && terraform init

# /lambdas
cd lambdas && npm init -y && npm install   # sin deps externas (runtime nativo)

# /auth0  -> pegar el código en Auth0 Dashboard > Actions > Library (no requiere npm local)

# /ia_models
cd ia_models && pip install modal google-cloud-aiplatform

# /monitoring -> aplicar vía API de Datadog o UI (Logs > Pipelines / Dashboards)

# /support -> snippet JS, se inserta en la página de login (Auth0 Universal Login)
```

## Variables de entorno requeridas
- `AUTH0_WEBHOOK_SECRET` (Lambda)
- `GCP_PROJECT`, `VERTEX_ENDPOINT_ID`, `VERTEX_REGION` (Modal)
- `DD_API_KEY` (Datadog Forwarder)
- `INTERCOM_APP_ID` (widget)
