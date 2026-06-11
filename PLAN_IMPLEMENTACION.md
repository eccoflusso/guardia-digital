# Plan de Implementación — Guardia Digital Inteligente

> IAM/IGA B2B para Mid-Market chileno. Zero-Trust, reducción de costo TI y
> cumplimiento de auditoría (Ley 20.393).
> Este documento es el plan maestro de puesta en marcha. **No se escribe código
> de producción aún**; describe arquitectura, fases, riesgos y checklist.

---

## 1. Arquitectura y flujo de datos

```
                         ┌──────────────────────────┐
   Usuario ──login──▶    │  Auth0 (Universal Login)  │
                         │  • Action post-login MFA   │  ← /auth0
                         │  • Widget Intercom (login) │  ← /support
                         │  • Log Streams (HTTP)      │
                         └─────────────┬──────────────┘
                                       │ POST /webhooks/auth0 (Bearer secret)
                                       ▼
                         ┌──────────────────────────┐
                         │  API Gateway HTTP API     │  ← /infra (Terraform)
                         │        │ AWS_PROXY        │
                         │        ▼                  │
                         │  Lambda guardia-webhook   │  ← /lambdas (Node 20)
                         │  valida → normaliza → log │
                         └─────────────┬──────────────┘
                                       │ stdout JSON
                                       ▼
                         ┌──────────────────────────┐
              CloudWatch │  Datadog Forwarder        │  ← /monitoring
              Logs   ──▶ │  pipelines + monitors      │
                         └─────────────┬──────────────┘
                                       │ (ingesta batch — HOY: stub)
                                       ▼
                         ┌──────────────────────────┐
                         │  Modal (cada 15 min)      │  ← /ia_models
                         │  → Vertex AI endpoint      │
                         │  anomaly_score ≥ 0.8       │
                         └─────────────┬──────────────┘
                                       │ (HOY: TODO) re-MFA / bloqueo
                                       ▼
                              Auth0 Management API
```

**Flujo crítico:** Auth0 emite logs → Lambda los normaliza → CloudWatch →
Datadog (SIEM/alertas) → Modal/Vertex evalúa anomalías → acción de respuesta
(re-MFA o bloqueo) de vuelta en Auth0. Hoy ese lazo **no está cerrado** (ver §4).

---

## 2. Estado actual (gap analysis)

| Componente | Estado | Falta para producción |
|---|---|---|
| `/infra` (Terraform) | Boilerplate funcional | `variables.tf`/`outputs.tf` separados, backend remoto de estado (S3+DynamoDB lock), `archive_file` provider, tags, stage logging |
| `/lambdas` (Node 20) | Handler completo | `package.json`, tests, validación de firma robusta, idempotencia, encolado a SQS/Kinesis (TODO en código) |
| `/auth0` (Action) | Snippet listo | Pegar en Auth0 Dashboard, configurar secrets, probar reglas de riesgo |
| `/ia_models` (Modal) | Boilerplate + **stubs** | `_fetch_pending_logs()` real, modelo entrenado en Vertex, webhook de respuesta a Auth0 (TODO) |
| `/monitoring` (Datadog) | Config declarativa | Aplicar Forwarder (CloudFormation), crear pipelines/monitors vía API/UI |
| `/support` (Intercom) | Snippet listo | App ID real, insertar en Page Template de Auth0 |

**TODOs explícitos en el código** (deuda conocida):
1. `lambdas/handler.js:208` → encolar en SQS/Kinesis si crece el volumen.
2. `ia_models/anomaly_detector.py:288,326` → `_fetch_pending_logs()` es un stub.
3. `ia_models/anomaly_detector.py:321` → webhook a Auth0 Management API para
   bloquear sesión / forzar re-MFA (el lazo de respuesta no está cerrado).

---

## 3. Prerrequisitos (cuentas y tooling)

**Tooling local** (verificado en este equipo):
- ✅ node v24 · npm 11 · python 3.13 · aws-cli 2.34 · gcloud 565 · modal 1.4 · git 2.53
- ❌ **Terraform** — no instalado. Instalar (`winget install Hashicorp.Terraform` o tfenv).

**Cuentas / credenciales necesarias** (cada una habilita una fase):
- Auth0 tenant (plan con Adaptive MFA / Log Streams).
- AWS account + IAM user/role con permisos de despliegue (Lambda, API GW, IAM, CloudWatch).
- GCP project con Vertex AI habilitado + service account JSON.
- Modal account (token).
- Datadog account + API key.
- Intercom workspace + App ID.

**Variables de entorno** (consolidar en `.env.example`, nunca commitear `.env`):
| Variable | Componente |
|---|---|
| `AUTH0_WEBHOOK_SECRET` | Lambda + Auth0 Log Stream |
| `GCP_PROJECT`, `VERTEX_ENDPOINT_ID`, `VERTEX_REGION` | Modal |
| `DD_API_KEY` | Datadog Forwarder |
| `INTERCOM_APP_ID` | Widget |
| `AWS_REGION` (def. us-east-1; evaluar sa-east-1 por latencia a Chile) | Infra |

---

## 4. Fases de implementación

### Fase 0 — Higiene del repo (sin costo) · ~0.5 día
- `git init` + `.gitignore` (node_modules, `.env`, `*.tfstate*`, `handler.zip`, `__pycache__`).
- `.env.example` con todas las variables de §3.
- `lambdas/package.json` (engine node 20, scripts de test/lint).
- Pre-commit: bloquear secretos (gitleaks/trufflehog).

### Fase 1 — Ingreso de identidad (Auth0 + soporte) · ~1 día
- Configurar tenant Auth0, Universal Login, conexión(es) AD/contratistas.
- Cargar Action `post-login-mfa-adaptativo.js`; validar reglas de riesgo en staging.
- Insertar widget Intercom en Page Template; configurar flujos de bot (bloqueo, MFA).
- **Hito:** login con MFA adaptativo + autoservicio funcional.

### Fase 2 — Captura y normalización (AWS) · ~1–2 días
- Refactor de `/infra`: separar variables/outputs, backend remoto S3+DynamoDB.
- `terraform init/plan/apply` en cuenta de **staging**.
- Crear Log Stream en Auth0 → `POST {webhook_url}/webhooks/auth0` con Bearer secret.
- Test e2e: login real → ver evento normalizado en CloudWatch.
- **Hito:** logs de Auth0 llegando estructurados a CloudWatch.

### Fase 3 — Observabilidad y SIEM (Datadog) · ~1 día
- Desplegar Datadog Forwarder (CloudFormation) y suscribir el log group.
- Aplicar pipelines (geo-ip, categorización) y monitores (fuerza bruta, anomalías).
- Importar `dashboard-compliance.json`.
- **Hito:** dashboard de compliance + alertas a Slack/PagerDuty activas.

### Fase 4 — Detección de anomalías (Modal + Vertex) · ~3–5 días *(camino crítico)*
> **Decisión tomada:** Vertex AI desde el inicio (no se empieza con heurísticas).
- **Entrenar/desplegar el modelo en Vertex AI** (no existe aún) — viaje imposible,
  fuera de turno, dispositivo nuevo. Definir features y endpoint.
- Implementar `_fetch_pending_logs()` real (fuente: Datadog Logs API o S3/SQS).
- Cerrar el lazo: webhook a Auth0 Management API para re-MFA/bloqueo (TODO §2.3).
- Desplegar job Modal (schedule 15 min) con secrets GCP.
- **Hito:** acceso anómalo detectado → respuesta automática en Auth0.

### Fase 5 — Endurecimiento y go-live · ~2–3 días
- Seguridad: rotación de `AUTH0_WEBHOOK_SECRET`, least-privilege IAM, WAF/rate-limit en API GW.
- Resiliencia: DLQ en Lambda, reintentos en Modal, idempotencia por `auth0_log_id`.
- Compliance Ley 20.393: retención de logs, trazabilidad de decisiones MFA, evidencia de auditoría.
- Promoción staging → prod; runbook de incidentes.

**Ruta crítica:** Fase 4 (modelo Vertex + lazo de respuesta) es lo más largo y
riesgoso; todo lo demás puede avanzar en paralelo una vez listas las cuentas.

---

## 5. Riesgos y decisiones abiertas

| Riesgo / Decisión | Impacto | Recomendación |
|---|---|---|
| Modelo Vertex AI no existe | Fase 4 bloqueada | **Decidido: Vertex AI desde el inicio.** Mitigar el camino crítico definiendo features y dataset de entrenamiento temprano (Fase 3) |
| Región AWS (us-east-1 vs sa-east-1) | Latencia/costo/residencia de datos | sa-east-1 (São Paulo) por cercanía y residencia LATAM; validar costo |
| Ingesta Modal hoy es stub | Lazo IA abierto | Definir fuente única (Datadog Logs API recomendada) en Fase 3 |
| Validación de webhook por Bearer estático | Riesgo si se filtra | Migrar a firma HMAC + rotación; mientras, secret en Secrets Manager |
| Estado de Terraform local | Colisión/pérdida | Backend remoto S3+DynamoDB antes de cualquier `apply` compartido |
| Residencia de datos personales (Chile) | Compliance | Confirmar marco legal aplicable y retención antes de prod |

---

## 6. Checklist de puesta en marcha

**Pre-vuelo**
- [ ] Terraform instalado localmente
- [ ] Credenciales de las 6 plataformas obtenidas y guardadas en gestor de secretos
- [ ] `.env.example`, `.gitignore`, `git init` hechos
- [ ] Cuenta AWS de **staging** separada de prod

**Por fase**
- [ ] F1: MFA adaptativo + widget verificados en Auth0 staging
- [ ] F2: webhook e2e (login → CloudWatch) OK
- [ ] F3: Datadog dashboard + 2 monitores activos
- [ ] F4: modelo Vertex desplegado + lazo de respuesta cerrado
- [ ] F5: seguridad, retención y runbook firmados

**Go-live**
- [ ] Secretos rotados y fuera del repo
- [ ] IAM con least-privilege auditado
- [ ] Evidencia de auditoría Ley 20.393 documentada
- [ ] Plan de rollback probado

---

## 7. Próximo paso sugerido

Arrancar por **Fase 0** (higiene del repo, sin costo ni credenciales): `git init`,
`.gitignore`, `.env.example` y `lambdas/package.json`. Es reversible, desbloquea
todo lo demás y deja el proyecto listo para colaborar. Avísame y lo ejecuto.
