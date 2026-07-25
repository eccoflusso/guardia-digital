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

## 1bis. Contexto de portafolio Wayweb

Guardia Digital Inteligente no es un producto aislado: es la pieza **"Identidad"**
de un portafolio de 3 productos Wayweb organizados como un ciclo de seguridad,
integrados **solo por API (sin unificar código)**:

| Producto | Rol en el ciclo | TRL / estado (2026-07-23) |
|---|---|---|
| **SCAN-SIGHT I.A.** (`scan.wayweb.cl`) | **Exterior** — EASM, escanea dominios y detecta exposición externa | TRL 6 · live en producción (GCP) |
| **Guardia Digital Inteligente** (este repo) | **Identidad** — IAM/Zero-Trust, reacciona al riesgo detectado afuera | TRL 3 · scaffolding |
| **SPC I.A.** (`ventisqueros.wayweb.cl`) | **Respuesta** — simulacros de crisis/TTX con datos reales | TRL ~5–6 · desplegado con cliente piloto (Ventisqueros) |

**Integración concreta:** el Action `auth0/post-login-mfa-adaptativo.js` consume
`GET https://api-pupzjflnwa-uc.a.run.app/risk-signal?domain=` (endpoint
`handle_risk_signal` del repo `scanner-ia/src/api/handler.py`, construido
específicamente para Guardia). Ese endpoint calcula un `risk_score` sobre los
hallazgos reales del dominio en Firestore y devuelve `mfa_posture`
(`enforce`/`step_up`/`standard`), que el Action usa para forzar MFA si la
superficie externa del cliente está comprometida. Llamada con timeout 1.5s y
**fail-open** (si no responde, no bloquea el login).

**Estado real de esta integración (verificado en código, no solo en diseño):**
- **Lado SCAN-SIGHT:** `/risk-signal` está **desplegado en producción y probado
  end-to-end** (dominio real `wayweb.cl` → postura `"enforce"`), según su propia
  bitácora (Sesión #24, 2026-06-24).
- **Lado Guardia:** el Action que lo consume **existe en este repo pero nunca se
  pegó en un tenant Auth0 real** — no está bloqueado por diseño ni por
  disponibilidad del scanner, sino porque Guardia todavía no tiene un tenant
  Auth0 configurado (ver Fase 1).
- La variable `SCAN_SIGHT_API` (URL del scanner, opcional) ya está documentada
  en `.env.example`.

---

## 2. Estado actual (gap analysis)

> Actualizado 2026-07-25 (Sesión #4): el código de los 6 componentes está
> **completo**, incluyendo el cierre del lazo de respuesta. Lo que falta en
> todos los casos es **desplegar contra cuentas reales** — nada de esto ha
> sido validado en un entorno real todavía (sigue en TRL 3, ver bitácora).

| Componente              | Estado                  | Falta para producción                                                                                                            |
| ----------------------- | ----------------------- | -------------------------------------------------------------------------------------------------------------------------------- |
| `/infra` (Terraform)    | **Completo** — `variables.tf`/`outputs.tf` separados, backend S3+DynamoDB (partial config), tags, log group con retención. `terraform validate` OK | Crear bucket S3 + tabla DynamoDB reales, completar `backend.staging.hcl`, `terraform apply` en cuenta de staging |
| `/lambdas` (Node 20)    | **Completo** — idempotencia por `auth0_log_id` (hash determinístico), comparación constant-time del secret, 9 tests (`node --test`, todos pasan) | Desplegar vía Terraform; encolado a SQS/Kinesis sigue como mejora futura (no bloquea Fase 2) |
| `/auth0` (Action)       | **Completo** — señal SCAN-SIGHT con logging en fallos (antes silencioso), y lee `force_mfa_until` para el lazo de respuesta | Pegar en Auth0 Dashboard, configurar secrets, probar reglas de riesgo en tenant real |
| `/ia_models` (Modal)    | **Completo** — `_fetch_pending_logs()` real (Datadog Logs API v2 con cursor persistente), `_enforce_auth0_response()` cierra el lazo (Management API: re-MFA o bloqueo según score) | Modelo entrenado en Vertex (dataset sintético listo en `generate_synthetic_dataset.py`), desplegar job Modal con las 3 cuentas de secrets |
| `/monitoring` (Datadog) | Config declarativa      | Aplicar Forwarder (CloudFormation), crear pipelines/monitors vía API/UI                                                          |
| `/support` (Intercom)   | Snippet listo           | Fuera de alcance para TRL 5 (ver bitácora, sección Implementación)                                                                |

**TODOs resueltos en código en Sesión #4** (quedan pendientes de *desplegar*, no de escribir):

1. ~~`lambdas/handler.js` → idempotencia por `auth0_log_id`~~ — resuelto (hash determinístico del `log_id`, ver tests).
2. ~~`ia_models/anomaly_detector.py` → `_fetch_pending_logs()` era un stub~~ — resuelto (Datadog Logs API v2 + cursor en `modal.Dict`).
3. ~~`ia_models/anomaly_detector.py` → webhook a Auth0 Management API~~ — resuelto (`_enforce_auth0_response()`: `force_mfa_until` en `app_metadata` o `blocked:true` según `anomaly_score`).

**Pendiente real (no de código):** encolado a SQS/Kinesis en `lambdas/handler.js` si el volumen de logins crece — se deja como mejora futura, no bloquea ninguna fase.

---

## 3. Prerrequisitos (cuentas y tooling)

**Tooling local** (verificado en este equipo):

- ✅ node v24 · npm 11 · python 3.13 · aws-cli 2.34 · gcloud 565 · modal 1.4 · git 2.53
- ✅ **Terraform 1.15.8** — instalado (`winget install Hashicorp.Terraform`), `terraform validate` OK sobre `/infra` refactorizado.

**Cuentas / credenciales necesarias** (cada una habilita una fase — en gestión, Sesión #4):

- Auth0 tenant (plan con Adaptive MFA / Log Streams) + Application M2M para la Management API (scopes `read:users update:users`, usada para cerrar el lazo).
- AWS account + IAM user/role con permisos de despliegue (Lambda, API GW, IAM, CloudWatch), región **sa-east-1**.
- GCP project con Vertex AI habilitado + service account JSON.
- Modal account (token).
- Datadog account + **API key y Application key** (la Logs Search API v2 exige ambos).
- ~~Intercom workspace + App ID~~ — fuera de alcance para TRL 5.

**Variables de entorno** (consolidar en `.env.example`, nunca commitear `.env`):
| Variable | Componente |
|---|---|
| `AUTH0_WEBHOOK_SECRET` | Lambda + Auth0 Log Stream |
| `GCP_PROJECT`, `VERTEX_ENDPOINT_ID`, `VERTEX_REGION` | Modal |
| `DD_API_KEY`, `DD_APP_KEY` | Datadog Forwarder + ingesta (`_fetch_pending_logs`) |
| `AWS_REGION` (def. sa-east-1 por latencia/residencia LATAM) | Infra |
| `SCAN_SIGHT_API` (opcional; señal de postura MFA del portafolio, ver §1bis) | Auth0 Action |
| `AUTH0_DOMAIN`, `AUTH0_M2M_CLIENT_ID`, `AUTH0_M2M_CLIENT_SECRET` | Cierre del lazo (`_enforce_auth0_response`) |

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

### Fase 4 — Detección de anomalías (Modal + Vertex) · ~3–5 días _(camino crítico)_

> **Decisión tomada:** Vertex AI desde el inicio (no se empieza con heurísticas).

- **Entrenar/desplegar el modelo en Vertex AI** (no existe aún) — viaje imposible,
  fuera de turno, dispositivo nuevo. Definir features y endpoint.
- Implementar `_fetch_pending_logs()` real (fuente: Datadog Logs API o S3/SQS).
- Cerrar el lazo: webhook a Auth0 Management API para re-MFA/bloqueo (TODO §2.3).
- Desplegar job Modal (schedule 15 min) con secrets GCP.
- **Hito:** acceso anómalo detectado → respuesta automática en Auth0.

### Fase 5 — Endurecimiento y go-live · ~2–3 días

- Seguridad: rotación de `AUTH0_WEBHOOK_SECRET`, least-privilege IAM, WAF/rate-limit en API GW.
- Resiliencia: DLQ en Lambda, reintentos en Modal. ~~Idempotencia por `auth0_log_id`~~ (resuelto en Sesión #4).
- Compliance Ley 20.393: retención de logs, trazabilidad de decisiones MFA, evidencia de auditoría.
- Promoción staging → prod; runbook de incidentes.

**Ruta crítica:** Fase 4 (modelo Vertex + lazo de respuesta) es lo más largo y
riesgoso; todo lo demás puede avanzar en paralelo una vez listas las cuentas.

---

## 5. Riesgos y decisiones abiertas

| Riesgo / Decisión                         | Impacto                            | Recomendación                                                                                                                       |
| ----------------------------------------- | ---------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------- |
| Modelo Vertex AI no existe                | Fase 4 bloqueada                   | Mitigado (Sesión #4): `generate_synthetic_dataset.py` genera dataset etiquetado listo para AutoML — ya no depende de datos orgánicos |
| Región AWS (us-east-1 vs sa-east-1)       | Latencia/costo/residencia de datos | **Decidido:** sa-east-1 (São Paulo) — ya es el default en `infra/variables.tf` y `.env.example`                                     |
| Ingesta Modal hoy es stub                 | Lazo IA abierto                    | Resuelto (Sesión #4): `_fetch_pending_logs()` real contra Datadog Logs API v2, cursor persistente en `modal.Dict`                   |
| Validación de webhook por Bearer estático | Riesgo si se filtra                | Mitigado (Sesión #4): comparación constant-time (`timingSafeEqual`) — migración a firma HMAC sigue pendiente, no crítica            |
| Estado de Terraform local                 | Colisión/pérdida                   | Resuelto (Sesión #4): `backend "s3" {}` con partial config (`backend.example.hcl`); falta crear el bucket/tabla reales               |
| Residencia de datos personales (Chile)    | Compliance                         | Confirmar marco legal aplicable y retención antes de prod                                                                           |
| Lazo de respuesta a Auth0 (re-MFA/bloqueo) | Función central del producto       | Resuelto (Sesión #4): `_enforce_auth0_response()` vía Management API — falta validar contra tenant Auth0 real                        |
| Dependencia de SCAN-SIGHT I.A. (`/risk-signal`) | Bajo — señal opcional, fail-open | Ya verificada y en producción del lado scanner (§1bis); no bloquea el login si no responde. Monitorear disponibilidad una vez activa. |

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
