"""
Crea (o actualiza) el dashboard de Datadog "Guardia Digital — Operación y
Compliance" vía la API de Dashboards, a partir de las queries reales
verificadas contra los dos servicios que emiten telemetría:

  - service:guardia-auth0-webhook-staging  -> eventos de login normalizados
    (Lambda, ver lambdas/handler.js). Facets: @type, @user_id, @geo.country_code,
    @connection, @tenant.
  - service:guardia-ia-pipeline             -> telemetría del job de IA
    (Modal, ver ia_models/anomaly_detector.py::_ship_to_datadog). Facets:
    @event_type (anomaly_detected|enforcement|ingestion_cycle|error),
    @anomaly_score, @enforce_action, @error, @logs_found, @country_code.

Uso: python build_dashboard.py
Requiere DD_API_KEY, DD_APP_KEY, DD_SITE en el entorno (ya en .env).
"""
import json
import os

import requests

DD_API_KEY = os.environ["DD_API_KEY"]
DD_APP_KEY = os.environ["DD_APP_KEY"]
DD_SITE = os.environ.get("DD_SITE", "datadoghq.com")

LOGIN_SVC = "guardia-auth0-webhook-staging"
IA_SVC = "guardia-ia-pipeline"


def qv(title, query, aggregation="count", live_span="1d"):
    # live_span fija la ventana de tiempo del widget (independiente del selector
    # global del dashboard) para que el título "(24h)" sea cierto siempre,
    # no solo cuando el usuario tiene elegido "Past 1 Day" arriba a la derecha.
    return {
        "definition": {
            "title": title,
            "title_size": "13",
            "title_align": "left",
            "type": "query_value",
            "requests": [{
                "response_format": "scalar",
                "queries": [{
                    "data_source": "logs", "name": "q1",
                    "search": {"query": query},
                    "compute": {"aggregation": aggregation},
                }],
            }],
            "autoscale": True,
            "precision": 0,
            "time": {"live_span": live_span},
        }
    }


def toplist(title, query, facet, limit=10, aggregation="count", metric=None):
    compute = {"aggregation": aggregation}
    sort = {"order": "desc", "aggregation": aggregation}
    if aggregation != "count":
        # Promediar/sumar un campo numérico exige decirle a Datadog CUÁL campo
        # (bug real: sin esto, la query es inválida y el widget muestra error).
        compute["metric"] = metric
        sort["metric"] = metric
    return {
        "definition": {
            "title": title,
            "title_size": "13",
            "title_align": "left",
            "type": "toplist",
            "requests": [{
                "response_format": "scalar",
                "queries": [{
                    "data_source": "logs", "name": "q1",
                    "search": {"query": query},
                    "compute": compute,
                    "group_by": [{"facet": facet, "limit": limit, "sort": sort}],
                }],
                # Sin "formulas", Datadog no sabe qué query mostrar en un widget
                # toplist -- se guarda sin error, pero renderiza vacío siempre.
                "formulas": [{"formula": "q1"}],
            }],
        }
    }


def timeseries(title, query, aggregation="count", metric=None):
    compute = {"aggregation": aggregation}
    if aggregation != "count":
        compute["metric"] = metric
    return {
        "definition": {
            "title": title,
            "title_size": "13",
            "title_align": "left",
            "type": "timeseries",
            "requests": [{
                "response_format": "timeseries",
                "queries": [{
                    "data_source": "logs", "name": "q1",
                    "search": {"query": query},
                    "compute": compute,
                }],
                "display_type": "bars",
            }],
        }
    }


def geomap(title, query, facet):
    return {
        "definition": {
            "title": title,
            "title_size": "13",
            "title_align": "left",
            "type": "geomap",
            "requests": [{
                "response_format": "scalar",
                "queries": [{
                    "data_source": "logs", "name": "q1",
                    "search": {"query": query},
                    "compute": {"aggregation": "count"},
                    "group_by": [{"facet": facet, "limit": 50}],
                }],
            }],
            "style": {"palette": "hostmap_blues", "palette_flip": False},
            "view": {"focus": "WORLD"},
        }
    }


def log_stream(title, query, columns):
    return {
        "definition": {
            "title": title,
            "title_size": "13",
            "title_align": "left",
            "type": "list_stream",
            "requests": [{
                "response_format": "event_list",
                "query": {
                    "data_source": "logs_stream",
                    "query_string": query,
                    "indexes": [],
                    "storage": "hot",
                },
                "columns": [{"field": c, "width": "auto"} for c in columns],
            }],
        }
    }


def note(content, background_color="white"):
    return {"definition": {"type": "note", "content": content, "background_color": background_color, "font_size": "14"}}


def group(title, widgets):
    return {
        "definition": {
            "title": title,
            "type": "group",
            "layout_type": "ordered",
            "widgets": widgets,
        }
    }


dashboard = {
    "title": "Guardia Digital — Operación y Compliance",
    "description": "Resumen ejecutivo, mapa de accesos, detección de anomalías IA, "
                    "salud del pipeline y trazabilidad de auditoría (Ley 20.393).",
    "layout_type": "ordered",
    "widgets": [
        group("1. Resumen ejecutivo", [
            qv("Total logins (24h)", f"service:{LOGIN_SVC} @type:(s OR f OR fp)"),
            qv("Logins exitosos (24h)", f"service:{LOGIN_SVC} @type:s"),
            qv("Logins fallidos (24h)", f"service:{LOGIN_SVC} @type:f"),
            qv("Anomalías IA detectadas (24h)", f"service:{IA_SVC} @event_type:anomaly_detected"),
            toplist("Acciones de enforcement", f"service:{IA_SVC} @event_type:enforcement", "@enforce_action"),
        ]),
        group("2. Mapa de accesos (Zero-Trust)", [
            geomap("Origen geográfico de logins", f"service:{LOGIN_SVC} @type:(s OR f)", "@geo.country_code"),
            toplist("Top países por volumen de login", f"service:{LOGIN_SVC} @type:(s OR f)", "@geo.country_code"),
        ]),
        group("3. Detección de anomalías (Vertex AI)", [
            timeseries("Anomaly score en el tiempo (promedio)", f"service:{IA_SVC} @event_type:anomaly_detected",
                       "avg", metric="@anomaly_score"),
            toplist("Score promedio por país de origen", f"service:{IA_SVC} @event_type:anomaly_detected", "@country_code",
                    aggregation="avg", metric="@anomaly_score"),
            log_stream("Anomalías recientes (detalle)", f"service:{IA_SVC} @event_type:anomaly_detected",
                       ["timestamp", "@user_id", "@country_code", "@anomaly_score", "@hour_local"]),
        ]),
        group("4. Salud operacional del pipeline", [
            timeseries("Logs ingeridos por ciclo (cada 15 min)", f"service:{IA_SVC} @event_type:ingestion_cycle",
                       "avg", metric="@logs_found"),
            qv("Errores del pipeline (24h)", f"service:{IA_SVC} @event_type:error"),
            toplist("Tipos de error", f"service:{IA_SVC} @event_type:error", "@error"),
            log_stream("Errores recientes (detalle)", f"service:{IA_SVC} @event_type:error",
                       ["timestamp", "@error", "@detail"]),
        ]),
        group("5. Auditoría y compliance (Ley 20.393 / Ley 21.595)", [
            note(
                "**Trazabilidad de auditoría** — cada decisión de acceso (login, MFA, "
                "bloqueo) queda registrada con usuario, fecha/hora, geolocalización y "
                "resultado. Retención actual: según plan de Datadog contratado por la "
                "organización (confirmar período exacto con el account manager antes "
                "de certificar ante un auditor externo). Archivo inmutable (WORM, S3 "
                "Object Lock) disponible en `infra/worm_archive.tf`.",
                background_color="yellow",
            ),
            toplist("Eventos por Control Preventivo MPD", f"service:{IA_SVC} @mpd_control_category:*",
                    "@mpd_control_category"),
            log_stream("Trazabilidad de accesos (auditoría)", f"service:{LOGIN_SVC} @type:(s OR f OR fp OR limit_mu)",
                       ["timestamp", "@user_id", "@type", "@geo.country_code", "@connection", "@tenant"]),
        ]),
        group("6. Actividad por conexión / tenant", [
            toplist("Logins por conexión (AD sucursal / contratistas)", f"service:{LOGIN_SVC} @type:(s OR f)", "@connection"),
            toplist("Logins por tenant", f"service:{LOGIN_SVC} @type:(s OR f)", "@tenant"),
        ]),
    ],
}

# Si ya existe (guardado en dashboard_id.txt tras la primera corrida), lo
# actualiza in-place con PUT en vez de crear un duplicado.
EXISTING_ID_FILE = "dashboard_id.txt"
existing_id = None
if os.path.exists(EXISTING_ID_FILE):
    existing_id = open(EXISTING_ID_FILE, encoding="utf-8").read().strip()

headers = {
    "DD-API-KEY": DD_API_KEY,
    "DD-APPLICATION-KEY": DD_APP_KEY,
    "Content-Type": "application/json",
}

if existing_id:
    resp = requests.put(f"https://api.{DD_SITE}/api/v1/dashboard/{existing_id}", headers=headers, json=dashboard, timeout=30)
else:
    resp = requests.post(f"https://api.{DD_SITE}/api/v1/dashboard", headers=headers, json=dashboard, timeout=30)

if not resp.ok:
    print("ERROR", resp.status_code, resp.text)
resp.raise_for_status()
result = resp.json()

with open(EXISTING_ID_FILE, "w", encoding="utf-8") as f:
    f.write(result["id"])

print("Dashboard actualizado" if existing_id else "Dashboard creado:", result.get("title"))
print("ID:", result.get("id"))
print("URL:", f"https://app.{DD_SITE}{result.get('url')}")

with open("dashboard-compliance.json", "w", encoding="utf-8") as f:
    json.dump(result, f, indent=2, ensure_ascii=False)
print("Definición guardada en dashboard-compliance.json")
