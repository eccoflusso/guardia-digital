"""
Campaña de validación formal — Semana 3 del plan hacia TRL5.

Ejecuta una matriz de escenarios controlados contra el modelo real ya
desplegado en Vertex AI (invocando la función `detect_anomalies` ya
desplegada en Modal, modo `modal deploy`), mide score y latencia de cada
uno, y deja evidencia consolidada en `validation_results.json`.

Uso: modal run validation_campaign.py
"""
import json
import time

import modal

app = modal.App("guardia-validation-campaign")

SCENARIOS = [
    {
        "name": "Login normal (horario laboral, Chile)",
        "expected": "sin anomalía",
        "log": {
            "user_id": "auth0|campaign-test", "ip": "200.27.10.5",
            "geo": {"latitude": -33.45, "longitude": -70.66, "country_code": "CL"},
            "hour_local": 14, "type": "s",
        },
    },
    {
        "name": "Fuera de turno (03:00 CLT, Chile)",
        "expected": "anomalía (re-MFA o bloqueo)",
        "log": {
            "user_id": "auth0|campaign-test", "ip": "200.27.10.5",
            "geo": {"latitude": -33.45, "longitude": -70.66, "country_code": "CL"},
            "hour_local": 3, "type": "s",
        },
    },
    {
        "name": "Viaje imposible / país inusual (Rusia)",
        "expected": "anomalía (re-MFA o bloqueo)",
        "log": {
            "user_id": "auth0|campaign-test", "ip": "95.108.1.1",
            "geo": {"latitude": 55.75, "longitude": 37.62, "country_code": "RU"},
            "hour_local": 10, "type": "s",
        },
    },
    {
        "name": "Geo-IP nueva combinada (Nigeria, tarde-noche)",
        "expected": "anomalía (re-MFA o bloqueo)",
        "log": {
            "user_id": "auth0|campaign-test", "ip": "105.112.1.1",
            "geo": {"latitude": 9.06, "longitude": 7.49, "country_code": "NG"},
            "hour_local": 20, "type": "s",
        },
    },
    {
        "name": "Borde de horario laboral (07:00 CLT, límite inferior)",
        "expected": "sin anomalía (límite del rango normal)",
        "log": {
            "user_id": "auth0|campaign-test", "ip": "200.27.10.5",
            "geo": {"latitude": -33.45, "longitude": -70.66, "country_code": "CL"},
            "hour_local": 7, "type": "s",
        },
    },
    {
        "name": "Login fallido en horario normal (Chile)",
        "expected": "sin anomalía por geo/horario",
        "log": {
            "user_id": "auth0|campaign-test", "ip": "200.27.10.6",
            "geo": {"latitude": -33.45, "longitude": -70.66, "country_code": "CL"},
            "hour_local": 11, "type": "f",
        },
    },
]


@app.local_entrypoint()
def main():
    detect_anomalies = modal.Function.from_name("guardia-anomaly-detector", "detect_anomalies")

    results = []
    for scenario in SCENARIOS:
        start = time.time()
        anomalies = detect_anomalies.remote([scenario["log"]])
        elapsed_ms = round((time.time() - start) * 1000, 1)

        detected = len(anomalies) > 0
        score = anomalies[0]["anomaly_score"] if detected else None

        result = {
            "scenario": scenario["name"],
            "expected": scenario["expected"],
            "detected_as_anomaly": detected,
            "anomaly_score": score,
            "latency_ms": elapsed_ms,
        }
        results.append(result)
        print(f"[{ '✓' if detected else '·' }] {scenario['name']}")
        print(f"    esperado: {scenario['expected']}")
        print(f"    score: {score} | latencia: {elapsed_ms} ms\n")

    with open("validation_results.json", "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2, ensure_ascii=False)

    n_detected = sum(1 for r in results if r["detected_as_anomaly"])
    avg_latency = sum(r["latency_ms"] for r in results) / len(results)
    print("=== RESUMEN ===")
    print(f"Escenarios corridos: {len(results)}")
    print(f"Detectados como anómalos: {n_detected}")
    print(f"Latencia promedio: {avg_latency:.1f} ms")
    print("Resultados guardados en validation_results.json")
