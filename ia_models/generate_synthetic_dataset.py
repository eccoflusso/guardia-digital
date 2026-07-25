"""
Generador de dataset sintético para entrenar el primer modelo de detección de
anomalías en Vertex AI (AutoML Tabular), sin depender de logs reales de
producción (que hoy no existen — ver PLAN_IMPLEMENTACION.md §1bis y la
sección "Implementación" de la bitácora: es la mitigación del cuello de
botella de la Fase 4).

Uso:
    python generate_synthetic_dataset.py --rows 5000 --out dataset.csv

Columnas generadas (mismo esquema que consume `detect_anomalies` en
anomaly_detector.py, más la etiqueta `is_anomaly` que exige AutoML):
    user_id, ip, lat, lng, country, hour_local, event_type, is_anomaly

Patrones simulados:
    - Normal: usuario con "home base" fijo (Santiago, Chile), login en
      horario laboral (07:00-22:00 CLT), IP consistente con su perfil.
    - Anómalo — viaje imposible: dos logins del mismo usuario en países muy
      distantes dentro de una ventana de tiempo irreal para viajar.
    - Anómalo — fuera de turno: login entre 00:00 y 05:00 CLT.
    - Anómalo — dispositivo/IP nueva combinada con país distinto a Chile.
"""
import argparse
import csv
import random
from dataclasses import dataclass

COUNTRIES = {
    "CL": (-33.45, -70.66),   # Santiago — home base del mid-market chileno
    "AR": (-34.60, -58.38),
    "PE": (-12.05, -77.03),
    "US": (37.77, -122.42),
    "RU": (55.75, 37.62),
    "CN": (39.90, 116.40),
    "NG": (9.06, 7.49),
}
NORMAL_COUNTRIES = ["CL"]
ANOMALOUS_COUNTRIES = ["US", "RU", "CN", "NG"]


@dataclass
class Row:
    user_id: str
    ip: str
    lat: float
    lng: float
    country: str
    hour_local: int
    event_type: str
    is_anomaly: int


def _jitter(coord: float, spread: float = 0.05) -> float:
    return round(coord + random.uniform(-spread, spread), 4)


def _random_ip(country: str) -> str:
    # Rangos ficticios, solo para variar el feature — no corresponden a bloques reales.
    prefix = {"CL": "200.27", "AR": "190.15", "PE": "190.42", "US": "72.14",
              "RU": "95.108", "CN": "116.128", "NG": "105.112"}.get(country, "203.0")
    return f"{prefix}.{random.randint(0, 255)}.{random.randint(1, 254)}"


def make_normal_row(user_id: str) -> Row:
    country = random.choice(NORMAL_COUNTRIES)
    lat, lng = COUNTRIES[country]
    return Row(
        user_id=user_id,
        ip=_random_ip(country),
        lat=_jitter(lat),
        lng=_jitter(lng),
        country=country,
        hour_local=random.randint(7, 21),  # horario laboral CLT
        event_type="s",
        is_anomaly=0,
    )


def make_anomalous_row(user_id: str, kind: str | None = None) -> Row:
    kind = kind or random.choice(["viaje_imposible", "fuera_de_turno", "geo_ip_nueva"])

    if kind == "fuera_de_turno":
        country = "CL"
        lat, lng = COUNTRIES[country]
        hour_local = random.choice([0, 1, 2, 3, 4])
    else:
        # viaje_imposible y geo_ip_nueva comparten la señal principal: país
        # inusual para el perfil del usuario (fuera del perímetro CL).
        country = random.choice(ANOMALOUS_COUNTRIES)
        lat, lng = COUNTRIES[country]
        hour_local = random.randint(0, 23)

    return Row(
        user_id=user_id,
        ip=_random_ip(country),
        lat=_jitter(lat),
        lng=_jitter(lng),
        country=country,
        hour_local=hour_local,
        event_type=random.choices(["s", "f"], weights=[0.7, 0.3])[0],
        is_anomaly=1,
    )


def generate(rows: int, anomaly_ratio: float, seed: int) -> list[Row]:
    random.seed(seed)
    n_users = max(20, rows // 25)  # ~25 eventos por usuario en promedio
    users = [f"auth0|synthetic-{i:04d}" for i in range(n_users)]

    n_anomalous = int(rows * anomaly_ratio)
    n_normal = rows - n_anomalous

    data = [make_normal_row(random.choice(users)) for _ in range(n_normal)]
    data += [make_anomalous_row(random.choice(users)) for _ in range(n_anomalous)]
    random.shuffle(data)
    return data


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--rows", type=int, default=5000, help="Filas totales a generar.")
    parser.add_argument("--anomaly-ratio", type=float, default=0.08,
                         help="Proporción de filas anómalas (default 8%%, similar a incidencia real esperada).")
    parser.add_argument("--seed", type=int, default=42, help="Semilla para reproducibilidad.")
    parser.add_argument("--out", type=str, default="synthetic_login_dataset.csv", help="Ruta del CSV de salida.")
    args = parser.parse_args()

    rows = generate(args.rows, args.anomaly_ratio, args.seed)

    with open(args.out, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=[
            "user_id", "ip", "lat", "lng", "country", "hour_local", "event_type", "is_anomaly",
        ])
        writer.writeheader()
        for row in rows:
            writer.writerow(row.__dict__)

    n_anomalous = sum(r.is_anomaly for r in rows)
    print(f"Generadas {len(rows)} filas ({n_anomalous} anómalas, "
          f"{n_anomalous / len(rows):.1%}) -> {args.out}")
    print("Siguiente paso: subir el CSV a Vertex AI (Datasets > Tabular) y entrenar "
          "un modelo AutoML con target = is_anomaly.")


if __name__ == "__main__":
    main()
