"""
Servidor de predicción para Vertex AI (contenedor propio) — expone el
modelo AnomalyScorer entrenado por train_model.py sobre el protocolo de
predicción de Vertex AI (health check + predict route, formato
{"instances": [...]} -> {"predictions": [...]}).
"""
import os

import joblib
import pandas as pd
from fastapi import FastAPI, Request

from anomaly_scorer import AnomalyScorer  # noqa: F401 -- requerido por joblib.load para deserializar

MODEL_PATH = os.environ.get("MODEL_PATH", "/app/model_artifact/model.joblib")
FEATURES = ["lat", "lng", "hour_local", "country", "event_type"]

app = FastAPI()
model = joblib.load(MODEL_PATH)


@app.get(os.environ.get("AIP_HEALTH_ROUTE", "/health"))
def health():
    return {"status": "ok"}


@app.post(os.environ.get("AIP_PREDICT_ROUTE", "/predict"))
async def predict(request: Request):
    body = await request.json()
    instances = body["instances"]

    df = pd.DataFrame(instances)
    for col in FEATURES:
        if col not in df.columns:
            df[col] = None
    df = df[FEATURES]

    scores = model.predict(df)
    return {"predictions": [float(s) for s in scores]}
