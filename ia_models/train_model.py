"""
Entrena el primer modelo de detección de anomalías de acceso, sobre el dataset
sintético generado por `generate_synthetic_dataset.py`, y lo empaqueta para
desplegar en Vertex AI usando el contenedor de predicción pre-armado de
scikit-learn (sin necesidad de Docker propio).

Uso:
    python train_model.py --data synthetic_login_dataset.csv --out model_artifact/model.joblib

Diseño clave: Vertex AI (contenedor pre-armado sklearn) llama a `model.predict(instances)`
y devuelve el resultado tal cual como `predictions`. anomaly_detector.py espera un
`anomaly_score` continuo (0.0-1.0), no una etiqueta 0/1. Por eso `AnomalyScorer.predict()`
devuelve `predict_proba()[:, 1]` en vez de la etiqueta dura de RandomForestClassifier.
"""
import argparse
import os

import joblib
import pandas as pd
from sklearn.compose import ColumnTransformer
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, roc_auc_score
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import OneHotEncoder

from anomaly_scorer import AnomalyScorer  # módulo compartido con serving/serve.py

NUMERIC_FEATURES = ["lat", "lng", "hour_local"]
CATEGORICAL_FEATURES = ["country", "event_type"]
TARGET = "is_anomaly"


def build_pipeline() -> Pipeline:
    preprocessor = ColumnTransformer(
        transformers=[
            ("num", "passthrough", NUMERIC_FEATURES),
            ("cat", OneHotEncoder(handle_unknown="ignore"), CATEGORICAL_FEATURES),
        ]
    )
    return Pipeline(steps=[
        ("preprocess", preprocessor),
        ("classifier", RandomForestClassifier(
            n_estimators=200, max_depth=8, class_weight="balanced",
            random_state=42, n_jobs=-1,
        )),
    ])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--data", default="synthetic_login_dataset.csv")
    parser.add_argument("--out", default="model_artifact/model.joblib")
    parser.add_argument("--test-size", type=float, default=0.2)
    args = parser.parse_args()

    df = pd.read_csv(args.data)
    features = NUMERIC_FEATURES + CATEGORICAL_FEATURES
    X, y = df[features], df[TARGET]

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=args.test_size, random_state=42, stratify=y,
    )

    pipeline = build_pipeline()
    pipeline.fit(X_train, y_train)

    y_pred = pipeline.predict(X_test)
    y_proba = pipeline.predict_proba(X_test)[:, list(pipeline.classes_).index(1)]

    print("=== Evaluación en holdout (20%) ===")
    print(classification_report(y_test, y_pred, target_names=["normal", "anomalia"]))
    print(f"ROC-AUC: {roc_auc_score(y_test, y_proba):.4f}")

    scorer = AnomalyScorer(pipeline)

    os.makedirs(os.path.dirname(args.out) or ".", exist_ok=True)
    joblib.dump(scorer, args.out)
    print(f"\nModelo guardado en {args.out} (formato: AnomalyScorer, predict() -> anomaly_score continuo)")


if __name__ == "__main__":
    main()
