FROM python:3.12-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY serve.py .
COPY anomaly_scorer.py .
COPY model_artifact/model.joblib ./model_artifact/model.joblib

ENV MODEL_PATH=/app/model_artifact/model.joblib
EXPOSE 8080

CMD ["uvicorn", "serve:app", "--host", "0.0.0.0", "--port", "8080"]
