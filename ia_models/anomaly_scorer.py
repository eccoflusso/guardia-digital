"""
Módulo compartido entre `train_model.py` (entrena y serializa) y
`serving/serve.py` (deserializa y sirve). Debe vivir en un módulo importable
por su nombre real en ambos lados — si se define dentro de un script corrido
como `__main__`, joblib/pickle lo referencia como `__main__.AnomalyScorer` y
falla al deserializar en cualquier otro proceso (ver Sesión #6).
"""
from sklearn.pipeline import Pipeline


class AnomalyScorer:
    """Envoltorio fino: expone `.predict()` devolviendo la probabilidad de la
    clase anómala en vez de la etiqueta 0/1 — así el contenedor de predicción
    devuelve un score continuo, compatible con el umbral 0.8/0.95 que ya usa
    `ia_models/anomaly_detector.py`.
    """

    def __init__(self, pipeline: Pipeline):
        self.pipeline = pipeline

    def predict(self, X):
        proba = self.pipeline.predict_proba(X)
        anomaly_class_index = list(self.pipeline.classes_).index(1)
        return proba[:, anomaly_class_index]
