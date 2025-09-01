#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
AI Payload Classifier (for WAF)
-------------------------------
- Loads labeled XLSX payload samples
- Trains & caches TF-IDF + LinearSVC
- Predicts input payload category (0: benign, 1: SQLi, 2: XSS, 3: DDoS)
- Lazy thread-safe loading
"""

import os
import time
import joblib
import threading
import pandas as pd
import numpy as np
from typing import List, Tuple
from functools import wraps

from sklearn.pipeline import Pipeline
from sklearn.svm import LinearSVC
from sklearn.model_selection import GridSearchCV
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.utils.class_weight import compute_class_weight
from sklearn.exceptions import NotFittedError

# --------------------------
# CONFIG
# --------------------------
MODEL_PATH = os.getenv("AI_MODEL_PATH", "ai_detector_model.pkl")
PAYLOAD_DIR = os.getenv("AI_PAYLOAD_DIR", "payloads")
TUNE_MODE = os.getenv("AI_DETECTOR_TUNE", "0") == "1"
RATE_LIMIT_CALLS = int(os.getenv("AI_RATE_MAX_CALLS", 100))
RATE_LIMIT_PERIOD = int(os.getenv("AI_RATE_PERIOD", 60))

LABEL_MAP = {
    0: "benign.xlsx",
    1: "sqli.xlsx",
    2: "xss.xlsx",
    3: "ddos.xlsx"
}

# Thread-safe model cache
_model = None
_model_lock = threading.Lock()

# --------------------------
# RATE LIMITING
# --------------------------
def rate_limit(max_calls, period_sec):
    calls = []
    lock = threading.Lock()

    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            nonlocal calls
            now = time.time()
            with lock:
                calls = [t for t in calls if now - t < period_sec]
                if len(calls) >= max_calls:
                    raise RuntimeError("Rate limit exceeded.")
                calls.append(now)
            return func(*args, **kwargs)
        return wrapper
    return decorator

# --------------------------
# DATA LOADING
# --------------------------
def _read_payload_file(xlsx_path: str) -> List[str]:
    if not os.path.exists(xlsx_path):
        raise FileNotFoundError(f"Missing file: {xlsx_path}")

    try:
        df = pd.read_excel(xlsx_path, engine="openpyxl", usecols=[0])
    except Exception as e:
        raise RuntimeError(f"Error reading {xlsx_path}: {e}")

    samples = df.iloc[:, 0].dropna().astype(str).tolist()
    if not samples:
        raise ValueError(f"No valid entries in {xlsx_path}")

    return samples

def _load_all_payloads() -> Tuple[List[str], List[int]]:
    texts, labels = [], []
    for label, filename in LABEL_MAP.items():
        path = os.path.join(PAYLOAD_DIR, filename)
        entries = _read_payload_file(path)
        texts.extend(entries)
        labels.extend([label] * len(entries))
    return texts, labels

# --------------------------
# MODEL BUILDING
# --------------------------
def _build_pipeline() -> Pipeline:
    tfidf = TfidfVectorizer(
        analyzer="char_wb",
        ngram_range=(3, 5),
        lowercase=True,
        sublinear_tf=True
    )
    clf = LinearSVC(random_state=42)
    return Pipeline([("tfidf", tfidf), ("clf", clf)])

def _train_model() -> Pipeline:
    X, y = _load_all_payloads()
    classes = np.unique(y)
    weights = compute_class_weight("balanced", classes=classes, y=y)
    class_weight_dict = dict(zip(classes, weights))

    pipeline = _build_pipeline()

    if TUNE_MODE:
        param_grid = {
            "tfidf__ngram_range": [(3, 5), (3, 6)],
            "clf__C": [0.5, 1.0, 2.0],
            "clf__class_weight": [class_weight_dict]
        }
        search = GridSearchCV(pipeline, param_grid, cv=3, scoring="f1_macro", n_jobs=-1)
        search.fit(X, y)
        model = search.best_estimator_
    else:
        clf = LinearSVC(C=1.0, class_weight=class_weight_dict, random_state=42)
        vectorizer = pipeline.named_steps["tfidf"]
        model = Pipeline([("tfidf", vectorizer), ("clf", clf)])
        model.fit(X, y)

    joblib.dump({
        "model": model,
        "meta": {
            "classes": classes.tolist(),
            "trained": time.time(),
            "tuned": TUNE_MODE
        }
    }, MODEL_PATH)
    return model

def _load_or_train() -> Pipeline:
    global _model
    with _model_lock:
        if _model is not None:
            return _model
        if os.path.exists(MODEL_PATH):
            try:
                payload = joblib.load(MODEL_PATH)
                _model = payload["model"]
                return _model
            except Exception:
                pass
        _model = _train_model()
        return _model

# --------------------------
# PUBLIC INFERENCE API
# --------------------------
@rate_limit(RATE_LIMIT_CALLS, RATE_LIMIT_PERIOD)
def detect_attack(payload: str) -> int:
    try:
        model = _load_or_train()
        clean = payload.strip()
        if not clean:
            return 0
        return int(model.predict([clean])[0])
    except NotFittedError:
        model = _train_model()
        return int(model.predict([payload])[0])
    except Exception as e:
        return 0  # default to benign

# --------------------------
# MAIN TEST ENTRY
# --------------------------
if __name__ == "__main__":
    print(">> AI Detector starting up...")
    try:
        model = _load_or_train()
        print("Model ready. Sample predictions:")
        for test in [
            "Hello world",
            "<script>alert(1)</script>",
            "SELECT * FROM users WHERE id = 1 --",
            "GET / " * 40
        ]:
            label = detect_attack(test)
            print(f"{test[:50]:50} => {label}")
    except Exception as e:
        print("ERROR:", str(e))
