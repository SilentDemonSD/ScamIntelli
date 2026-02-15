import json
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import joblib

from src.scam_detector.text_preprocessor import get_preprocessor
from src.utils.logging import get_logger

logger = get_logger(__name__)

try:
    import numpy as np

    HAS_NUMPY = True
except ImportError:
    HAS_NUMPY = False
    np = None

try:
    from sklearn.ensemble import (
        GradientBoostingClassifier,
        RandomForestClassifier,
        VotingClassifier,
    )
    from sklearn.linear_model import LogisticRegression
    from sklearn.metrics import (
        accuracy_score,
        f1_score,
        log_loss,
        precision_score,
        recall_score,
    )
    from sklearn.model_selection import StratifiedKFold, cross_val_score, train_test_split
    from sklearn.preprocessing import StandardScaler

    HAS_SKLEARN = True
except ImportError:
    HAS_SKLEARN = False

try:
    import lightgbm as lgb

    HAS_LIGHTGBM = True
except ImportError:
    HAS_LIGHTGBM = False
    lgb = None

try:
    import xgboost as xgb

    HAS_XGBOOST = True
except ImportError:
    HAS_XGBOOST = False
    xgb = None


MODELS_DIR = Path("models")
ENSEMBLE_PATH = MODELS_DIR / "ensemble_detector.joblib"
SCALER_PATH = MODELS_DIR / "feature_scaler.joblib"
TRAINING_DATA_PATH = MODELS_DIR / "training_data.jsonl"
METRICS_PATH = MODELS_DIR / "training_metrics.json"


@dataclass
class TrainingMetrics:
    accuracy: float = 0.0
    precision: float = 0.0
    recall: float = 0.0
    f1: float = 0.0
    cv_mean: float = 0.0
    cv_std: float = 0.0
    log_loss_value: float = 0.0
    per_model: Dict[str, float] = field(default_factory=dict)
    n_samples: int = 0
    n_features: int = 0
    training_time_seconds: float = 0.0
    timestamp: str = ""

    def to_dict(self) -> dict:
        return {
            "accuracy": round(self.accuracy, 4),
            "precision": round(self.precision, 4),
            "recall": round(self.recall, 4),
            "f1": round(self.f1, 4),
            "cv_mean": round(self.cv_mean, 4),
            "cv_std": round(self.cv_std, 4),
            "log_loss": round(self.log_loss_value, 4),
            "per_model": {k: round(v, 4) for k, v in self.per_model.items()},
            "n_samples": self.n_samples,
            "n_features": self.n_features,
            "training_time_seconds": round(self.training_time_seconds, 2),
            "timestamp": self.timestamp,
        }


@dataclass
class EnsemblePrediction:
    is_scam: bool
    confidence: float
    per_model_scores: Dict[str, float]
    feature_importance: Dict[str, float]
    model_used: str = "ensemble"


class TrainingPipeline:

    def __init__(self):
        self._preprocessor = get_preprocessor()
        self._ensemble: Optional[Any] = None
        self._scaler: Optional[Any] = None
        self._feature_names: List[str] = []
        self._is_loaded = False
        self._load_model()

    def train(
        self,
        data_path: str = str(TRAINING_DATA_PATH),
        test_size: float = 0.2,
        cv_folds: int = 5,
    ) -> TrainingMetrics:
        if not HAS_SKLEARN or not HAS_NUMPY:
            raise RuntimeError("scikit-learn and numpy required for training")

        start_time = time.time()
        texts, labels = self._load_training_data(data_path)
        if len(texts) < 10:
            raise ValueError(f"Need at least 10 samples, got {len(texts)}")

        logger.info("Training on %d samples", len(texts))

        self._preprocessor.fit_tfidf(texts, max_features=500)

        X = self._preprocessor.get_combined_features(texts)
        y = np.array(labels, dtype=np.int32)

        if X is None:
            raise RuntimeError("Feature extraction failed")

        sample_feats = self._preprocessor.extract_features(texts[0])
        hand_names = list(sample_feats.to_dict().keys())
        n_tfidf = X.shape[1] - len(hand_names)
        tfidf_names = [f"tfidf_{i}" for i in range(n_tfidf)]
        self._feature_names = hand_names + tfidf_names

        self._scaler = StandardScaler()
        X_scaled = np.ascontiguousarray(self._scaler.fit_transform(X), dtype=np.float64)

        X_train, X_test, y_train, y_test = train_test_split(
            X_scaled, y, test_size=test_size, random_state=42, stratify=y
        )

        estimators = self._build_estimators()
        self._ensemble = VotingClassifier(
            estimators=estimators,
            voting="soft",
            n_jobs=-1,
        )

        cv = StratifiedKFold(n_splits=cv_folds, shuffle=True, random_state=42)
        cv_scores = cross_val_score(self._ensemble, X_train, y_train, cv=cv, scoring="accuracy")

        self._ensemble.fit(X_train, y_train)
        y_pred = self._ensemble.predict(X_test)
        y_pred_proba = self._ensemble.predict_proba(X_test)

        per_model = {}
        for name, model in self._ensemble.named_estimators_.items():
            pred = model.predict(X_test)
            per_model[name] = accuracy_score(y_test, pred)

        training_time = time.time() - start_time

        logloss = log_loss(y_test, y_pred_proba)

        metrics = TrainingMetrics(
            accuracy=accuracy_score(y_test, y_pred),
            precision=precision_score(y_test, y_pred, zero_division=0),
            recall=recall_score(y_test, y_pred, zero_division=0),
            f1=f1_score(y_test, y_pred, zero_division=0),
            cv_mean=cv_scores.mean(),
            cv_std=cv_scores.std(),
            log_loss_value=logloss,
            per_model=per_model,
            n_samples=len(texts),
            n_features=X.shape[1],
            training_time_seconds=training_time,
            timestamp=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        )

        self._save_model()
        self._save_metrics(metrics)
        self._is_loaded = True

        logger.info(
            "Training complete: acc=%.4f, f1=%.4f, cv=%.4f±%.4f, loss=%.4f (%.1fs)",
            metrics.accuracy, metrics.f1, metrics.cv_mean, metrics.cv_std,
            metrics.log_loss_value, metrics.training_time_seconds,
        )

        return metrics

    def predict(self, text: str) -> EnsemblePrediction:
        if not self._is_loaded or self._ensemble is None:
            return self._heuristic_predict(text)

        try:
            X = self._preprocessor.get_combined_features([text])
            if X is None:
                return self._heuristic_predict(text)

            X_scaled = np.ascontiguousarray(
                self._scaler.transform(X), dtype=np.float64
            ) if self._scaler else np.ascontiguousarray(X, dtype=np.float64)

            proba = self._ensemble.predict_proba(X_scaled)[0]
            confidence = float(proba[1]) if len(proba) > 1 else float(proba[0])
            is_scam = confidence >= 0.5

            per_model = {}
            for name, model in self._ensemble.named_estimators_.items():
                try:
                    p = model.predict_proba(X_scaled)[0]
                    per_model[name] = float(p[1]) if len(p) > 1 else float(p[0])
                except Exception:
                    per_model[name] = 0.0

            feature_imp = {}
            try:
                rf_model = self._ensemble.named_estimators_.get("rf")
                if rf_model and hasattr(rf_model, "feature_importances_"):
                    importances = rf_model.feature_importances_
                    for i, imp in enumerate(importances):
                        fname = self._feature_names[i] if i < len(self._feature_names) else f"f{i}"
                        if imp > 0.01:
                            feature_imp[fname] = round(float(imp), 4)
                    feature_imp = dict(
                        sorted(feature_imp.items(), key=lambda x: x[1], reverse=True)[:15]
                    )
            except Exception:
                pass

            return EnsemblePrediction(
                is_scam=is_scam,
                confidence=round(confidence, 4),
                per_model_scores=per_model,
                feature_importance=feature_imp,
                model_used="ensemble",
            )
        except Exception as e:
            logger.warning("Ensemble prediction failed, using heuristic: %s", e)
            return self._heuristic_predict(text)

    def predict_batch(self, texts: List[str]) -> List[EnsemblePrediction]:
        return [self.predict(t) for t in texts]

    @property
    def is_trained(self) -> bool:
        return self._is_loaded and self._ensemble is not None

    def add_training_sample(
        self,
        text: str,
        label: int,
        scam_category: str = "unknown",
        metadata: Optional[Dict] = None,
    ) -> None:
        TRAINING_DATA_PATH.parent.mkdir(parents=True, exist_ok=True)

        # Dedup guard: skip if an identical text already exists
        existing_texts: set[str] = set()
        if TRAINING_DATA_PATH.exists():
            with open(TRAINING_DATA_PATH, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        entry = json.loads(line)
                        t = entry.get("text") or entry.get("message", "")
                        if t:
                            existing_texts.add(t)
                    except json.JSONDecodeError:
                        continue

        if text in existing_texts:
            logger.info("Skipping duplicate training sample: %.80s…", text)
            return

        sample = {
            "text": text,
            "label": label,
            "scam_category": scam_category,
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        }
        if metadata:
            sample.update(metadata)

        with open(TRAINING_DATA_PATH, "a", encoding="utf-8") as f:
            f.write(json.dumps(sample, ensure_ascii=False) + "\n")

    def _build_estimators(self) -> list:
        estimators = [
            ("rf", RandomForestClassifier(
                n_estimators=150,
                max_depth=8,
                min_samples_split=10,
                min_samples_leaf=5,
                max_features="sqrt",
                class_weight="balanced",
                random_state=42,
                n_jobs=-1,
            )),
            ("gb", GradientBoostingClassifier(
                n_estimators=120,
                max_depth=4,
                learning_rate=0.05,
                subsample=0.75,
                min_samples_split=10,
                min_samples_leaf=5,
                max_features="sqrt",
                random_state=42,
            )),
            ("lr", LogisticRegression(
                max_iter=1000,
                C=0.5,
                l1_ratio=0,
                class_weight="balanced",
                solver="lbfgs",
                random_state=42,
            )),
        ]

        if HAS_LIGHTGBM:
            estimators.append(("lgbm", lgb.LGBMClassifier(
                n_estimators=150,
                max_depth=5,
                learning_rate=0.05,
                subsample=0.7,
                colsample_bytree=0.7,
                reg_alpha=0.5,
                reg_lambda=2.0,
                min_child_samples=10,
                is_unbalance=True,
                random_state=42,
                verbose=-1,
            )))

        if HAS_XGBOOST:
            estimators.append(("xgb", xgb.XGBClassifier(
                n_estimators=150,
                max_depth=5,
                learning_rate=0.05,
                subsample=0.7,
                colsample_bytree=0.7,
                reg_alpha=0.5,
                reg_lambda=2.0,
                min_child_weight=5,
                scale_pos_weight=1.0,
                random_state=42,
                eval_metric="logloss",
                verbosity=0,
            )))

        return estimators

    def _heuristic_predict(self, text: str) -> EnsemblePrediction:
        features = self._preprocessor.extract_features(text)

        score = 0.0
        score += min(features.urgency_keywords * 0.12, 0.3)
        score += min(features.threat_indicators * 0.15, 0.3)
        score += min(features.fake_fee_mentions * 0.10, 0.25)
        score += min(features.authority_claims * 0.12, 0.25)
        score += min(features.emotional_manipulation * 0.06, 0.15)
        score += min(features.isolation_attempts * 0.10, 0.20)

        if features.url_count > 0:
            score += 0.15
        if features.currency_mention_count > 0:
            score += 0.05
        if features.phone_count > 0 and features.urgency_keywords > 0:
            score += 0.10
        if features.uppercase_ratio > 0.3:
            score += 0.08

        cat_scores = features.category_keyword_scores
        max_cat_score = max(cat_scores.values()) if cat_scores else 0
        score += min(max_cat_score * 0.08, 0.25)

        if features.total_scam_indicators >= 5:
            score += 0.15
        elif features.total_scam_indicators >= 3:
            score += 0.08

        score = min(score, 1.0)

        return EnsemblePrediction(
            is_scam=score >= 0.5,
            confidence=round(score, 4),
            per_model_scores={"heuristic": round(score, 4)},
            feature_importance={
                "urgency_keywords": features.urgency_keywords,
                "threat_indicators": features.threat_indicators,
                "authority_claims": features.authority_claims,
                "total_scam_indicators": features.total_scam_indicators,
            },
            model_used="heuristic_fallback",
        )

    def _load_training_data(self, path: str) -> Tuple[List[str], List[int]]:
        texts, labels = [], []
        data_path = Path(path)
        if not data_path.exists():
            logger.warning("Training data not found: %s", path)
            return texts, labels

        with open(data_path, "r", encoding="utf-8") as f:
            for line_num, line in enumerate(f, 1):
                line = line.strip()
                if not line:
                    continue
                try:
                    sample = json.loads(line)
                    text = sample.get("text", "").strip()
                    label = int(sample.get("label", 0))
                    if text and label in (0, 1):
                        texts.append(text)
                        labels.append(label)
                except (json.JSONDecodeError, ValueError) as e:
                    logger.warning("Skipping malformed line %d: %s", line_num, e)

        logger.info("Loaded %d training samples from %s", len(texts), path)
        return texts, labels

    def _load_model(self):
        if ENSEMBLE_PATH.exists() and HAS_SKLEARN:
            try:
                saved = joblib.load(ENSEMBLE_PATH)
                self._ensemble = saved.get("ensemble")
                self._feature_names = saved.get("feature_names", [])
                self._is_loaded = self._ensemble is not None

                if SCALER_PATH.exists():
                    self._scaler = joblib.load(SCALER_PATH)

                if self._is_loaded:
                    logger.info("Loaded ensemble model from %s", ENSEMBLE_PATH)
            except Exception as e:
                logger.warning("Failed to load ensemble model: %s", e)

    def _save_model(self):
        if self._ensemble is None:
            return
        try:
            MODELS_DIR.mkdir(parents=True, exist_ok=True)
            joblib.dump(
                {"ensemble": self._ensemble, "feature_names": self._feature_names},
                ENSEMBLE_PATH,
            )
            if self._scaler is not None:
                joblib.dump(self._scaler, SCALER_PATH)
            logger.info("Saved ensemble model to %s", ENSEMBLE_PATH)
        except Exception as e:
            logger.warning("Failed to save ensemble model: %s", e)

    def _save_metrics(self, metrics: TrainingMetrics):
        try:
            MODELS_DIR.mkdir(parents=True, exist_ok=True)
            with open(METRICS_PATH, "w", encoding="utf-8") as f:
                json.dump(metrics.to_dict(), f, indent=2)
            logger.info("Saved training metrics to %s", METRICS_PATH)
        except Exception as e:
            logger.warning("Failed to save metrics: %s", e)


_pipeline: Optional[TrainingPipeline] = None


def get_training_pipeline() -> TrainingPipeline:
    global _pipeline
    if _pipeline is None:
        _pipeline = TrainingPipeline()
    return _pipeline
