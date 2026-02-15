import sys, asyncio
sys.path.insert(0, '/app')
from src.scam_detector.ml_engine import MLScamDetector, FeatureExtractor

msg = "WON ! You have won some lakh ! Pleaase share your bank account number to proceed !!."
features = FeatureExtractor.extract(msg)
print("=== Feature Extraction ===")
for name, val in zip(features.feature_names, features.features):
    if val > 0:
        print(f"  {name}: {val:.4f}")

pred = asyncio.run(MLScamDetector.predict(msg))
print(f"\nML: is_scam={pred.is_scam}, confidence={pred.confidence}")

from src.scam_detector.classifier import calculate_keyword_score, calculate_intent_score, calculate_pattern_score
kw_score, kw_matched = asyncio.run(calculate_keyword_score(msg))
intent = asyncio.run(calculate_intent_score(msg))
pattern = asyncio.run(calculate_pattern_score(msg))
print(f"\nKeyword score: {kw_score}, matched: {kw_matched}")
print(f"Intent score: {intent}")
print(f"Pattern score: {pattern}")

from src.scam_detector.hybrid_engine import HybridScamDetectionEngine
result = asyncio.run(HybridScamDetectionEngine.detect(msg))
print(f"\nHybrid: is_scam={result.is_scam}, confidence={result.confidence}")
print("Breakdown:")
for k, v in result.breakdown.items():
    print(f"  {k}: {v:.4f}")
print(f"Hard indicators: {result.has_hard_indicators}")
