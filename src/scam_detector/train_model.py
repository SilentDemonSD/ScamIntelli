import argparse
import json
from pathlib import Path


def main():
    parser = argparse.ArgumentParser(description="ScamIntelli Model Training")
    parser.add_argument(
        "--generate", action="store_true",
        help="Generate synthetic training data before training"
    )
    parser.add_argument(
        "--samples", type=int, default=80,
        help="Samples per scam category when generating data (default: 80)"
    )
    parser.add_argument(
        "--data", type=str, default="models/training_data.jsonl",
        help="Path to training data JSONL file"
    )
    parser.add_argument(
        "--evaluate", type=str, default=None,
        help="Evaluate a single message instead of training"
    )
    parser.add_argument(
        "--status", action="store_true",
        help="Show model status and metrics"
    )

    args = parser.parse_args()

    if args.status:
        _show_status()
        return

    if args.evaluate:
        _evaluate_message(args.evaluate)
        return

    # Generate data if requested or if no data exists
    data_path = Path(args.data)
    if args.generate or not data_path.exists():
        print(f"Generating synthetic training data ({args.samples} samples per category)...")
        from src.scam_detector.data_generator import generate_training_data
        n = generate_training_data(samples_per_category=args.samples, output_path=args.data)
        print(f"Generated {n} training samples -> {args.data}")

    # Train
    print("\nTraining ensemble model...")
    from src.scam_detector.training_pipeline import TrainingPipeline
    pipeline = TrainingPipeline()
    metrics = pipeline.train(data_path=args.data)

    print("\n" + "=" * 60)
    print("TRAINING RESULTS")
    print("=" * 60)
    print(f"  Accuracy:  {metrics.accuracy:.4f}")
    print(f"  Precision: {metrics.precision:.4f}")
    print(f"  Recall:    {metrics.recall:.4f}")
    print(f"  F1 Score:  {metrics.f1:.4f}")
    print(f"  Log Loss:  {metrics.log_loss_value:.4f}")
    print(f"  CV Mean:   {metrics.cv_mean:.4f} +/- {metrics.cv_std:.4f}")
    print(f"  Samples:   {metrics.n_samples}")
    print(f"  Features:  {metrics.n_features}")
    print(f"  Time:      {metrics.training_time_seconds:.1f}s")
    print()
    print("Per-model accuracy:")
    for name, acc in sorted(metrics.per_model.items(), key=lambda x: x[1], reverse=True):
        print(f"  {name:8s}: {acc:.4f}")
    print("=" * 60)


def _show_status():
    from src.scam_detector.training_pipeline import get_training_pipeline
    pipeline = get_training_pipeline()

    print(f"Model loaded: {pipeline.is_trained}")

    metrics_path = Path("models/training_metrics.json")
    if metrics_path.exists():
        with open(metrics_path) as f:
            metrics = json.load(f)
        print(f"Last trained: {metrics.get('timestamp', 'unknown')}")
        print(f"Accuracy:     {metrics.get('accuracy', 0):.4f}")
        print(f"F1 Score:     {metrics.get('f1', 0):.4f}")
        print(f"Samples:      {metrics.get('n_samples', 0)}")
    else:
        print("No training metrics found.")


def _evaluate_message(text: str):
    from src.scam_detector.training_pipeline import get_training_pipeline
    pipeline = get_training_pipeline()
    pred = pipeline.predict(text)

    print(f"Text:       {text[:100]}...")
    print(f"Is Scam:    {pred.is_scam}")
    print(f"Confidence: {pred.confidence:.4f}")
    print(f"Model:      {pred.model_used}")
    print(f"Per-model:  {json.dumps(pred.per_model_scores, indent=2)}")
    if pred.feature_importance:
        print(f"Top features: {json.dumps(pred.feature_importance, indent=2)}")


if __name__ == "__main__":
    main()
