import argparse
import importlib.util
import json
import os
import subprocess
import sys


DEFAULT_MODEL = "mlx-community/Qwen2.5-Coder-7B-Instruct-4bit"


def normalize_messages(raw_messages: list[dict]) -> list[dict]:
    """Normalize orchestrator messages into clean {role, content} chat turns for mlx-lm."""
    normalized = []
    for msg in raw_messages:
        role = msg.get("role", "user")
        content = msg.get("content") or ""
        if role == "assistant" and not content and msg.get("tool_calls"):
            calls = []
            for tc in msg["tool_calls"]:
                fn = tc.get("function", {})
                args = fn.get("arguments", "{}")
                if isinstance(args, str):
                    try:
                        args = json.loads(args)
                    except json.JSONDecodeError:
                        pass
                calls.append(json.dumps({"name": fn.get("name", ""), "arguments": args}, ensure_ascii=False))
            content = "\n".join(calls)
        if not content:
            continue
        normalized.append({"role": role, "content": content})
    return normalized


def export_mlx_dataset(
    input_path: str,
    out_dir: str,
    val_split: float = 0.1,
) -> tuple[int, int]:
    """Convert trajectories.jsonl into mlx-lm train.jsonl and valid.jsonl. Returns (train_count, valid_count)."""
    if not os.path.isfile(input_path):
        raise FileNotFoundError(f"Trajectories file not found: {input_path}")

    samples = []
    with open(input_path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            record = json.loads(line)
            msgs = normalize_messages(record.get("messages", []))
            if len(msgs) >= 2:
                samples.append({"messages": msgs})

    if not samples:
        raise ValueError(f"No valid trajectories found in {input_path}")

    os.makedirs(out_dir, exist_ok=True)
    if len(samples) == 1:
        train_samples = samples
        valid_samples = samples
    else:
        val_count = max(1, int(len(samples) * val_split))
        if val_count >= len(samples):
            val_count = 1
        train_samples = samples[:-val_count]
        valid_samples = samples[-val_count:]

    train_path = os.path.join(out_dir, "train.jsonl")
    valid_path = os.path.join(out_dir, "valid.jsonl")
    for path, rows in ((train_path, train_samples), (valid_path, valid_samples)):
        with open(path, "w", encoding="utf-8") as f:
            for row in rows:
                f.write(json.dumps(row, ensure_ascii=False) + "\n")

    return len(train_samples), len(valid_samples)


def main():
    here = os.path.dirname(os.path.abspath(__file__))
    parser = argparse.ArgumentParser(description="Layer 4 RLVR: Export trajectories.jsonl and run Apple MLX LoRA")
    parser.add_argument("--input", default=os.path.join(here, "trajectories.jsonl"), help="Input trajectories.jsonl")
    parser.add_argument("--out-dir", default=os.path.join(here, "mlx_data"), help="Output directory for train/valid.jsonl")
    parser.add_argument("--val-split", type=float, default=0.1, help="Validation split fraction (default: 0.1)")
    parser.add_argument("--model", default=DEFAULT_MODEL, help=f"HuggingFace/MLX model (default: {DEFAULT_MODEL})")
    parser.add_argument("--iters", type=int, default=100, help="LoRA training iterations (default: 100)")
    parser.add_argument("--adapter-path", default=os.path.join(here, "adapters"), help="Output LoRA adapter directory")
    parser.add_argument("--train", action="store_true", help="Invoke python -m mlx_lm.lora after exporting")
    args = parser.parse_args()

    n_train, n_valid = export_mlx_dataset(args.input, args.out_dir, val_split=args.val_split)
    print(f"[RLVR] Exported {n_train} train + {n_valid} valid samples to {args.out_dir}", flush=True)

    cmd = [
        sys.executable,
        "-m",
        "mlx_lm.lora",
        "--model",
        args.model,
        "--train",
        "--data",
        args.out_dir,
        "--iters",
        str(args.iters),
        "--adapter-path",
        args.adapter_path,
    ]
    print(f"[RLVR] MLX LoRA command:\n  {' '.join(cmd)}", flush=True)

    if args.train:
        if importlib.util.find_spec("mlx_lm") is None:
            print("ERROR: mlx-lm is not installed in this environment. Install with: pip install mlx-lm", file=sys.stderr)
            sys.exit(1)
        subprocess.run(cmd, check=True)


if __name__ == "__main__":
    main()
