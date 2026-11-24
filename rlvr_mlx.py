import argparse
import importlib.util
import json
import os
import shutil
import subprocess
import sys

import mcp_server


DEFAULT_MODEL = "mlx-community/Qwen2.5-Coder-7B-Instruct-8bit"

MODELFILE_TEMPLATE = '''FROM {gguf_path}
TEMPLATE """{{- if .Suffix }}<|fim_prefix|>{{ .Prompt }}<|fim_suffix|>{{ .Suffix }}<|fim_middle|>
{{- else if .Messages }}
{{- if or .System .Tools }}<|im_start|>system
{{- if .System }}
{{ .System }}
{{- end }}
{{- if .Tools }}

# Tools

You may call one or more functions to assist with the user query.

You are provided with function signatures within <tools></tools> XML tags:
<tools>
{{- range .Tools }}
{"type": "function", "function": {{ .Function }}}
{{- end }}
</tools>

For each function call, return a json object with function name and arguments within <tool_call></tool_call> with NO other text. Do not include any backticks or ```json.
<tool_call>
{"name": <function-name>, "arguments": <args-json-object>}
</tool_call>
{{- end }}<|im_end|>
{{ end }}
{{- range $i, $_ := .Messages }}
{{- $last := eq (len (slice $.Messages $i)) 1 -}}
{{- if eq .Role "user" }}<|im_start|>user
{{ .Content }}<|im_end|>
{{ else if eq .Role "assistant" }}<|im_start|>assistant
{{ if .Content }}{{ .Content }}
{{- else if .ToolCalls }}<tool_call>
{{ range .ToolCalls }}{"name": "{{ .Function.Name }}", "arguments": {{ .Function.Arguments }}}
{{ end }}</tool_call>
{{- end }}{{ if not $last }}<|im_end|>
{{ end }}
{{- else if eq .Role "tool" }}<|im_start|>user
<tool_response>
{{ .Content }}
</tool_response><|im_end|>
{{ end }}
{{- if and (ne .Role "assistant") $last }}<|im_start|>assistant
{{ end }}
{{- end }}
{{- else }}
{{- if .System }}<|im_start|>system
{{ .System }}<|im_end|>
{{ end }}{{ if .Prompt }}<|im_start|>user
{{ .Prompt }}<|im_end|>
{{ end }}<|im_start|>assistant
{{ end }}{{ .Response }}{{ if .Response }}<|im_end|>{{ end }}"""
SYSTEM You are Qwen, created by Alibaba Cloud. You are a helpful assistant.
PARAMETER stop "<|im_start|>"
PARAMETER stop "<|im_end|>"
PARAMETER stop "<|endoftext|>"
PARAMETER num_ctx 8192
'''


def get_openai_tools() -> list[dict]:
    """Return MCP tool definitions in OpenAI function-calling schema matching orchestrator.py."""
    return [
        {
            "type": "function",
            "function": {
                "name": t["name"],
                "description": t["description"],
                "parameters": t["inputSchema"],
            },
        }
        for t in mcp_server.TOOLS
    ]


def _is_fallback_tool_json(content: str) -> bool:
    lines = [l.strip() for l in content.strip().splitlines() if l.strip()]
    return bool(lines) and all(
        l.startswith("{") and '"name"' in l and '"arguments"' in l for l in lines
    )


def normalize_messages(raw_messages: list[dict]) -> list[dict]:
    """Preserve structured tool_calls (with dict arguments) for Qwen chat_template.jinja parity."""
    normalized = []
    for msg in raw_messages:
        role = msg.get("role", "user")
        content = msg.get("content") or ""
        raw_calls = msg.get("tool_calls") or []

        if role == "assistant" and raw_calls:
            norm_calls = []
            for tc in raw_calls:
                fn = tc.get("function", {})
                args = fn.get("arguments", {})
                if isinstance(args, str):
                    try:
                        args = json.loads(args)
                    except json.JSONDecodeError:
                        args = {}
                if not isinstance(args, dict):
                    args = {}
                norm_calls.append(
                    {
                        "type": "function",
                        "function": {
                            "name": fn.get("name", ""),
                            "arguments": args,
                        },
                    }
                )
            # Strip raw fallback JSON from content so chat_template emits clean <tool_call> blocks only
            clean_content = "" if _is_fallback_tool_json(content) else content
            normalized.append(
                {
                    "role": "assistant",
                    "content": clean_content,
                    "tool_calls": norm_calls,
                }
            )
            continue

        if not content:
            continue
        entry = {"role": role, "content": content}
        if role == "tool" and msg.get("tool_call_id"):
            entry["tool_call_id"] = msg["tool_call_id"]
        normalized.append(entry)
    return normalized


def export_mlx_dataset(
    input_path: str,
    out_dir: str,
    val_split: float = 0.1,
    include_tools: bool = True,
    drop_no_diff: bool = True,
) -> tuple[int, int]:
    """Convert trajectories.jsonl into mlx-lm train.jsonl and valid.jsonl. Returns (train_count, valid_count)."""
    if not os.path.isfile(input_path):
        raise FileNotFoundError(f"Trajectories file not found: {input_path}")

    tools = get_openai_tools() if include_tools else None
    samples = []
    with open(input_path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            record = json.loads(line)
            if drop_no_diff and "git_diff" in record:
                diff_txt = record["git_diff"]
                if diff_txt == "No changes." or "@@ " not in diff_txt:
                    continue
            msgs = normalize_messages(record.get("messages", []))
            if len(msgs) >= 2:
                sample = {"messages": msgs}
                if tools is not None:
                    sample["tools"] = tools
                samples.append(sample)

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


def render_modelfile(gguf_path: str = "./custom-qwen-7b.gguf") -> str:
    """Render an Ollama Modelfile with exact qwen2.5-coder:7b <tool_call> template parity."""
    return MODELFILE_TEMPLATE.replace("{gguf_path}", gguf_path)


def unload_ollama_models() -> None:
    """Free Unified Memory by unloading any cached Ollama models before MLX training."""
    if not shutil.which("ollama"):
        return
    try:
        res = subprocess.run(["ollama", "ps"], capture_output=True, text=True, timeout=5)
        for line in res.stdout.splitlines()[1:]:
            parts = line.split()
            if parts:
                subprocess.run(["ollama", "stop", parts[0]], capture_output=True, timeout=5)
                print(f"[RLVR] Unloaded Ollama model '{parts[0]}' to free Unified Memory", flush=True)
    except Exception:
        pass


def verify_adapter_finite(adapter_path: str) -> None:
    """Fail fast if any trained LoRA adapter tensor contains NaN or Inf."""
    weights_file = os.path.join(adapter_path, "adapters.safetensors")
    if not os.path.isfile(weights_file):
        raise FileNotFoundError(f"Adapter weights not found: {weights_file}")
    import mlx.core as mx

    weights = mx.load(weights_file)
    bad = [
        k for k, v in weights.items()
        if mx.any(mx.isnan(v)).item() or mx.any(mx.isinf(v)).item()
    ]
    if bad:
        raise RuntimeError(f"Adapter contains non-finite weights in {len(bad)}/{len(weights)} tensors (e.g. {bad[0]})")


def write_lora_config(out_dir: str, iters: int) -> str:
    """Write a bfloat16-safe AdamW LoRA config YAML to prevent gradient/eps NaN instability."""
    cfg_path = os.path.join(out_dir, "lora_config.yaml")
    steps_per_eval = max(5, iters // 2)
    cfg = (
        "optimizer: adamw\n"
        "optimizer_config:\n"
        "  adamw:\n"
        "    eps: 1.0e-5\n"
        "    weight_decay: 0.01\n"
        "    bias_correction: true\n"
        "grad_accumulation_steps: 2\n"
        "steps_per_report: 5\n"
        f"steps_per_eval: {steps_per_eval}\n"
    )
    with open(cfg_path, "w", encoding="utf-8") as f:
        f.write(cfg)
    return cfg_path


def main():
    here = os.path.dirname(os.path.abspath(__file__))
    parser = argparse.ArgumentParser(description="Layer 4 RLVR: Export trajectories.jsonl and run Apple MLX LoRA")
    parser.add_argument("--input", default=os.path.join(here, "trajectories.jsonl"), help="Input trajectories.jsonl")
    parser.add_argument("--out-dir", default=os.path.join(here, "mlx_data"), help="Output directory for train/valid.jsonl")
    parser.add_argument("--val-split", type=float, default=0.1, help="Validation split fraction (default: 0.1)")
    parser.add_argument("--include-legacy-no-diff", action="store_true", help="Keep legacy rows with git_diff == 'No changes.'")
    parser.add_argument("--model", default=DEFAULT_MODEL, help=f"HuggingFace/MLX model (default: {DEFAULT_MODEL})")
    parser.add_argument("--iters", type=int, default=30, help="LoRA training iterations (default: 30)")
    parser.add_argument("--learning-rate", type=float, default=2e-6, help="LoRA learning rate (default: 2e-6)")
    parser.add_argument("--max-seq-length", type=int, default=8192, help="Max sequence length without trajectory truncation (default: 8192)")
    parser.add_argument("--batch-size", type=int, default=2, help="Max LoRA batch size (auto-clamped to dataset size)")
    parser.add_argument("--adapter-path", default=os.path.join(here, "adapters"), help="Output LoRA adapter directory")
    parser.add_argument("--fused-path", default=os.path.join(here, "fused_model"), help="Output directory for fused HF model")
    parser.add_argument("--train", action="store_true", help="Invoke python -m mlx_lm lora after exporting")
    parser.add_argument("--fuse", action="store_true", help="Fuse LoRA adapter into base model (--dequantize for GGUF export)")
    parser.add_argument("--export-gguf", default=None, metavar="OUT_GGUF", help="Convert fused model to GGUF via llama.cpp")
    parser.add_argument("--outtype", default="q8_0", choices=["f32", "f16", "bf16", "q8_0"], help="GGUF export tensor type before quantization (default: q8_0; use f16 with --quantize)")
    parser.add_argument("--quantize", default=None, metavar="TYPE", help="Quantize exported GGUF via llama-quantize (e.g. Q4_K_M)")
    parser.add_argument(
        "--llama-quantize-bin",
        default=None,
        help="Path to llama-quantize executable (auto-searches PATH and saved_llama_build/bin/llama-quantize)",
    )
    parser.add_argument("--write-modelfile", default=None, metavar="PATH", help="Write parity-audited Modelfile.custom")
    parser.add_argument(
        "--llama-cpp-dir",
        default=os.path.abspath(os.path.join(here, "..", "android-ndk-agent", "app", "src", "main", "cpp", "third_party", "llama.cpp")),
        help="Path to llama.cpp checkout containing convert_hf_to_gguf.py",
    )
    args = parser.parse_args()

    n_train, n_valid = export_mlx_dataset(
        args.input,
        args.out_dir,
        val_split=args.val_split,
        drop_no_diff=not args.include_legacy_no_diff,
    )
    effective_batch = max(1, min(args.batch_size, n_train, n_valid))
    cfg_path = write_lora_config(args.out_dir, args.iters)
    print(f"[RLVR] Exported {n_train} train + {n_valid} valid samples to {args.out_dir}", flush=True)

    cmd = [
        sys.executable,
        "-m",
        "mlx_lm",
        "lora",
        "--model",
        args.model,
        "--train",
        "--config",
        cfg_path,
        "--data",
        args.out_dir,
        "--batch-size",
        str(effective_batch),
        "--iters",
        str(args.iters),
        "--learning-rate",
        str(args.learning_rate),
        "--max-seq-length",
        str(args.max_seq_length),
        "--grad-checkpoint",
        "--adapter-path",
        args.adapter_path,
    ]
    print(f"[RLVR] MLX LoRA command:\n  {' '.join(cmd)}", flush=True)

    if args.train:
        if importlib.util.find_spec("mlx_lm") is None:
            print("ERROR: mlx-lm is not installed in this environment. Install with: pip install mlx-lm", file=sys.stderr)
            sys.exit(1)
        unload_ollama_models()
        subprocess.run(cmd, check=True)
        verify_adapter_finite(args.adapter_path)
        print("[RLVR] Verified LoRA adapter weights are finite (0 NaN/Inf tensors)", flush=True)

    if args.fuse:
        if importlib.util.find_spec("mlx_lm") is None:
            print("ERROR: mlx-lm is not installed in this environment. Install with: pip install mlx-lm", file=sys.stderr)
            sys.exit(1)
        verify_adapter_finite(args.adapter_path)
        fuse_cmd = [
            sys.executable,
            "-m",
            "mlx_lm",
            "fuse",
            "--model",
            args.model,
            "--adapter-path",
            args.adapter_path,
            "--save-path",
            args.fused_path,
            "--dequantize",
        ]
        print(f"[RLVR] Fusing adapter:\n  {' '.join(fuse_cmd)}", flush=True)
        subprocess.run(fuse_cmd, check=True)

    if args.export_gguf:
        converter = os.path.join(args.llama_cpp_dir, "convert_hf_to_gguf.py")
        if not os.path.isfile(converter):
            print(f"ERROR: convert_hf_to_gguf.py not found at {converter}", file=sys.stderr)
            sys.exit(1)
        outtype = "f16" if args.quantize and args.outtype == "q8_0" else args.outtype
        raw_gguf = args.export_gguf + ".f16.tmp.gguf" if args.quantize else args.export_gguf
        gguf_cmd = [
            sys.executable,
            converter,
            args.fused_path,
            "--outfile",
            raw_gguf,
            "--outtype",
            outtype,
        ]
        print(f"[RLVR] Exporting GGUF:\n  {' '.join(gguf_cmd)}", flush=True)
        subprocess.run(gguf_cmd, check=True)

        if args.quantize:
            qbin = args.llama_quantize_bin or shutil.which("llama-quantize")
            if not qbin:
                cand = os.path.join(here, "saved_llama_build", "bin", "llama-quantize")
                if os.path.isfile(cand) and os.access(cand, os.X_OK):
                    qbin = cand
            if not qbin:
                print("ERROR: llama-quantize not found on PATH or in saved_llama_build/bin/llama-quantize", file=sys.stderr)
                sys.exit(1)
            q_cmd = [qbin, raw_gguf, args.export_gguf, args.quantize]
            print(f"[RLVR] Quantizing GGUF ({args.quantize}):\n  {' '.join(q_cmd)}", flush=True)
            subprocess.run(q_cmd, check=True)
            if os.path.isfile(raw_gguf) and raw_gguf != args.export_gguf:
                os.remove(raw_gguf)

    if args.write_modelfile:
        gguf_target = args.export_gguf or "./custom-qwen-7b.gguf"
        with open(args.write_modelfile, "w", encoding="utf-8") as f:
            f.write(render_modelfile(gguf_target))
        print(f"[RLVR] Wrote parity-audited Modelfile -> {args.write_modelfile}", flush=True)


if __name__ == "__main__":
    main()
