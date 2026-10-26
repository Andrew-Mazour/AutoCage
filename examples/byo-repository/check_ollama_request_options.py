#!/usr/bin/env python3
"""No-inference regression for the pinned LiteLLM Ollama request serializer."""

from __future__ import annotations

import tempfile
from pathlib import Path

from aider import models as aider_models
from litellm.llms.ollama.chat.transformation import OllamaChatConfig

from local_aider_runner import model_settings_content


def main() -> int:
    temperature = 0.0
    seed = 74031
    context_length = 8192
    with tempfile.TemporaryDirectory(prefix="autocage-model-settings-") as temporary:
        settings_path = Path(temporary) / "settings.yml"
        settings_path.write_text(model_settings_content(seed), encoding="utf-8")
        loaded = aider_models.register_models([str(settings_path)])
        if loaded != [str(settings_path)]:
            raise SystemExit("Aider did not load the generated model-settings file")
        model = next(
            (item for item in aider_models.MODEL_SETTINGS if item.name == "ollama_chat/qwen2.5-coder:3b"),
            None,
        )
        effective = {
            "temperature": model.use_temperature if model is not None else None,
            "seed": model.extra_params.get("seed") if model and model.extra_params else None,
            "num_ctx": model.extra_params.get("num_ctx") if model and model.extra_params else None,
            "edit_format": model.edit_format if model is not None else None,
        }
        expected_settings = {
            "temperature": temperature, "seed": seed,
            "num_ctx": context_length, "edit_format": "whole",
        }
        if effective != expected_settings:
            raise SystemExit(f"Aider effective model settings mismatch: {effective!r}")
    provider = OllamaChatConfig()
    options = provider.map_openai_params(
        {"temperature": temperature, "seed": seed},
        {"num_ctx": context_length},
        model="qwen2.5-coder:3b",
        drop_params=False,
    )
    payload = provider.transform_request(
        model="qwen2.5-coder:3b",
        messages=[{"role": "user", "content": "synthetic options probe"}],
        optional_params=dict(options),
        litellm_params={},
        headers={},
    )
    expected = {"temperature": temperature, "seed": seed, "num_ctx": context_length}
    actual = {key: payload["options"].get(key) for key in expected}
    if actual != expected:
        raise SystemExit(f"Ollama request options mismatch: {actual!r}")
    print(f"PASS Aider loaded effective settings: {effective}")
    print(f"PASS Ollama /api/chat options payload: {actual}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
