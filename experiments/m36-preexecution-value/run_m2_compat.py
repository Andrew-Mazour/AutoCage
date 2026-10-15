#!/usr/bin/env python3
"""Run the frozen M2 corpus through the current tune CLI without editing M2."""
from __future__ import annotations

import argparse
import importlib.util
import sys
from pathlib import Path


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--controller", type=Path, required=True)
    parser.add_argument("--autocage", type=Path, required=True)
    parser.add_argument("--results", type=Path, required=True)
    args = parser.parse_args()
    controller = args.controller.resolve()
    binary = args.autocage.resolve()
    results = args.results.resolve()
    sys.path.insert(0, str(controller.parent))
    spec = importlib.util.spec_from_file_location("frozen_m2_controller", controller)
    if spec is None or spec.loader is None:
        raise RuntimeError("cannot load frozen M2 controller")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)

    # The frozen controller supplies the exact same agent and verifier strings
    # used for its broad baseline. Preserve them rather than reconstructing a
    # second variant in this compatibility layer.
    original_launch_tune = module.launch_tune

    def launch_tune_compat(
        binary_path: Path,
        workspace: Path,
        run_dir: Path,
        agent: str,
        verifier: str,
        strategy: str,
        max_replays: int,
    ):
        return original_launch_tune(
            binary_path, workspace, run_dir, agent, verifier, strategy, max_replays
        )

    module.launch_tune = launch_tune_compat
    sys.argv = [str(controller), "--autocage", str(binary), "--results", str(results)]
    return int(module.main())


if __name__ == "__main__":
    raise SystemExit(main())
