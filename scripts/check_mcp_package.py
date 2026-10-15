"""Build/install optional wheels and test their real entry point outside sources."""

import os
from pathlib import Path
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]


def run(*args, **kwargs):
    subprocess.run(args, check=True, cwd=kwargs.pop("cwd", ROOT), **kwargs)


with tempfile.TemporaryDirectory(prefix="hudson-mcp-package-") as directory:
    stage = Path(directory)
    for package in ("python", "mcp"):
        run(
            sys.executable,
            "-m",
            "build",
            "--wheel",
            "--no-isolation",
            "--outdir",
            str(stage),
            str(ROOT / "sdk" / package),
        )
    installed = stage / "installed"
    run(
        sys.executable,
        "-m",
        "pip",
        "install",
        "--no-deps",
        "--no-index",
        "--target",
        str(installed),
        *map(str, stage.glob("*.whl")),
    )
    env = {
        **os.environ,
        "PYTHONPATH": str(installed) + os.pathsep + str(ROOT / "sdk/mcp/tests"),
        "PYTHONDONTWRITEBYTECODE": "1",
    }
    run(sys.executable, "-m", "unittest", "test_stdio", cwd=stage, env=env)
    run(
        sys.executable,
        "-c",
        "import hudsonbox_mcp,sys; assert hudsonbox_mcp.__file__.startswith(sys.argv[1])",
        str(installed),
        cwd=stage,
        env=env,
    )
print("Optional MCP wheel and installed stdio/HTTPS interoperability passed.")
