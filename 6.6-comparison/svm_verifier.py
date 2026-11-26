"""Build the existing offline SVM output verifier for the current host."""

import argparse
from contextlib import contextmanager
import os
from pathlib import Path
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]


def verifier_from_cli():
    parser = argparse.ArgumentParser(description="Independently verify archived SVM measurements.")
    parser.add_argument("--verifier", type=Path,
                        help="existing verifier for this host; otherwise build from Go source")
    return prepare_verifier(parser.parse_args().verifier)


@contextmanager
def prepare_verifier(path=None):
    if path is not None:
        path = path.expanduser().resolve()
        if not path.is_file() or not os.access(path, os.X_OK):
            raise ValueError(f"verifier is not an executable file: {path}")
        yield path
        return
    env = os.environ.copy()
    env.update(GOTOOLCHAIN="local", GOWORK="off", GOFLAGS="", CGO_ENABLED="0")
    # Do not inherit a cross-compilation target from the shell or Go settings.
    host = subprocess.check_output(["go", "env", "GOHOSTOS", "GOHOSTARCH"],
                                   cwd=ROOT, env=env, text=True).split()
    env.update(GOOS=host[0], GOARCH=host[1])
    with tempfile.TemporaryDirectory(prefix="cdpt-svm-verifier-") as directory:
        binary = Path(directory) / ("svmpilotverify.exe" if host[0] == "windows" else "svmpilotverify")
        subprocess.run(["go", "build", "-mod=readonly", "-trimpath", "-o", str(binary),
                        "./6.6-comparison/verify"], cwd=ROOT, env=env, check=True)
        yield binary
