"""Build a reviewable ZIP with an explicit allowlist: no credentials or model cache."""

import argparse
import hashlib
from pathlib import Path
import stat
import zipfile

ROOT = Path(__file__).resolve().parent.parent
FILES = {"main.py", "discovery.py", "run.sh", "setup.sh", "test.sh", "README.md", "requirements.txt", "requirements-dev.txt", "requirements-lock.txt", "pytest.ini", ".gitignore"}
DIRECTORIES = {
    "scanner": {".py"},
    "scripts": {".py", ".sh"},
    "tests": {".py"},
    "docs": {".md", ".json"},
    "schemas": {".json"},
    "vendor": {".whl"},
}
EXECUTABLES = {"run.sh", "setup.sh", "test.sh", "scripts/start-ollama.sh"}


def build(output):
    files = [ROOT / name for name in FILES]
    for directory, suffixes in DIRECTORIES.items():
        files.extend(path for path in (ROOT / directory).rglob("*")
                     if path.is_file() and (path.suffix in suffixes or
                         (directory == "vendor" and path.name == "SHA256SUMS"))
                     and "__pycache__" not in path.parts)
    for path in files:
        if not path.is_file() or path.is_symlink():
            raise ValueError(f"Invalid delivery file: {path}")
    output.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for path in sorted(files):
            archive.write(path, Path("agentic-security-scanner") / path.relative_to(ROOT))
    with zipfile.ZipFile(output) as archive:
        corrupt = archive.testzip()
        if corrupt:
            raise ValueError(f"Corrupt ZIP entry: {corrupt}")
        for name in EXECUTABLES:
            member = archive.getinfo("agentic-security-scanner/" + name)
            if not member.external_attr >> 16 & stat.S_IXUSR:
                raise ValueError(f"Missing executable permission: {name}")
    digest = hashlib.sha256(output.read_bytes()).hexdigest()
    output.with_suffix(".zip.sha256").write_text(digest + "  " + output.name + "\n")
    print(f"ZIP: {output}; files: {len(files)}; bytes: {output.stat().st_size}; SHA256: {digest}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("output", type=Path)
    build(parser.parse_args().output.resolve())
