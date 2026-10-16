#!/usr/bin/env python3
"""
scripts/build_and_publish_tools.py — Build & Publish Tools Registry for Compliance Platform

Builds standalone, relocatable archives for:
  - 10 native tools across 5 platforms (windows-x64, linux-x64, linux-arm64, macos-x64, macos-arm64)
  - Python bundle for windows-x64 (relocatable CPython 3.11.9 with checkov, bandit, pylint, pytest, pip-audit, yamllint)
  - CPython standalone for POSIX platforms (linux-x64, linux-arm64, macos-x64, macos-arm64)
  - Node bundle for windows-x64 (portable Node 22 LTS with eslint and typescript)
  - PowerShell module bundle (PSScriptAnalyzer 1.23.0)

Generates schema 3 runtime-manifest.json, computes exact SHA-256 and sizes,
signs with Ed25519, and publishes to GitHub Release tools-v1 on LORD-SOUPEX/Compliance_Platform.
"""

import argparse
import hashlib
import io
import json
import os
import shutil
import subprocess  # nosec B404
import sys
import tarfile
import tempfile
import time
import urllib.error
import urllib.request
import zipfile
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
DIST_DIR = REPO_ROOT / "dist-tools"
CACHE_DIR = REPO_ROOT / ".tools" / "cache" / "upstream"
ED25519_KEY_PATH = REPO_ROOT / ".tools" / "cache" / "distribution_ed25519.key"
GO_BINARY = REPO_ROOT / ".tools" / "go" / "bin" / ("go.exe" if sys.platform == "win32" else "go")

REGISTRY_BASE_URL = "https://github.com/LORD-SOUPEX/Compliance_Platform/releases/download/tools-v1"
REPO_SLUG = "LORD-SOUPEX/Compliance_Platform"
RELEASE_TAG = "tools-v1"

PLATFORMS = ["windows-x64", "linux-x64", "linux-arm64", "macos-x64", "macos-arm64"]

UPSTREAM_BINARIES = {
    "ruff": {
        "version": "0.16.10",
        "version_args": ["--version"],
        "urls": {
            "windows-x64": "https://github.com/astral-sh/ruff/releases/download/0.16.10/ruff-x86_64-pc-windows-msvc.zip",
            "linux-x64": "https://github.com/astral-sh/ruff/releases/download/0.16.10/ruff-x86_64-unknown-linux-gnu.tar.gz",
            "linux-arm64": "https://github.com/astral-sh/ruff/releases/download/0.16.10/ruff-aarch64-unknown-linux-gnu.tar.gz",
            "macos-x64": "https://github.com/astral-sh/ruff/releases/download/0.16.10/ruff-x86_64-apple-darwin.tar.gz",
            "macos-arm64": "https://github.com/astral-sh/ruff/releases/download/0.16.10/ruff-aarch64-apple-darwin.tar.gz",
        },
    },
    "gitleaks": {
        "version": "8.30.1",
        "version_args": ["version"],
        "urls": {
            "windows-x64": "https://github.com/gitleaks/gitleaks/releases/download/v8.30.1/gitleaks_8.30.1_windows_x64.zip",
            "linux-x64": "https://github.com/gitleaks/gitleaks/releases/download/v8.30.1/gitleaks_8.30.1_linux_x64.tar.gz",
            "linux-arm64": "https://github.com/gitleaks/gitleaks/releases/download/v8.30.1/gitleaks_8.30.1_linux_arm64.tar.gz",
            "macos-x64": "https://github.com/gitleaks/gitleaks/releases/download/v8.30.1/gitleaks_8.30.1_darwin_x64.tar.gz",
            "macos-arm64": "https://github.com/gitleaks/gitleaks/releases/download/v8.30.1/gitleaks_8.30.1_darwin_arm64.tar.gz",
        },
    },
    "tflint": {
        "version": "0.64.0",
        "version_args": ["--version"],
        "urls": {
            "windows-x64": "https://github.com/terraform-linters/tflint/releases/download/v0.64.0/tflint_windows_amd64.zip",
            "linux-x64": "https://github.com/terraform-linters/tflint/releases/download/v0.64.0/tflint_linux_amd64.zip",
            "linux-arm64": "https://github.com/terraform-linters/tflint/releases/download/v0.64.0/tflint_linux_arm64.zip",
            "macos-x64": "https://github.com/terraform-linters/tflint/releases/download/v0.64.0/tflint_darwin_amd64.zip",
            "macos-arm64": "https://github.com/terraform-linters/tflint/releases/download/v0.64.0/tflint_darwin_arm64.zip",
        },
    },
    "trivy": {
        "version": "0.75.0",
        "version_args": ["--version"],
        "urls": {
            "windows-x64": "https://github.com/aquasecurity/trivy/releases/download/v0.75.0/trivy_0.75.0_windows-64bit.zip",
            "linux-x64": "https://github.com/aquasecurity/trivy/releases/download/v0.75.0/trivy_0.75.0_Linux-64bit.tar.gz",
            "linux-arm64": "https://github.com/aquasecurity/trivy/releases/download/v0.75.0/trivy_0.75.0_Linux-ARM64.tar.gz",
            "macos-x64": "https://github.com/aquasecurity/trivy/releases/download/v0.75.0/trivy_0.75.0_macOS-64bit.tar.gz",
            "macos-arm64": "https://github.com/aquasecurity/trivy/releases/download/v0.75.0/trivy_0.75.0_macOS-ARM64.tar.gz",
        },
    },
    "terraform": {
        "version": "1.8.5",
        "version_args": ["version"],
        "urls": {
            "windows-x64": "https://releases.hashicorp.com/terraform/1.8.5/terraform_1.8.5_windows_amd64.zip",
            "linux-x64": "https://releases.hashicorp.com/terraform/1.8.5/terraform_1.8.5_linux_amd64.zip",
            "linux-arm64": "https://releases.hashicorp.com/terraform/1.8.5/terraform_1.8.5_linux_arm64.zip",
            "macos-x64": "https://releases.hashicorp.com/terraform/1.8.5/terraform_1.8.5_darwin_amd64.zip",
            "macos-arm64": "https://releases.hashicorp.com/terraform/1.8.5/terraform_1.8.5_darwin_arm64.zip",
        },
    },
    "tofu": {
        "version": "1.8.2",
        "version_args": ["version"],
        "urls": {
            "windows-x64": "https://github.com/opentofu/opentofu/releases/download/v1.8.2/tofu_1.8.2_windows_amd64.zip",
            "linux-x64": "https://github.com/opentofu/opentofu/releases/download/v1.8.2/tofu_1.8.2_linux_amd64.tar.gz",
            "linux-arm64": "https://github.com/opentofu/opentofu/releases/download/v1.8.2/tofu_1.8.2_linux_arm64.tar.gz",
            "macos-x64": "https://github.com/opentofu/opentofu/releases/download/v1.8.2/tofu_1.8.2_darwin_amd64.tar.gz",
            "macos-arm64": "https://github.com/opentofu/opentofu/releases/download/v1.8.2/tofu_1.8.2_darwin_arm64.tar.gz",
        },
    },
    "hadolint": {
        "version": "2.15.1",
        "version_args": ["--version"],
        "bare_binary": True,
        "urls": {
            "windows-x64": "https://github.com/hadolint/hadolint/releases/download/v2.15.1/hadolint-windows-x86_64.exe",
            "linux-x64": "https://github.com/hadolint/hadolint/releases/download/v2.15.1/hadolint-linux-x86_64",
            "linux-arm64": "https://github.com/hadolint/hadolint/releases/download/v2.15.1/hadolint-Linux-arm64",
            "macos-x64": "https://github.com/hadolint/hadolint/releases/download/v2.15.1/hadolint-macos-x86_64",
            "macos-arm64": "https://github.com/hadolint/hadolint/releases/download/v2.15.1/hadolint-macos-arm64",
        },
    },
    "terragrunt": {
        "version": "1.1.6",
        "version_args": ["--version"],
        "bare_binary": True,
        "urls": {
            "windows-x64": "https://github.com/gruntwork-io/terragrunt/releases/download/v1.1.6/terragrunt_windows_amd64.exe",
            "linux-x64": "https://github.com/gruntwork-io/terragrunt/releases/download/v1.1.6/terragrunt_linux_amd64",
            "linux-arm64": "https://github.com/gruntwork-io/terragrunt/releases/download/v1.1.6/terragrunt_linux_arm64",
            "macos-x64": "https://github.com/gruntwork-io/terragrunt/releases/download/v1.1.6/terragrunt_darwin_amd64",
            "macos-arm64": "https://github.com/gruntwork-io/terragrunt/releases/download/v1.1.6/terragrunt_darwin_arm64",
        },
    },
    "shellcheck": {
        "version": "0.10.0",
        "version_args": ["--version"],
        "urls": {
            "windows-x64": "https://github.com/koalaman/shellcheck/releases/download/v0.10.0/shellcheck-v0.10.0.zip",
            "linux-x64": "https://github.com/koalaman/shellcheck/releases/download/v0.10.0/shellcheck-v0.10.0.linux.x86_64.tar.xz",
            "linux-arm64": "https://github.com/koalaman/shellcheck/releases/download/v0.10.0/shellcheck-v0.10.0.linux.aarch64.tar.xz",
            "macos-x64": "https://github.com/koalaman/shellcheck/releases/download/v0.10.0/shellcheck-v0.10.0.darwin.x86_64.tar.xz",
            "macos-arm64": "https://github.com/koalaman/shellcheck/releases/download/v0.10.0/shellcheck-v0.10.0.darwin.aarch64.tar.xz",
        },
    },
    "rumdl": {
        "version": "0.2.79",
        "version_args": ["--version"],
        "urls": {
            "windows-x64": "https://github.com/rvben/rumdl/releases/download/v0.2.79/rumdl-v0.2.79-x86_64-pc-windows-msvc.zip",
            "linux-x64": "https://github.com/rvben/rumdl/releases/download/v0.2.79/rumdl-v0.2.79-x86_64-unknown-linux-musl.tar.gz",
            "linux-arm64": "https://github.com/rvben/rumdl/releases/download/v0.2.79/rumdl-v0.2.79-aarch64-unknown-linux-musl.tar.gz",
            "macos-x64": "https://github.com/rvben/rumdl/releases/download/v0.2.79/rumdl-v0.2.79-x86_64-apple-darwin.tar.gz",
            "macos-arm64": "https://github.com/rvben/rumdl/releases/download/v0.2.79/rumdl-v0.2.79-aarch64-apple-darwin.tar.gz",
        },
    },
}

CPYTHON_STANDALONE = {
    "linux-x64": "https://github.com/astral-sh/python-build-standalone/releases/download/20240415/cpython-3.11.9%2B20240415-x86_64-unknown-linux-gnu-install_only.tar.gz",
    "linux-arm64": "https://github.com/astral-sh/python-build-standalone/releases/download/20240415/cpython-3.11.9%2B20240415-aarch64-unknown-linux-gnu-install_only.tar.gz",
    "macos-x64": "https://github.com/astral-sh/python-build-standalone/releases/download/20240415/cpython-3.11.9%2B20240415-x86_64-apple-darwin-install_only.tar.gz",
    "macos-arm64": "https://github.com/astral-sh/python-build-standalone/releases/download/20240415/cpython-3.11.9%2B20240415-aarch64-apple-darwin-install_only.tar.gz",
}


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while chunk := f.read(65536):
            h.update(chunk)
    return h.hexdigest()


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def download_cached(url: str, filename: str, retries: int = 5) -> Path:
    CACHE_DIR.mkdir(parents=True, exist_ok=True)
    dest = CACHE_DIR / filename
    if dest.exists() and dest.stat().st_size > 0:
        return dest

    for attempt in range(1, retries + 1):
        try:
            print(f"  [DL] {url} -> {dest.name} (attempt {attempt}/{retries})")
            req = urllib.request.Request(url, headers={"User-Agent": "Compliance-Platform-Build"})
            with urllib.request.urlopen(req, timeout=45) as resp, open(dest, "wb") as out:
                shutil.copyfileobj(resp, out)
            return dest
        except (urllib.error.URLError, urllib.error.HTTPError, OSError) as e:
            if dest.exists():
                dest.unlink()
            if attempt == retries:
                raise RuntimeError(f"Download failed after {retries} attempts: {url} -> {e}")
            wait = attempt * 3
            print(f"  [RETRY] Download error: {e}. Retrying in {wait}s...")
            time.sleep(wait)
    return dest


def extract_binary_from_archive(archive_path: Path, binary_name: str) -> bytes:
    name_lower = archive_path.name.lower()
    if name_lower.endswith(".zip"):
        with zipfile.ZipFile(archive_path) as zf:
            for item in zf.infolist():
                if item.is_dir():
                    continue
                leaf = Path(item.filename).name.lower()
                if leaf == binary_name.lower():
                    return zf.read(item)
    elif name_lower.endswith((".tar.gz", ".tgz")):
        with tarfile.open(archive_path, "r:gz") as tf:
            for member in tf.getmembers():
                if not member.isfile():
                    continue
                leaf = Path(member.name).name.lower()
                if leaf == binary_name.lower():
                    f = tf.extractfile(member)
                    if f:
                        return f.read()
    elif name_lower.endswith((".tar.xz", ".txz")):
        with tarfile.open(archive_path, "r:xz") as tf:
            for member in tf.getmembers():
                if not member.isfile():
                    continue
                leaf = Path(member.name).name.lower()
                if leaf == binary_name.lower():
                    f = tf.extractfile(member)
                    if f:
                        return f.read()
    raise RuntimeError(f"Binary {binary_name} not found in {archive_path.name}")


def package_single_binary(raw_bytes: bytes, target_filename: str, inner_name: str) -> tuple[Path, str, str]:
    DIST_DIR.mkdir(parents=True, exist_ok=True)
    out_path = DIST_DIR / target_filename
    bin_sha = sha256_bytes(raw_bytes)

    if target_filename.endswith(".zip"):
        with zipfile.ZipFile(out_path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
            zf.writestr(inner_name, raw_bytes, compress_type=zipfile.ZIP_DEFLATED)
    elif target_filename.endswith(".tar.gz"):
        with tarfile.open(out_path, "w:gz") as tf:
            ti = tarfile.TarInfo(inner_name)
            ti.size = len(raw_bytes)
            ti.mode = 0o755
            tf.addfile(ti, io.BytesIO(raw_bytes))
    else:
        raise ValueError(f"Unsupported archive extension: {target_filename}")

    arc_sha = sha256_file(out_path)
    return out_path, arc_sha, bin_sha


def build_native_tool(tool_name: str, platform: str, cfg: dict) -> tuple[str, str, str, str]:
    version = cfg["version"]
    url = cfg["urls"][platform]
    is_win = platform.startswith("windows")
    ext_exe = ".exe" if is_win else ""
    inner_bin = f"{tool_name}{ext_exe}"

    # Target archive format: .zip for windows, .tar.gz for POSIX (or .zip for terraform/tflint)
    arc_ext = ".zip" if is_win or tool_name in ("tflint", "terraform") else ".tar.gz"
    out_archive_name = f"{platform}-{tool_name}-{version}{arc_ext}"

    if cfg.get("bare_binary"):
        dl_name = f"{platform}-{tool_name}-{version}.bin{ext_exe}"
        raw_file = download_cached(url, dl_name)
        with open(raw_file, "rb") as f:
            raw_bytes = f.read()
    else:
        dl_name = f"upstream-{platform}-{Path(url).name}"
        archive_file = download_cached(url, dl_name)
        raw_bytes = extract_binary_from_archive(archive_file, inner_bin)

    _, arc_sha, bin_sha = package_single_binary(raw_bytes, out_archive_name, inner_bin)
    return out_archive_name, arc_sha, inner_bin, bin_sha


def build_python_bundle_windows() -> tuple[str, str, str]:
    out_name = "windows-x64-python-tools-3.11.9.tar.gz"
    out_path = DIST_DIR / out_name
    src_python = REPO_ROOT / ".tools" / "python"
    if not src_python.exists():
        raise RuntimeError("Source .tools/python does not exist!")

    # Ensure checkov has __main__.py so python -m checkov works seamlessly
    checkov_dir = src_python / "Lib" / "site-packages" / "checkov"
    if checkov_dir.exists():
        checkov_main = checkov_dir / "__main__.py"
        if not checkov_main.exists():
            checkov_main.write_text(
                "import sys\nfrom checkov.main import Checkov\n\nif __name__ == '__main__':\n    sys.exit(Checkov().run())\n",
                encoding="utf-8",
            )

    print("  [BUNDLE] Building relocatable Python bundle for windows-x64...")
    DIST_DIR.mkdir(parents=True, exist_ok=True)
    with tarfile.open(out_path, "w:gz") as tf:
        for root, dirs, files in os.walk(src_python):
            # Exclude pycache and test caches
            dirs[:] = [d for d in dirs if d not in ("__pycache__", ".pytest_cache", ".ruff_cache")]
            rel_dir = Path(root).relative_to(src_python)
            for file in files:
                if file.endswith((".pyc", ".pyo")):
                    continue
                src_file = Path(root) / file
                arc_member = f"python/{rel_dir / file}".replace("\\", "/")
                
                # If it's a script with a hardcoded shebang, sanitize it
                content = None
                if "Scripts" in src_file.parts and not file.endswith((".exe", ".dll", ".pyd")):
                    try:
                        raw = src_file.read_bytes()
                        if raw.startswith(b"#!"):
                            lines = raw.split(b"\n", 1)
                            if b"python" in lines[0].lower():
                                new_shebang = b"#!/usr/bin/env python"
                                rest = lines[1] if len(lines) > 1 else b""
                                content = new_shebang + b"\n" + rest
                    except Exception:
                        pass
                
                if content is not None:
                    ti = tarfile.TarInfo(name=arc_member)
                    ti.size = len(content)
                    ti.mode = 0o755
                    ti.mtime = int(time.time())
                    tf.addfile(ti, io.BytesIO(content))
                else:
                    ti = tf.gettarinfo(src_file, arcname=arc_member)
                    ti.mode = 0o755 if file.endswith((".exe", ".cmd", ".bat")) else 0o644
                    with open(src_file, "rb") as f:
                        tf.addfile(ti, f)

    arc_sha = sha256_file(out_path)
    return out_name, arc_sha, "python/python.exe"


def build_node_bundle_windows() -> tuple[str, str, str]:
    out_name = "windows-x64-node-tools-22.14.0.zip"
    out_path = DIST_DIR / out_name
    print("  [BUNDLE] Building Node 22 bundle for windows-x64...")

    node_url = "https://nodejs.org/dist/v22.14.0/win-x64/node.exe"
    cached_node = download_cached(node_url, "node-v22.14.0-win-x64.exe")

    tmp_dir = Path(tempfile.mkdtemp(prefix="node-bundle-"))
    try:
        npm_cmd = shutil.which("npm.cmd") or shutil.which("npm") or "npm"
        subprocess.run(
            [npm_cmd, "install", "--prefix", str(tmp_dir), "eslint@9.21.0", "typescript@5.7.3", "--no-audit", "--no-fund"],
            check=True,
            capture_output=True,
        )

        DIST_DIR.mkdir(parents=True, exist_ok=True)
        with zipfile.ZipFile(out_path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
            with open(cached_node, "rb") as f:
                node_bytes = f.read()
            zf.writestr("node/node.exe", node_bytes, compress_type=zipfile.ZIP_DEFLATED)

            node_modules = tmp_dir / "node_modules"
            for root, dirs, files in os.walk(node_modules):
                rel_dir = Path(root).relative_to(tmp_dir)
                for file in files:
                    src_file = Path(root) / file
                    arc_member = f"node/{rel_dir / file}".replace("\\", "/")
                    with open(src_file, "rb") as f:
                        zf.writestr(arc_member, f.read(), compress_type=zipfile.ZIP_DEFLATED)
    finally:
        shutil.rmtree(tmp_dir, ignore_errors=True)

    arc_sha = sha256_file(out_path)
    return out_name, arc_sha, "node/node.exe"


def build_psscriptanalyzer_bundle_windows() -> tuple[str, str, str]:
    out_name = "windows-x64-powershell-modules-PSScriptAnalyzer-1.23.0.zip"
    out_path = DIST_DIR / out_name
    print("  [BUNDLE] Building PSScriptAnalyzer 1.23.0 bundle...")

    ps_url = "https://www.powershellgallery.com/api/v2/package/PSScriptAnalyzer/1.23.0"
    cached_nupkg = download_cached(ps_url, "PSScriptAnalyzer-1.23.0.nupkg")

    DIST_DIR.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(cached_nupkg) as src_zf, zipfile.ZipFile(out_path, "w", compression=zipfile.ZIP_DEFLATED) as dst_zf:
        for item in src_zf.infolist():
            if item.is_dir() or item.filename.startswith(("_rels/", "package/")):
                continue
            if item.filename.endswith((".nuspec", "[Content_Types].xml")):
                continue
            data = src_zf.read(item)
            arc_name = f"powershell-modules/PSScriptAnalyzer/{item.filename}".replace("\\", "/")
            dst_zf.writestr(arc_name, data, compress_type=zipfile.ZIP_DEFLATED)

    arc_sha = sha256_file(out_path)
    return out_name, arc_sha, "powershell-modules/PSScriptAnalyzer/PSScriptAnalyzer.psd1"


def package_posix_cpython(platform: str) -> tuple[str, str, str]:
    url = CPYTHON_STANDALONE[platform]
    dl_name = f"cpython-standalone-{platform}-3.11.9.tar.gz"
    src_tar = download_cached(url, dl_name)
    out_name = f"{platform}-python-3.11.9.tar.gz"
    out_path = DIST_DIR / out_name
    shutil.copy2(src_tar, out_path)
    arc_sha = sha256_file(out_path)
    return out_name, arc_sha, "python/bin/python3"


def sign_manifest(manifest_bytes: bytes, key_path: Path) -> str:
    tmp_go = REPO_ROOT / ".tools" / "temp_signer.go"
    code = f"""package main
import (
    "crypto/ed25519"
    "encoding/hex"
    "fmt"
    "os"
)
func main() {{
    keyBytes, err := os.ReadFile({json.dumps(str(key_path))})
    if err != nil {{ fmt.Fprintf(os.Stderr, "key read: %v\\n", err); os.Exit(1) }}
    priv := ed25519.NewKeyFromSeed(keyBytes)
    manifestBytes, err := os.ReadFile({json.dumps(str(REPO_ROOT / ".config" / "runtime-manifest.json"))})
    if err != nil {{ fmt.Fprintf(os.Stderr, "manifest read: %v\\n", err); os.Exit(1) }}
    sig := ed25519.Sign(priv, manifestBytes)
    fmt.Print(hex.EncodeToString(sig))
}}
"""
    with open(tmp_go, "w", encoding="utf-8") as f:
        f.write(code)
    try:
        res = subprocess.run([str(GO_BINARY), "run", str(tmp_go)], check=True, capture_output=True, text=True)
        return res.stdout.strip()
    finally:
        if tmp_go.exists():
            tmp_go.unlink()


def get_github_token() -> str:
    token = os.environ.get("GH_TOKEN") or os.environ.get("GITHUB_TOKEN")
    if token:
        return token
    res = subprocess.run(["git", "credential", "fill"], input="protocol=https\nhost=github.com\n", text=True, capture_output=True)
    for line in res.stdout.splitlines():
        if line.startswith("password="):
            return line.split("=", 1)[1]
    raise RuntimeError("GitHub Token not found in GH_TOKEN, GITHUB_TOKEN or git credential")


def publish_github_release(tag: str, assets: list[Path], repo_slug: str = REPO_SLUG):
    print(f"\n[RELEASE] Publishing {len(assets)} assets to GitHub Release {tag} on {repo_slug}...")
    gh_bin = REPO_ROOT / ".tools" / "bin" / ("gh.exe" if sys.platform == "win32" else "gh")
    token = get_github_token()
    env = os.environ.copy()
    env["GH_TOKEN"] = token

    check_cmd = [str(gh_bin), "release", "view", tag, "--repo", repo_slug]
    res = subprocess.run(check_cmd, env=env, capture_output=True, text=True)
    if res.returncode != 0:
        print(f"Creating release {tag} on {repo_slug}...")
        create_cmd = [
            str(gh_bin), "release", "create", tag,
            "--repo", repo_slug,
            "--title", "Compliance Platform Tools Registry v1",
            "--notes", "Self-hosted relocatable tools registry for Compliance Platform v2.0.18.",
        ]
        subprocess.run(create_cmd, env=env, check=True)

    print("Uploading assets to release...")
    batch_size = 5
    for i in range(0, len(assets), batch_size):
        chunk = assets[i:i + batch_size]
        upload_cmd = [str(gh_bin), "release", "upload", tag, "--repo", repo_slug, "--clobber"] + [str(p) for p in chunk]
        for attempt in range(1, 6):
            res = subprocess.run(upload_cmd, env=env, capture_output=True, text=True)
            if res.returncode == 0:
                print(f"  Uploaded {min(i + len(chunk), len(assets))}/{len(assets)} assets.")
                break
            print(f"  [RETRY] Upload chunk failed ({res.stderr.strip()}). Retrying in {attempt * 2}s (attempt {attempt}/5)...")
            time.sleep(attempt * 2)
            if attempt == 5:
                raise subprocess.CalledProcessError(res.returncode, upload_cmd, output=res.stdout, stderr=res.stderr)
    print("[PASS] All assets successfully uploaded to release!")


def host_matches_platform(plat: str) -> bool:
    if sys.platform == "win32":
        return plat == "windows-x64"
    import platform as sys_plat
    mach = sys_plat.machine().lower()
    if sys.platform == "linux":
        if mach in ("x86_64", "amd64"):
            return plat == "linux-x64"
        if mach in ("aarch64", "arm64"):
            return plat == "linux-arm64"
    if sys.platform == "darwin":
        if mach in ("x86_64", "amd64"):
            return plat == "macos-x64"
        if mach in ("arm64", "aarch64"):
            return plat == "macos-arm64"
    return False


def build_python_bundle_posix(plat: str) -> tuple[str, str, str]:
    """Builds a relocatable Python bundle on Linux/macOS with checkov, bandit, pylint, pytest, pip-audit, yamllint, ansible-lint."""
    out_name = f"{plat}-python-tools-3.11.9.tar.gz"
    out_path = DIST_DIR / out_name
    print(f"  [BUNDLE] Building relocatable Python bundle for {plat}...")

    url = CPYTHON_STANDALONE[plat]
    dl_name = f"cpython-standalone-{plat}-3.11.9.tar.gz"
    src_tar = download_cached(url, dl_name)

    tmp_dir = Path(tempfile.mkdtemp(prefix=f"py-bundle-{plat}-"))
    try:
        with tarfile.open(src_tar, "r:gz") as tf:
            tf.extractall(tmp_dir)

        py_bin = tmp_dir / "python" / "bin" / "python3"
        if not py_bin.exists():
            raise RuntimeError(f"Python binary not found at {py_bin}")

        pip_pkgs = [
            "checkov==3.3.23",
            "bandit==1.9.4",
            "pylint==4.1.2",
            "pytest==9.1.1",
            "pip-audit==2.10.1",
            "yamllint==1.35.1",
            "ansible-lint==25.8.2",
        ]
        subprocess.run(
            [str(py_bin), "-m", "pip", "install", "--no-cache-dir", "--no-warn-script-location"] + pip_pkgs,
            check=True,
        )

        for p in (tmp_dir / "python" / "lib").glob("python*/site-packages/checkov"):
            main_py = p / "__main__.py"
            if not main_py.exists():
                main_py.write_text(
                    "import sys\nfrom checkov.main import Checkov\n\nif __name__ == '__main__':\n    sys.exit(Checkov().run())\n",
                    encoding="utf-8",
                )

        bin_dir = tmp_dir / "python" / "bin"
        if bin_dir.exists():
            for item in bin_dir.iterdir():
                if item.is_file() and not item.is_symlink():
                    try:
                        raw = item.read_bytes()
                        if raw.startswith(b"#!"):
                            lines = raw.split(b"\n", 1)
                            if b"python" in lines[0].lower():
                                new_shebang = b"#!/usr/bin/env python3"
                                rest = lines[1] if len(lines) > 1 else b""
                                item.write_bytes(new_shebang + b"\n" + rest)
                    except Exception:
                        pass

        DIST_DIR.mkdir(parents=True, exist_ok=True)
        with tarfile.open(out_path, "w:gz") as tf:
            for root, dirs, files in os.walk(tmp_dir / "python"):
                dirs[:] = [d for d in dirs if d not in ("__pycache__", ".pytest_cache")]
                for file in files:
                    if file.endswith((".pyc", ".pyo")):
                        continue
                    src_file = Path(root) / file
                    arc_member = f"python/{src_file.relative_to(tmp_dir / 'python')}".replace("\\", "/")
                    ti = tf.gettarinfo(src_file, arcname=arc_member)
                    ti.mode = 0o755 if ("bin" in src_file.parts or file.endswith((".sh",))) else 0o644
                    with open(src_file, "rb") as f:
                        tf.addfile(ti, f)

        arc_sha = sha256_file(out_path)
        return out_name, arc_sha, "python/bin/python3"
    finally:
        shutil.rmtree(tmp_dir, ignore_errors=True)


def main():
    parser = argparse.ArgumentParser(description="Build and publish Compliance Platform tools registry")
    parser.add_argument("--repo", default=REPO_SLUG, help=f"GitHub repository slug (default: {REPO_SLUG})")
    parser.add_argument("--tag", default=RELEASE_TAG, help=f"GitHub release tag (default: {RELEASE_TAG})")
    parser.add_argument("--dry-run", action="store_true", help="Build and measure archives, generate manifest, but do not upload")
    parser.add_argument("--skip-upload", action="store_true", help="Skip uploading to GitHub Releases")
    args = parser.parse_args()

    registry_base_url = f"https://github.com/{args.repo}/releases/download/{args.tag}"

    print("================================================================================")
    print(f"Building Compliance Platform Tools Registry ({args.tag}) on {args.repo}")
    print("================================================================================")

    manifest_platforms = {}
    built_assets = []

    for plat in PLATFORMS:
        print(f"\nProcessing platform {plat}...")
        plat_tools = {}
        for tool_name, cfg in UPSTREAM_BINARIES.items():
            out_arc, arc_sha, inner_bin, bin_sha = build_native_tool(tool_name, plat, cfg)
            built_assets.append(DIST_DIR / out_arc)
            plat_tools[tool_name] = {
                "name": tool_name,
                "version": cfg["version"],
                "install": "archive",
                "archive": out_arc,
                "archive_sha256": arc_sha,
                "binary_in_archive": inner_bin,
                "binary_sha256": bin_sha,
                "version_args": cfg["version_args"],
            }

        # Python & bundles
        if plat == "windows-x64":
            py_arc, py_sha, py_bin = build_python_bundle_windows()
            built_assets.append(DIST_DIR / py_arc)
            plat_tools["python"] = {
                "name": "python",
                "version": "3.11.9",
                "install": "bundle",
                "archive": py_arc,
                "archive_sha256": py_sha,
                "binary_in_archive": py_bin,
                "binary_sha256": "",
                "version_args": ["--version"],
            }
            py_tools = [
                ("bandit", "1.9.4", "bandit"),
                ("pylint", "4.1.2", "pylint"),
                ("pytest", "9.1.1", "pytest"),
                ("pip-audit", "2.10.1", "pip_audit"),
                ("checkov", "3.3.23", "checkov.main"),
                ("yamllint", "1.35.1", "yamllint"),
            ]
            for pname, pver, pmod in py_tools:
                plat_tools[pname] = {
                    "name": pname,
                    "version": pver,
                    "install": "bundle",
                    "bundle": "python",
                    "archive": py_arc,
                    "archive_sha256": py_sha,
                    "python_module": pmod,
                    "binary_in_archive": "python/python.exe",
                    "binary_sha256": "",
                    "version_args": ["--version"],
                }

            node_arc, node_sha, node_bin = build_node_bundle_windows()
            built_assets.append(DIST_DIR / node_arc)
            plat_tools["node"] = {
                "name": "node",
                "version": "22.14.0",
                "install": "bundle",
                "archive": node_arc,
                "archive_sha256": node_sha,
                "binary_in_archive": node_bin,
                "binary_sha256": "",
                "version_args": ["-v"],
            }
            plat_tools["eslint"] = {
                "name": "eslint",
                "version": "9.21.0",
                "install": "bundle",
                "bundle": "node",
                "archive": node_arc,
                "archive_sha256": node_sha,
                "binary_in_archive": "node/node_modules/.bin/eslint.cmd",
                "binary_sha256": "",
                "version_args": ["--version"],
            }
            plat_tools["tsc"] = {
                "name": "tsc",
                "version": "5.7.3",
                "install": "bundle",
                "bundle": "node",
                "archive": node_arc,
                "archive_sha256": node_sha,
                "binary_in_archive": "node/node_modules/.bin/tsc.cmd",
                "binary_sha256": "",
                "version_args": ["-v"],
            }

            ps_arc, ps_sha, ps_bin = build_psscriptanalyzer_bundle_windows()
            built_assets.append(DIST_DIR / ps_arc)
            for ps_alias in ("PSScriptAnalyzer", "Invoke-ScriptAnalyzer"):
                plat_tools[ps_alias] = {
                    "name": ps_alias,
                    "version": "1.23.0",
                    "install": "bundle",
                    "bundle": "powershell-modules",
                    "archive": ps_arc,
                    "archive_sha256": ps_sha,
                    "binary_in_archive": ps_bin,
                    "binary_sha256": "",
                    "version_args": [],
                }
        else:
            if host_matches_platform(plat):
                py_arc, py_sha, py_bin = build_python_bundle_posix(plat)
                built_assets.append(DIST_DIR / py_arc)
                plat_tools["python"] = {
                    "name": "python",
                    "version": "3.11.9",
                    "install": "bundle",
                    "archive": py_arc,
                    "archive_sha256": py_sha,
                    "binary_in_archive": py_bin,
                    "binary_sha256": "",
                    "version_args": ["--version"],
                }
                posix_tools = [
                    ("bandit", "1.9.4", "bandit"),
                    ("pylint", "4.1.2", "pylint"),
                    ("pytest", "9.1.1", "pytest"),
                    ("pip-audit", "2.10.1", "pip_audit"),
                    ("checkov", "3.3.23", "checkov.main"),
                    ("yamllint", "1.35.1", "yamllint"),
                    ("ansible-lint", "25.8.2", "ansiblelint"),
                ]
                for pname, pver, pmod in posix_tools:
                    plat_tools[pname] = {
                        "name": pname,
                        "version": pver,
                        "install": "bundle",
                        "bundle": "python",
                        "archive": py_arc,
                        "archive_sha256": py_sha,
                        "python_module": pmod,
                        "binary_in_archive": "python/bin/python3",
                        "binary_sha256": "",
                        "version_args": ["--version"],
                    }
            else:
                # Standalone CPython runtime when cross-building from Windows or other host
                py_arc, py_sha, py_bin = package_posix_cpython(plat)
                built_assets.append(DIST_DIR / py_arc)
                plat_tools["python"] = {
                    "name": "python",
                    "version": "3.11.9",
                    "install": "bundle",
                    "archive": py_arc,
                    "archive_sha256": py_sha,
                    "binary_in_archive": py_bin,
                    "binary_sha256": "",
                    "version_args": ["--version"],
                }

        manifest_platforms[plat] = {
            "status": "qualified" if plat == "windows-x64" else "targeted",
            "tools": plat_tools,
        }

    manifest_platforms["windows-arm64"] = {
        "status": "targeted",
        "tools": {},
    }

    manifest = {
        "schema_version": 3,
        "manifest_version": "2.0.18",
        "registry_base_url": registry_base_url,
        "platforms": manifest_platforms,
    }

    manifest_json_path = REPO_ROOT / ".config" / "runtime-manifest.json"
    manifest_bytes = json.dumps(manifest, indent=2, ensure_ascii=False).encode("utf-8") + b"\n"
    with open(manifest_json_path, "wb") as f:
        f.write(manifest_bytes)
    print(f"\n[MANIFEST] Written schema 3 manifest to {manifest_json_path}")

    # Sign manifest
    sig_hex = sign_manifest(manifest_bytes, ED25519_KEY_PATH)
    sig_path = REPO_ROOT / ".config" / "runtime-manifest.json.sig"
    with open(sig_path, "w", encoding="utf-8") as f:
        f.write(sig_hex)
    print(f"[SIGN] Signed manifest ({len(sig_hex)} hex characters)")

    # Sync embedded copies
    embedded_dir = REPO_ROOT / "core" / "internal" / "embedded" / "assets"
    embedded_dir.mkdir(parents=True, exist_ok=True)
    shutil.copy2(manifest_json_path, embedded_dir / "runtime-manifest.json")
    shutil.copy2(sig_path, embedded_dir / "runtime-manifest.json.sig")
    print(f"[SYNC] Synchronized embedded runtime-manifest assets")

    # Deduplicate built assets list
    unique_assets = sorted(list(set(built_assets)), key=lambda p: p.name)
    print(f"\n[SUMMARY] {len(unique_assets)} unique archive assets generated:")
    for a in unique_assets:
        size_mb = a.stat().st_size / (1024 * 1024)
        print(f"  - {a.name:<55} ({size_mb:>6.2f} MB)")

    if args.dry_run or args.skip_upload:
        print("\n[INFO] Dry-run or skip-upload active: skipped release publishing.")
        return

    publish_github_release(args.tag, unique_assets, repo_slug=args.repo)


if __name__ == "__main__":
    main()
