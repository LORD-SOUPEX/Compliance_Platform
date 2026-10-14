#!/usr/bin/env python3
"""
Packaging script for Compliance Local Pipelines VS Code Extension (.vsix)
Produces a standard Open Packaging Conventions (OPC) compliant .vsix containing
compiled TypeScript extension and embedded multi-OS Go binaries.
"""

import os
import sys
import json
import platform
import zipfile
import shutil
import subprocess
from pathlib import Path

CONTENT_TYPES_XML = """<?xml version="1.0" encoding="utf-8"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
  <Default Extension="json" ContentType="application/json"/>
  <Default Extension="js" ContentType="application/javascript"/>
  <Default Extension="vsixmanifest" ContentType="text/xml"/>
  <Default Extension="exe" ContentType="application/octet-stream"/>
  <Default Extension="md" ContentType="text/markdown"/>
  <Default Extension="txt" ContentType="text/plain"/>
</Types>
"""

VSIX_MANIFEST_TEMPLATE = """<?xml version="1.0" encoding="utf-8"?>
<PackageManifest Version="2.0.0" xmlns="http://schemas.microsoft.com/developer/vsx-schema/2011" xmlns:d="http://schemas.microsoft.com/developer/vsx-schema/design/2011">
  <Metadata>
    <Identity Id="{id}" Version="{version}" Publisher="{publisher}" TargetPlatform="universal"/>
    <DisplayName>{display_name}</DisplayName>
    <Description xml:space="preserve">{description}</Description>
    <Categories>Programming Languages, Linters, Security</Categories>
    <Properties>
      <Property Id="Microsoft.VisualStudio.Code.Engine" Value="{engine}" />
      <Property Id="Microsoft.VisualStudio.Code.ExtensionDependencies" Value="" />
      <Property Id="Microsoft.VisualStudio.Code.ExtensionPack" Value="" />
      <Property Id="Microsoft.VisualStudio.Code.LocalizedLanguages" Value="" />
      <Property Id="Microsoft.VisualStudio.Code.ExtensionKind" Value="workspace" />
    </Properties>
  </Metadata>
  <Installation>
    <InstallationTarget Id="Microsoft.VisualStudio.Code"/>
  </Installation>
  <Dependencies/>
  <Assets>
    <Asset Type="Microsoft.VisualStudio.Code.Manifest" Path="extension/package.json" Addressable="true"/>
    <Asset Type="Microsoft.VisualStudio.Services.Content.Details" Path="extension/README.md" Addressable="true"/>
  </Assets>
</PackageManifest>
"""

TARGETS = [
    ("windows", "amd64", "compliance-windows-amd64.exe"),
    ("windows", "arm64", "compliance-windows-arm64.exe"),
    ("linux", "amd64", "compliance-linux-amd64"),
    ("linux", "arm64", "compliance-linux-arm64"),
    ("darwin", "amd64", "compliance-darwin-amd64"),
    ("darwin", "arm64", "compliance-darwin-arm64"),
]

EMBEDDED_CONFIG = [
    "control-catalog.json",
    "control-catalog.schema.json",
    "compliance-report.schema.json",
    "compliance-session.schema.json",
    "runtime-manifest.json",
    "runtime-manifest.json.sig",
    "runtime-manifest.schema.json",
    "pipeline.schema.json",
    "platform-support.json",
]

def sync_embedded_assets(root: Path) -> None:
    """Copy .config into the Go embed tree. //go:embed cannot reach a parent of core/."""
    source = root / ".config"
    destination = root / "core" / "internal" / "embedded" / "assets"
    destination.mkdir(parents=True, exist_ok=True)
    for name in EMBEDDED_CONFIG:
        src = source / name
        if not src.is_file():
            raise RuntimeError(f"Fichier de configuration absent pour l'embed Go: {src}")
        shutil.copy2(src, destination / name)

def host_cli_binary_name() -> str:
    machine = platform.machine().lower()
    arm = machine in ("arm64", "aarch64")
    if sys.platform == "win32":
        return "compliance-windows-arm64.exe" if arm else "compliance-windows-amd64.exe"
    if sys.platform == "darwin":
        return "compliance-darwin-arm64" if arm else "compliance-darwin-amd64"
    return "compliance-linux-arm64" if arm else "compliance-linux-amd64"

def write_zip_entry(zf: zipfile.ZipFile, src_path: Path, arcname: str, executable: bool) -> None:
    data = src_path.read_bytes()
    info = zipfile.ZipInfo(arcname)
    info.compress_type = zipfile.ZIP_DEFLATED
    if executable:
        info.create_system = 3
        info.external_attr = (0o100755) << 16
    else:
        info = zipfile.ZipInfo.from_file(src_path, arcname)
        info.compress_type = zipfile.ZIP_DEFLATED
    zf.writestr(info, data)

def find_go_binary(root: Path) -> str:
    tool_go = root / ".tools" / "go" / "bin" / ("go.exe" if sys.platform == "win32" else "go")
    if tool_go.exists():
        return str(tool_go)
    which_go = shutil.which("go")
    if which_go:
        return which_go
    return ""

def get_latest_core_mtime(core_dir: Path) -> float:
    latest = 0.0
    for path in core_dir.rglob("*.go"):
        try:
            mtime = path.stat().st_mtime
            if mtime > latest:
                latest = mtime
        except OSError:
            pass
    return latest

def ensure_binaries(ext_dir: Path, force: bool = False):
    root = ext_dir.parent
    sync_embedded_assets(root)
    core_dir = root / "core"
    bin_dir = ext_dir / "bin"
    bin_dir.mkdir(parents=True, exist_ok=True)

    go_bin = find_go_binary(root)
    latest_src_mtime = get_latest_core_mtime(core_dir)

    for goos, goarch, binary_name in TARGETS:
        dest_path = bin_dir / binary_name
        needs_build = force or (not dest_path.exists()) or (dest_path.stat().st_mtime < latest_src_mtime)
        if needs_build:
            if not go_bin:
                if dest_path.exists():
                    print(f"[WARN] Go compiler not found, using existing binary: {dest_path}")
                    continue
                raise RuntimeError(f"Go compiler not found and required binary is missing: {dest_path}")

            print(f"[BUILD] Compiling Go engine for {goos}/{goarch} -> {binary_name}...")
            env = dict(os.environ)
            env["CGO_ENABLED"] = "0"
            env["GOOS"] = goos
            env["GOARCH"] = goarch

            cmd = [
                go_bin, "build",
                "-ldflags=-s -w",
                "-o", str(dest_path),
                "./cmd/compliance"
            ]
            res = subprocess.run(cmd, cwd=str(core_dir), env=env, capture_output=True, text=True)
            if res.returncode != 0:
                raise RuntimeError(f"Failed to build binary for {goos}/{goarch}: {res.stderr}")
            print(f"  + Built {binary_name} ({dest_path.stat().st_size} bytes)")

    # Synchronize local CLI in .tools/bin/ if directory exists
    tools_bin = root / ".tools" / "bin"
    if tools_bin.exists():
        cli_name = "compliance.exe" if sys.platform == "win32" else "compliance"
        src_candidate = bin_dir / host_cli_binary_name()
        if src_candidate.exists():
            shutil.copy2(src_candidate, tools_bin / cli_name)
            if sys.platform != "win32":
                os.chmod(tools_bin / cli_name, 0o755)

def package_vsix():
    ext_dir = Path(__file__).resolve().parent
    root = ext_dir.parent
    package_json_path = ext_dir / "package.json"

    with open(package_json_path, "r", encoding="utf-8") as f:
        pkg = json.load(f)

    name = pkg.get("name", "compliance-local-pipelines")
    version = pkg.get("version", "0.1.0")
    publisher = pkg.get("publisher", "compliance-platform")
    display_name = pkg.get("displayName", name)
    description = pkg.get("description", "")
    engine = pkg.get("engines", {}).get("vscode", "^1.81.0")

    vsix_manifest = VSIX_MANIFEST_TEMPLATE.format(
        id=name,
        version=version,
        publisher=publisher,
        display_name=display_name,
        description=description,
        engine=engine,
    )

    # 1. Compile missing or outdated multi-OS binaries
    ensure_binaries(ext_dir)

    dist_dir = ext_dir / "dist"
    dist_dir.mkdir(parents=True, exist_ok=True)
    vsix_filename = f"{name}-{version}.vsix"
    vsix_path = dist_dir / vsix_filename

    print(f"[INFO] Packaging {name} v{version} into {vsix_path}...")

    # Files to include in extension/ directory
    extension_files = []
    executable_arcnames = set()

    # 1. package.json & README.md
    extension_files.append((ext_dir / "package.json", "extension/package.json"))
    readme_path = ext_dir / "README.md"
    if readme_path.exists():
        extension_files.append((readme_path, "extension/README.md"))

    # 2. Compiled JS files in .extension-build/src/
    build_src = ext_dir / ".extension-build" / "src"
    if not build_src.exists():
        raise RuntimeError("Build artifacts in .extension-build/src/ missing. Run Build first.")
    for file in build_src.glob("*.js"):
        extension_files.append((file, f"extension/.extension-build/src/{file.name}"))

    # 3. Binaries in bin/
    bin_dir = ext_dir / "bin"
    if not bin_dir.exists():
        raise RuntimeError("Embedded binaries in bin/ missing. Run build_go_binaries first.")
    for file in sorted(bin_dir.iterdir()):
        if file.is_file():
            arcname = f"extension/bin/{file.name}"
            extension_files.append((file, arcname))
            if not file.name.endswith(".exe"):
                executable_arcnames.add(arcname)

    config_dir = root / ".config"
    for name in EMBEDDED_CONFIG:
        src = config_dir / name
        extension_files.append((src, f"extension/.config/{name}"))

    # Create VSIX ZIP archive
    with zipfile.ZipFile(vsix_path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        # Write root OPC entries
        zf.writestr("[Content_Types].xml", CONTENT_TYPES_XML.strip())
        zf.writestr("extension.vsixmanifest", vsix_manifest.strip())

        # Write extension files
        for src_path, arcname in extension_files:
            print(f"  + {arcname} ({src_path.stat().st_size} bytes)")
            write_zip_entry(zf, src_path, arcname, arcname in executable_arcnames)

    print(f"[SUCCESS] VSIX archive built successfully: {vsix_path} ({vsix_path.stat().st_size} bytes)")
    return vsix_path

if __name__ == "__main__":
    ext_dir = Path(__file__).resolve().parent
    if len(sys.argv) > 1 and sys.argv[1] == "--ensure-binaries":
        ensure_binaries(ext_dir)
        sys.exit(0)
    package_vsix()
