#!/usr/bin/env python3
"""
Packaging script for Compliance Local Pipelines VS Code Extension (.vsix)
Produces a standard Open Packaging Conventions (OPC) compliant .vsix containing
compiled TypeScript extension and embedded multi-OS Go binaries.
"""

import html
import json
import os
import platform
import shutil
import struct
import subprocess  # nosec B404
import sys
import xml.etree.ElementTree as ET  # nosec B405
import zipfile
from pathlib import Path

MIME_BY_EXTENSION = {
    "json": "application/json",
    "js": "application/javascript",
    "vsixmanifest": "text/xml",
    "xml": "text/xml",
    "exe": "application/octet-stream",
    "md": "text/markdown",
    "txt": "text/plain",
    "sig": "application/octet-stream",
    "png": "image/png",
    "jpg": "image/jpeg",
    "jpeg": "image/jpeg",
}

VSIX_MANIFEST_TEMPLATE = """<?xml version="1.0" encoding="utf-8"?>
<PackageManifest Version="2.0.0" xmlns="http://schemas.microsoft.com/developer/vsx-schema/2011" xmlns:d="http://schemas.microsoft.com/developer/vsx-schema/design/2011">
  <Metadata>
    {identity}
    <DisplayName>{display_name}</DisplayName>
    <Description xml:space="preserve">{description}</Description>
    <Categories>{categories}</Categories>
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
    <Asset Type="Microsoft.VisualStudio.Services.Content.License" Path="extension/LICENSE" Addressable="true"/>
  </Assets>
</PackageManifest>
"""

BUILD_STAMP = "cgo0-trimpath-v1"

# Valeurs acceptées par le Marketplace VS Code. "universal" n'en fait pas partie :
# un paquet multi-plateforme omet simplement l'attribut TargetPlatform.
VALID_TARGET_PLATFORMS = {
    "win32-x64",
    "win32-arm64",
    "linux-x64",
    "linux-arm64",
    "linux-armhf",
    "alpine-x64",
    "alpine-arm64",
    "darwin-x64",
    "darwin-arm64",
    "web",
}

# Seules ces cibles ont un binaire embarqué. Les autres valeurs Marketplace
# restent refusées tant qu'aucun binaire dédié n'existe.
PLATFORM_BINARIES = {
    "win32-x64": "compliance-windows-amd64.exe",
    "win32-arm64": "compliance-windows-arm64.exe",
    "linux-x64": "compliance-linux-amd64",
    "linux-arm64": "compliance-linux-arm64",
    "darwin-x64": "compliance-darwin-amd64",
    "darwin-arm64": "compliance-darwin-arm64",
}

VS_XML = "http://schemas.microsoft.com/developer/vsx-schema/2011"


def render_identity(extension_id, version, publisher, target_platform=None) -> str:
    """Identity without TargetPlatform for a universal VSIX. vsce does the same."""
    if target_platform is None:
        return f'<Identity Id="{extension_id}" Version="{version}" Publisher="{publisher}"/>'
    if target_platform not in VALID_TARGET_PLATFORMS:
        allowed = ", ".join(sorted(VALID_TARGET_PLATFORMS))
        raise RuntimeError(
            f"TargetPlatform {target_platform!r} refusé par le Marketplace. "
            f"Valeurs autorisées : {allowed}. "
            'Un paquet universel ne doit pas porter cet attribut (en particulier pas "universal").'
        )
    binary = PLATFORM_BINARIES.get(target_platform)
    if not binary:
        raise RuntimeError(
            f"Aucun binaire n'est embarqué pour TargetPlatform {target_platform}. "
            "Ne pas publier cette cible tant que le binaire correspondant n'existe pas."
        )
    return (
        f'<Identity Id="{extension_id}" Version="{version}" Publisher="{publisher}" '
        f'TargetPlatform="{target_platform}"/>'
    )


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
            raise RuntimeError(
                f"Fichier de configuration absent pour l'embed Go: {src}"
            )
        shutil.copy2(src, destination / name)


def host_cli_binary_name() -> str:
    machine = platform.machine().lower()
    arm = machine in ("arm64", "aarch64")
    if sys.platform == "win32":
        return "compliance-windows-arm64.exe" if arm else "compliance-windows-amd64.exe"
    if sys.platform == "darwin":
        return "compliance-darwin-arm64" if arm else "compliance-darwin-amd64"
    return "compliance-linux-arm64" if arm else "compliance-linux-amd64"


def content_types_xml(arcnames) -> str:
    extensions = {"vsixmanifest"}
    overrides = []
    for arcname in arcnames:
        leaf = arcname.rsplit("/", 1)[-1]
        if "." in leaf and not leaf.startswith("."):
            extensions.add(leaf.rsplit(".", 1)[-1].lower())
        else:
            part_name = "/" + arcname.lstrip("/")
            overrides.append(
                f'  <Override PartName="{html.escape(part_name, quote=True)}" ContentType="application/octet-stream"/>'
            )
        if leaf.lower().endswith((".jpg", ".jpeg")):
            part_name = "/" + arcname.lstrip("/")
            overrides.append(
                f'  <Override PartName="{html.escape(part_name, quote=True)}" ContentType="image/jpeg"/>'
            )
    lines = [
        '<?xml version="1.0" encoding="utf-8"?>',
        '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">',
    ]
    for ext in sorted(extensions):
        mime = MIME_BY_EXTENSION.get(ext, "application/octet-stream")
        lines.append(f'  <Default Extension="{ext}" ContentType="{mime}"/>')
    lines.extend(sorted(overrides))
    lines.append("</Types>")
    return "\n".join(lines)


def write_zip_entry(
    zf: zipfile.ZipFile, src_path: Path, arcname: str, executable: bool
) -> None:
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
    tool_go = (
        root / ".tools" / "go" / "bin" / ("go.exe" if sys.platform == "win32" else "go")
    )
    if tool_go.exists():
        return str(tool_go)
    which_go = shutil.which("go")
    if which_go:
        return which_go
    return ""


def get_latest_core_mtime(core_dir: Path) -> float:
    latest = 0.0
    for path in core_dir.rglob("*"):
        if path.is_file():
            try:
                latest = max(latest, path.stat().st_mtime)
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
    stamp_path = bin_dir / ".buildstamp"
    stamp_ok = (
        stamp_path.is_file()
        and stamp_path.read_text(encoding="utf-8").strip() == BUILD_STAMP
    )

    for goos, goarch, binary_name in TARGETS:
        dest_path = bin_dir / binary_name
        needs_build = (
            force
            or (not stamp_ok)
            or (not dest_path.exists())
            or (dest_path.stat().st_mtime < latest_src_mtime)
        )
        if needs_build:
            if not go_bin:
                if dest_path.exists():
                    print(
                        f"[WARN] Go compiler not found, using existing binary: {dest_path}"
                    )
                    continue
                raise RuntimeError(
                    f"Go compiler not found and required binary is missing: {dest_path}"
                )

            print(
                f"[BUILD] Compiling Go engine for {goos}/{goarch} -> {binary_name}..."
            )
            env = dict(os.environ)
            env["CGO_ENABLED"] = "0"
            env["GOOS"] = goos
            env["GOARCH"] = goarch

            cmd = [
                go_bin,
                "build",
                "-trimpath",
                "-ldflags=-s -w",
                "-o",
                str(dest_path),
                "./cmd/compliance",
            ]
            res = subprocess.run(  # nosec B603
                cmd,
                cwd=str(core_dir),
                env=env,
                capture_output=True,
                text=True,
                check=False,
            )
            if res.returncode != 0:
                raise RuntimeError(
                    f"Failed to build binary for {goos}/{goarch}: {res.stderr}"
                )
            print(f"  + Built {binary_name} ({dest_path.stat().st_size} bytes)")

    stamp_path.write_text(BUILD_STAMP + "\n", encoding="utf-8")

    # Synchronize local CLI in .tools/bin/ if directory exists
    tools_bin = root / ".tools" / "bin"
    if tools_bin.exists():
        cli_name = "compliance.exe" if sys.platform == "win32" else "compliance"
        src_candidate = bin_dir / host_cli_binary_name()
        if src_candidate.exists():
            shutil.copy2(src_candidate, tools_bin / cli_name)
            if sys.platform != "win32":
                os.chmod(tools_bin / cli_name, 0o755)  # nosec B103


def compile_typescript(ext_dir: Path) -> None:
    """The VSIX must contain the TypeScript just edited, not a stale .extension-build."""
    tsc = ext_dir / "node_modules" / "typescript" / "lib" / "tsc.js"
    node = shutil.which("node")
    if not tsc.is_file() or not node:
        raise RuntimeError("node ou typescript absent. Lancer npm install dans vscode-extension.")
    print("[BUILD] Compilation TypeScript...")
    result = subprocess.run(  # nosec B603
        [node, str(tsc), "-p", "tsconfig.json"],
        cwd=ext_dir,
        check=False,
    )
    if result.returncode != 0:
        raise RuntimeError("Compilation TypeScript échouée. Le VSIX n'est pas produit.")


def package_vsix(target_platform=None):
    ext_dir = Path(__file__).resolve().parent
    root = ext_dir.parent
    package_json_path = ext_dir / "package.json"

    with open(package_json_path, "r", encoding="utf-8") as f:
        pkg = json.load(f)

    name = pkg.get("name", "compliance-local-pipelines")
    version = pkg.get("version", "0.1.0")
    publisher = pkg.get("publisher", "compliance-platform")
    display_name = html.escape(pkg.get("displayName", name), quote=False)
    description = html.escape(pkg.get("description", ""), quote=False)
    engine = html.escape(pkg.get("engines", {}).get("vscode", "^1.81.0"), quote=False)
    categories = html.escape(
        ", ".join(pkg.get("categories") or ["Linters"]), quote=False
    )
    publisher = html.escape(publisher, quote=False)
    name = html.escape(name, quote=False)
    version = html.escape(version, quote=False)

    vsix_manifest = VSIX_MANIFEST_TEMPLATE.format(
        identity=render_identity(name, version, publisher, target_platform),
        display_name=display_name,
        description=description,
        categories=categories,
        engine=engine,
    )

    compile_typescript(ext_dir)
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
    docs = root / "docs"
    marketplace = ext_dir / "README.md"
    changelog_path = docs / "CHANGELOG.md"
    if marketplace.is_file():
        extension_files.append((marketplace, "extension/README.md"))
    if changelog_path.is_file():
        extension_files.append((changelog_path, "extension/CHANGELOG.md"))
    uninstall_script = ext_dir / "scripts" / "uninstall.js"
    if uninstall_script.is_file():
        extension_files.append((uninstall_script, "extension/scripts/uninstall.js"))

    # 2. Compiled JS files in .extension-build/src/
    build_src = ext_dir / ".extension-build" / "src"
    if not build_src.exists():
        raise RuntimeError(
            "Build artifacts in .extension-build/src/ missing. Run Build first."
        )
    for file in build_src.glob("*.js"):
        extension_files.append((file, f"extension/.extension-build/src/{file.name}"))

    # 3. Binaries in bin/
    bin_dir = ext_dir / "bin"
    if not bin_dir.exists():
        raise RuntimeError(
            "Embedded binaries in bin/ missing. Run build_go_binaries first."
        )
    allowed_binary = PLATFORM_BINARIES.get(target_platform) if target_platform else None
    for file in sorted(bin_dir.iterdir()):
        if not file.is_file() or file.name.startswith("."):
            continue
        if allowed_binary and file.name != allowed_binary:
            continue
        arcname = f"extension/bin/{file.name}"
        extension_files.append((file, arcname))
        if not file.name.endswith(".exe"):
            executable_arcnames.add(arcname)

    icon_path = ext_dir / "media" / "icon.png"
    if not icon_path.is_file():
        raise RuntimeError(
            "media/icon.png absent : le Marketplace exige un PNG d'au moins 128x128."
        )
    extension_files.append((icon_path, "extension/media/icon.png"))
    report_css = ext_dir / "media" / "report.css"
    if not report_css.is_file():
        raise RuntimeError(
            "Rapport webview incomplet : media/report.css absent."
        )
    extension_files.append((report_css, "extension/media/report.css"))

    license_path = root / "LICENSE"
    if not license_path.is_file():
        raise RuntimeError("LICENSE absent à la racine du dépôt.")
    extension_files.append((license_path, "extension/LICENSE"))

    config_dir = root / ".config"
    for name in EMBEDDED_CONFIG:
        src = config_dir / name
        extension_files.append((src, f"extension/.config/{name}"))

    # Create VSIX ZIP archive
    content_types = content_types_xml(
        [arcname for _, arcname in extension_files] + ["extension.vsixmanifest"]
    )
    with zipfile.ZipFile(vsix_path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        # Write root OPC entries
        zf.writestr("[Content_Types].xml", content_types)
        zf.writestr("extension.vsixmanifest", vsix_manifest.strip())

        # Write extension files
        for src_path, arcname in extension_files:
            print(f"  + {arcname} ({src_path.stat().st_size} bytes)")
            write_zip_entry(zf, src_path, arcname, arcname in executable_arcnames)

    print(
        f"[SUCCESS] VSIX archive built successfully: {vsix_path} ({vsix_path.stat().st_size} bytes)"
    )
    validate_marketplace_vsix(vsix_path, package_json_path)
    return vsix_path


def png_size(data: bytes) -> tuple:
    if not data.startswith(b"\x89PNG\r\n\x1a\n") or data[12:16] != b"IHDR":
        raise RuntimeError("L'icône embarquée n'est pas un PNG.")
    width, height = struct.unpack(">II", data[16:24])
    return width, height


def validate_marketplace_vsix(vsix_path: Path, package_json_path: Path) -> None:
    """Fail if the VSIX manifest would be rejected by the Marketplace validator."""
    if not vsix_path.is_file():
        raise RuntimeError(
            f"VSIX introuvable pour le contrôle Marketplace : {vsix_path}"
        )

    pkg = json.loads(package_json_path.read_text(encoding="utf-8"))
    with zipfile.ZipFile(vsix_path) as archive:
        try:
            manifest_xml = archive.read("extension.vsixmanifest")
        except KeyError as exc:
            raise RuntimeError("extension.vsixmanifest absent du VSIX.") from exc
        if (
            b'TargetPlatform="universal"' in manifest_xml
            or b"TargetPlatform='universal'" in manifest_xml
        ):
            raise RuntimeError(
                'Le manifeste contient TargetPlatform="universal", valeur refusée par le Marketplace.'
            )

        root = ET.fromstring(manifest_xml)  # nosec B314
        ns = {"v": VS_XML}
        identity = root.find("v:Metadata/v:Identity", ns)
        if identity is None:
            raise RuntimeError("Élément Identity absent du manifeste.")
        if identity.get("Id") != pkg.get("name"):
            raise RuntimeError(
                f"Identity@Id={identity.get('Id')!r} différent de package.json name."
            )
        if identity.get("Version") != pkg.get("version"):
            raise RuntimeError(
                f"Identity@Version={identity.get('Version')!r} différent de package.json version."
            )
        if identity.get("Publisher") != pkg.get("publisher"):
            raise RuntimeError(
                f"Identity@Publisher={identity.get('Publisher')!r} différent de package.json publisher."
            )
        target_platform = identity.get("TargetPlatform")
        if (
            target_platform is not None
            and target_platform not in VALID_TARGET_PLATFORMS
        ):
            raise RuntimeError(
                f"TargetPlatform {target_platform!r} hors liste Marketplace."
            )

        install = root.find("v:Installation/v:InstallationTarget", ns)
        if install is None or install.get("Id") != "Microsoft.VisualStudio.Code":
            raise RuntimeError("InstallationTarget Microsoft.VisualStudio.Code absent.")

        engine = None
        for prop in root.findall("v:Metadata/v:Properties/v:Property", ns):
            if prop.get("Id") == "Microsoft.VisualStudio.Code.Engine":
                engine = prop.get("Value")
        expected_engine = (pkg.get("engines") or {}).get("vscode")
        if not engine or engine != expected_engine:
            raise RuntimeError(
                f"Engine du manifeste {engine!r} différent de engines.vscode {expected_engine!r}."
            )

        asset_types = {
            asset.get("Type") for asset in root.findall("v:Assets/v:Asset", ns)
        }
        for required in (
            "Microsoft.VisualStudio.Code.Manifest",
            "Microsoft.VisualStudio.Services.Content.Details",
            "Microsoft.VisualStudio.Services.Content.License",
        ):
            if required not in asset_types:
                raise RuntimeError(f"Asset manifeste absent : {required}")

        icon_rel = str(pkg.get("icon") or "").replace("\\", "/")
        if not icon_rel:
            raise RuntimeError("package.json ne déclare pas icon.")
        icon_entry = "extension/" + icon_rel.lstrip("./")
        try:
            icon_bytes = archive.read(icon_entry)
        except KeyError as exc:
            raise RuntimeError(f"Icône absente du VSIX : {icon_entry}") from exc
        width, height = png_size(icon_bytes)
        if width < 128 or height < 128:
            raise RuntimeError(
                f"Icône {width}x{height} : le Marketplace exige un PNG d'au moins 128x128."
            )

    print(
        f"[PASS] Manifeste Marketplace valide ({vsix_path.name}, icône {width}x{height})."
    )


if __name__ == "__main__":
    ext_dir = Path(__file__).resolve().parent
    if len(sys.argv) > 1 and sys.argv[1] == "--ensure-binaries":
        ensure_binaries(ext_dir)
        sys.exit(0)
    if len(sys.argv) > 1 and sys.argv[1] == "--check-vsix":
        package_json_path = ext_dir / "package.json"
        pkg = json.loads(package_json_path.read_text(encoding="utf-8"))
        vsix_path = ext_dir / "dist" / f"{pkg['name']}-{pkg['version']}.vsix"
        validate_marketplace_vsix(vsix_path, package_json_path)
        sys.exit(0)
    if len(sys.argv) > 2 and sys.argv[1] == "--target-platform":
        package_vsix(target_platform=sys.argv[2])
        sys.exit(0)
    package_vsix()
