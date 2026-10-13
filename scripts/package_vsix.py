#!/usr/bin/env python3
"""
Packaging script for Compliance Local Pipelines VS Code Extension (.vsix)
Produces a standard Open Packaging Conventions (OPC) compliant .vsix containing
compiled TypeScript extension and embedded multi-OS Go binaries.
"""

import os
import sys
import json
import zipfile
import shutil
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

def package_vsix():
    root = Path(__file__).resolve().parent.parent
    ext_dir = root / "vscode-extension"
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

    dist_dir = ext_dir / "dist"
    dist_dir.mkdir(parents=True, exist_ok=True)
    vsix_filename = f"{name}-{version}.vsix"
    vsix_path = dist_dir / vsix_filename

    print(f"[INFO] Packaging {name} v{version} into {vsix_path}...")

    # Files to include in extension/ directory
    extension_files = []

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
    for file in bin_dir.iterdir():
        if file.is_file():
            extension_files.append((file, f"extension/bin/{file.name}"))

    # Create VSIX ZIP archive
    with zipfile.ZipFile(vsix_path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        # Write root OPC entries
        zf.writestr("[Content_Types].xml", CONTENT_TYPES_XML.strip())
        zf.writestr("extension.vsixmanifest", vsix_manifest.strip())

        # Write extension files
        for src_path, arcname in extension_files:
            print(f"  + {arcname} ({src_path.stat().st_size} bytes)")
            zf.write(src_path, arcname)

    print(f"[SUCCESS] VSIX archive built successfully: {vsix_path} ({vsix_path.stat().st_size} bytes)")
    return vsix_path

if __name__ == "__main__":
    package_vsix()
