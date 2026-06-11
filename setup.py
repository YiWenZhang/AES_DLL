"""
Build script for AES_DLL Python package.

During ``pip install``, this script:
1. Compiles AES_DLL.dll using MSBuild (Windows).
2. Copies the DLL into the ``aes_dll/`` package directory.

The resulting wheel bundles the DLL, so end users get a pure
``pip install aes-dll`` experience with no compilation step.
"""

import os
import shutil
import subprocess
import sys
from pathlib import Path

from setuptools import setup
from setuptools.command.build_py import build_py as _build_py

ROOT = Path(__file__).resolve().parent


def build_dll_msbuild() -> Path:
    """Compile AES_DLL.dll with MSBuild. Returns path to the built DLL."""
    vcxproj = ROOT / "AES_DLL.vcxproj"
    if not vcxproj.exists():
        raise FileNotFoundError(f"Project file not found: {vcxproj}")

    # Locate MSBuild via vswhere
    msbuild = _find_msbuild()

    cmd = [
        msbuild,
        str(vcxproj),
        "-p:Configuration=Release",
        "-p:Platform=x64",
        "-t:Build",
        "-verbosity:minimal",
    ]
    print(f"[aes-dll] Compiling DLL: {' '.join(cmd)}")
    result = subprocess.run(cmd, capture_output=True, text=True)

    if result.returncode != 0:
        print(result.stdout)
        print(result.stderr, file=sys.stderr)
        raise RuntimeError(f"MSBuild failed (exit {result.returncode})")

    dll = ROOT / "x64" / "Release" / "AES_DLL.dll"
    if not dll.exists():
        raise FileNotFoundError(f"DLL not found at {dll} after build")
    return dll


def _find_msbuild() -> str:
    """Find MSBuild.exe via vswhere or fallback paths."""
    # Try vswhere first
    vswhere = (
        Path(os.environ.get("ProgramFiles(x86)", "C:\\Program Files (x86)"))
        / "Microsoft Visual Studio" / "Installer" / "vswhere.exe"
    )
    if vswhere.exists():
        result = subprocess.run(
            [str(vswhere), "-latest", "-products", "*",
             "-requires", "Microsoft.Component.MSBuild",
             "-find", "MSBuild\\**\\Bin\\MSBuild.exe"],
            capture_output=True, text=True,
        )
        paths = [p.strip() for p in result.stdout.splitlines() if p.strip()]
        if paths:
            return paths[0]

    # Fallback: try common VS install locations
    candidates = [
        ROOT / "D:\\visual_studio\\2026\\MSBuild\\Current\\Bin\\amd64\\MSBuild.exe",
    ]
    for c in candidates:
        if Path(c).exists():
            return str(c)

    return "MSBuild.exe"  # hope it's on PATH


class build_py(_build_py):
    """Custom build step: compile the DLL, then run the standard build_py."""

    def run(self):
        # Only build DLL on Windows
        if sys.platform == "win32":
            dll = build_dll_msbuild()
            # Copy DLL into the package directory so it's bundled in the wheel
            dest = ROOT / "aesdll" / "AES_DLL.dll"
            shutil.copy2(dll, dest)
            print(f"[aes-dll] Copied {dll.name} -> {dest}")
        else:
            print("[aes-dll] Skipping DLL build (not on Windows)")

        super().run()


setup(
    cmdclass={"build_py": build_py},
)
