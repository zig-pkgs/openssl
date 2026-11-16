#!/usr/bin/env python3
"""Extract OpenSSL source lists, include paths, defines, and generated files
from a configured OpenSSL build directory (via configdata.pm) for Zig.
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
from collections import deque
from pathlib import Path
from typing import Any

PERL_DUMP_SCRIPT = r"""
use strict;
use warnings;
use JSON::PP;

print encode_json({
    unified_info => \%unified_info,
    config       => \%config,
    target       => \%target,
    disabled     => \%disabled,
});
"""

SOURCE_EXTENSIONS = (".c", ".S", ".s")
GENERATED_EXTENSIONS = (".c", ".h", ".inc", ".S", ".s")


def load_configdata(build_dir: Path) -> dict[str, Any]:
    """Load %unified_info, %config, %target, and %disabled from configdata.pm."""
    configdata_pm = build_dir / "configdata.pm"
    if not configdata_pm.is_file():
        raise FileNotFoundError(f"configdata.pm not found in {build_dir}")

    proc = subprocess.run(
        ["perl", f"-I{build_dir}", "-Mconfigdata", "-MJSON::PP", "-e", PERL_DUMP_SCRIPT],
        check=True,
        capture_output=True,
        text=True,
    )
    return json.loads(proc.stdout)


def _add_unique(ordered: list[str], seen: set[str], items: list[str] | None) -> None:
    if not items:
        return
    for item in items:
        if item and item not in seen:
            seen.add(item)
            ordered.append(item)


def collect_target_artifacts(
    unified_info: dict[str, Any],
    lib_name: str,
    *,
    shared: bool = False,
    generated_set: set[str] | None = None,
) -> dict[str, list[str]]:
    """Resolve all C/ASM sources (split by generated vs static), include dirs, and defines."""
    generated_set = generated_set or set()
    sources_map: dict[str, list[str]] = unified_info.get("sources", {})
    shared_sources_map: dict[str, list[str]] = unified_info.get("shared_sources", {})
    depends_map: dict[str, list[str]] = unified_info.get("depends", {})
    includes_map: dict[str, list[str]] = unified_info.get("includes", {})
    defines_map: dict[str, list[str]] = unified_info.get("defines", {})

    visited_targets: set[str] = set()
    queue: deque[str] = deque([lib_name])

    all_sources: set[str] = set()
    # Keep '.' and 'include' ahead of internal subdirectories.
    include_dirs: list[str] = []
    seen_includes: set[str] = set()
    _add_unique(include_dirs, seen_includes, [".", "include"])
    defines: set[str] = set()

    while queue:
        target = queue.popleft()
        if target in visited_targets:
            continue
        visited_targets.add(target)

        _add_unique(include_dirs, seen_includes, includes_map.get(target))
        defines.update(defines_map.get(target, []))

        if target == lib_name and shared and target in shared_sources_map:
            entries = shared_sources_map[target]
        else:
            entries = sources_map.get(target, [])

        for entry in entries:
            if entry.endswith(".o"):
                _add_unique(include_dirs, seen_includes, includes_map.get(entry))
                defines.update(defines_map.get(entry, []))
                for src in sources_map.get(entry, []):
                    if src.endswith(SOURCE_EXTENSIONS):
                        all_sources.add(src)
            elif entry.endswith(".a"):
                queue.append(entry)

        for dep in depends_map.get(target, []):
            if dep.endswith(".a"):
                queue.append(dep)

    c_sources = sorted(s for s in all_sources if s.endswith(".c") and s not in generated_set)
    c_generated_sources = sorted(s for s in all_sources if s.endswith(".c") and s in generated_set)
    asm_sources = sorted(s for s in all_sources if s.endswith((".S", ".s")) and s not in generated_set)
    asm_generated_sources = sorted(s for s in all_sources if s.endswith((".S", ".s")) and s in generated_set)

    gen_headers = [g for g in generated_set if g.endswith((".h", ".inc"))]
    lib_prefixes = ("ssl/",) if lib_name == "libssl" else ("crypto/", "providers/")
    uncovered_gen_headers = [
        g
        for g in gen_headers
        if g.startswith(lib_prefixes)
        and not any(d != "." and g.startswith(f"{d}/") for d in include_dirs)
    ]
    generated_include_dirs = [
        d
        for d in include_dirs
        if (d == "." and uncovered_gen_headers)
        or (d != "." and any(g.startswith(f"{d}/") for g in gen_headers))
    ]

    return {
        "c_sources": c_sources,
        "c_generated_sources": c_generated_sources,
        "asm_sources": asm_sources,
        "asm_generated_sources": asm_generated_sources,
        "include_dirs": include_dirs,
        "generated_include_dirs": generated_include_dirs,
        "defines": sorted(defines),
    }


def extract_global_defines(config: dict[str, Any], target: dict[str, Any]) -> list[str]:
    """Build common library preprocessor defines matching OpenSSL's Makefile."""
    prefix = config.get("prefix") or "/usr/local"
    libdir_name = config.get("libdir") or "lib"
    libdir = f"{prefix.rstrip('/')}/{libdir_name}"

    openssldir = config.get("openssldir") or f"{prefix.rstrip('/')}/ssl"
    enginesdir = config.get("enginesdir") or f"{libdir}/engines-{config.get('shlib_version', '3')}"
    modulesdir = config.get("modulesdir") or f"{libdir}/ossl-modules"

    raw_defines: list[str] = []
    seen: set[str] = set()

    def push(d: str) -> None:
        if d and d not in seen:
            seen.add(d)
            raw_defines.append(d)

    for d in target.get("defines", []):
        push(d)
    for d in config.get("defines", []):
        push(d)
    for d in config.get("lib_defines", []):
        push(d)
    push("OPENSSL_USE_NODELETE")
    push(f'OPENSSLDIR="{openssldir}"')
    push(f'ENGINESDIR="{enginesdir}"')
    push(f'MODULESDIR="{modulesdir}"')

    return raw_defines


def collect_generated_files(unified_info: dict[str, Any], build_dir: Path) -> list[str]:
    """Return generated source/header/inc/asm files present in build_dir."""
    generated = unified_info.get("generate", {})
    existing = [
        path
        for path in sorted(generated.keys())
        if path.endswith(GENERATED_EXTENSIONS) and (build_dir / path).is_file()
    ]
    return existing


def copy_generated_files(files: list[str], build_dir: Path, dest_dir: Path) -> None:
    """Copy generated files from build_dir into dest_dir preserving relative paths."""
    dest_dir.mkdir(parents=True, exist_ok=True)
    for rel in files:
        src = build_dir / rel
        dst = dest_dir / rel
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(src, dst)


def _zig_str(value: str) -> str:
    escaped = value.replace("\\", "\\\\").replace('"', '\\"')
    return f'"{escaped}"'


def _format_zig_list(name: str, items: list[str]) -> str:
    lines = [f"pub const {name} = [_][]const u8{{"]
    for item in items:
        lines.append(f"    {_zig_str(item)},")
    lines.append("};")
    return "\n".join(lines)


def _format_zon_list(items: list[str]) -> str:
    if not items:
        return ".{}\n"
    lines = [".{"]
    for item in items:
        lines.append(f"    {_zig_str(item)},")
    lines.append("}")
    return "\n".join(lines) + "\n"


def write_zon_bundle(payload: dict[str, Any], out_dir: Path) -> list[Path]:
    """Write small per-concern .zon files into out_dir."""
    out_dir.mkdir(parents=True, exist_ok=True)
    crypto = payload["libcrypto"]
    ssl_static = payload["libssl_static"]
    ssl_shared = payload["libssl_shared"]

    files_map: dict[str, list[str]] = {
        "common_flags.zon": [f"-D{d}" for d in payload["common_defines"]],
        "crypto_flags.zon": [f"-D{d}" for d in crypto["defines"]],
        "crypto_include_dirs.zon": crypto["include_dirs"],
        "crypto_generated_include_dirs.zon": crypto["generated_include_dirs"],
        "crypto_c_sources.zon": crypto["c_sources"],
        "crypto_c_generated_sources.zon": crypto["c_generated_sources"],
        "crypto_asm_sources.zon": crypto["asm_sources"],
        "crypto_asm_generated_sources.zon": crypto["asm_generated_sources"],
        "ssl_include_dirs.zon": ssl_static["include_dirs"],
        "ssl_generated_include_dirs.zon": ssl_static["generated_include_dirs"],
        "ssl_static_sources.zon": ssl_static["c_sources"],
        "ssl_static_generated_sources.zon": ssl_static["c_generated_sources"],
        "ssl_shared_sources.zon": ssl_shared["c_sources"],
        "ssl_shared_generated_sources.zon": ssl_shared["c_generated_sources"],
        "generated_files.zon": payload["generated_files"],
    }

    written: list[Path] = []
    for filename, items in files_map.items():
        path = out_dir / filename
        path.write_text(_format_zon_list(items), encoding="utf-8")
        written.append(path)
    return written


def render_zig(payload: dict[str, Any]) -> str:
    """Render extracted OpenSSL build metadata as a Zig source file."""
    crypto = payload["libcrypto"]
    ssl_static = payload["libssl_static"]
    ssl_shared = payload["libssl_shared"]

    sections = [
        "// Auto-generated by extract_openssl_sources.py from OpenSSL configdata.pm.",
        f"// Target: {payload['target_name']}",
        "",
        _format_zig_list("common_flags", [f"-D{d}" for d in payload["common_defines"]]),
        "",
        _format_zig_list("crypto_flags", [f"-D{d}" for d in crypto["defines"]]),
        "",
        _format_zig_list("crypto_include_dirs", crypto["include_dirs"]),
        "",
        _format_zig_list("crypto_generated_include_dirs", crypto["generated_include_dirs"]),
        "",
        _format_zig_list("crypto_c_sources", crypto["c_sources"]),
        "",
        _format_zig_list("crypto_c_generated_sources", crypto["c_generated_sources"]),
        "",
        _format_zig_list("crypto_asm_sources", crypto["asm_sources"]),
        "",
        _format_zig_list("crypto_asm_generated_sources", crypto["asm_generated_sources"]),
        "",
        _format_zig_list("ssl_include_dirs", ssl_static["include_dirs"]),
        "",
        _format_zig_list("ssl_generated_include_dirs", ssl_static["generated_include_dirs"]),
        "",
        _format_zig_list("ssl_static_sources", ssl_static["c_sources"]),
        "",
        _format_zig_list("ssl_static_generated_sources", ssl_static["c_generated_sources"]),
        "",
        _format_zig_list("ssl_shared_sources", ssl_shared["c_sources"]),
        "",
        _format_zig_list("ssl_shared_generated_sources", ssl_shared["c_generated_sources"]),
        "",
        _format_zig_list("generated_files", payload["generated_files"]),
        "",
    ]
    return "\n".join(sections)


def main() -> int:
    default_build_dir = Path("~/Projects/buildroot/output/build/libopenssl-3.6.5").expanduser()
    parser = argparse.ArgumentParser(
        description="Extract OpenSSL crypto/ssl source lists and flags from configdata.pm."
    )
    parser.add_argument(
        "--build-dir",
        type=Path,
        default=default_build_dir,
        help=f"Configured OpenSSL build directory (default: {default_build_dir})",
    )
    parser.add_argument(
        "--format",
        choices=("zig", "zon", "json"),
        default="zig",
        help="Output format: zig (single .zig), zon (small .zon files in output dir), or json (default: zig)",
    )
    parser.add_argument(
        "-o",
        "--output",
        type=Path,
        default=None,
        help="Output file path (for zig/json) or directory (for zon, default: ./zon)",
    )
    parser.add_argument(
        "--copy-generated",
        type=Path,
        default=None,
        help="Optional destination directory to copy all generated files into",
    )
    args = parser.parse_args()

    build_dir = args.build_dir.expanduser().resolve()
    raw = load_configdata(build_dir)
    unified_info = raw["unified_info"]
    config = raw["config"]
    target = raw["target"]

    generated_files = collect_generated_files(unified_info, build_dir)
    if args.copy_generated is not None:
        dest = args.copy_generated.expanduser().resolve()
        copy_generated_files(generated_files, build_dir, dest)
        print(f"Copied {len(generated_files)} generated files to {dest}", file=sys.stderr)

    generated_set = set(generated_files)
    payload = {
        "target_name": config.get("target", "unknown"),
        "common_defines": extract_global_defines(config, target),
        "libcrypto": collect_target_artifacts(
            unified_info, "libcrypto", shared=False, generated_set=generated_set
        ),
        "libssl_static": collect_target_artifacts(
            unified_info, "libssl", shared=False, generated_set=generated_set
        ),
        "libssl_shared": collect_target_artifacts(
            unified_info, "libssl", shared=True, generated_set=generated_set
        ),
        "generated_files": generated_files,
    }

    if args.format == "zon":
        out_dir = (args.output or Path("zon")).expanduser()
        written = write_zon_bundle(payload, out_dir)
        print(f"Wrote {len(written)} .zon files to {out_dir}", file=sys.stderr)
        return 0

    output_text = (
        render_zig(payload)
        if args.format == "zig"
        else json.dumps(payload, indent=2) + "\n"
    )

    if args.output is not None:
        out_path = args.output.expanduser()
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(output_text, encoding="utf-8")
    else:
        sys.stdout.write(output_text)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
