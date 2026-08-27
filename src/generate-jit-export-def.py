#!/usr/bin/env python3
"""Generate a .def file exporting symbols from static libraries.

Used on Windows to selectively export symbols from zeek.exe so that
JIT-compiled HLTO DLLs and dynamic plugins can import them at load time.

Usage: python generate-jit-export-def.py <dumpbin_exe> <output.def> <lib1.lib> [lib2.lib ...]
       [--scan-dir <dir>]  [-- <backing_lib1> ...]

Libraries before '--' are "primary": all their defined external symbols are
exported.  Libraries after '--' are "backing": only symbols that are
*referenced but undefined* in the primary set are exported from the backing
set.  This resolves transitive dependencies (e.g. core Zeek APIs called by
inline runtime code) without exporting the entire Zeek symbol table.

--scan-dir <dir> scans for zeek_* and plugin-* obj files under <dir>,
adding them to the primary set. Uses os.walk to avoid symlink loops.
"""

import os
import re
import subprocess
import sys


def _parse_symbols(dumpbin, lib_path):
    """Return (defined, undefined, data_syms) sets of external symbols.

    data_syms contains names of symbols that are data (not functions).
    """
    result = subprocess.run(
        [dumpbin, "/SYMBOLS", lib_path],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    if result.returncode != 0:
        print(
            f"Warning: dumpbin failed on {lib_path}: {result.stderr}", file=sys.stderr
        )
        return set(), set(), set()

    defined = set()
    undefined = set()
    data_syms = set()
    for line in result.stdout.splitlines():
        if "External" not in line:
            continue
        parts = line.split("|", 1)
        if len(parts) < 2:
            continue

        is_function = "notype ()" in parts[0]
        sym = parts[1].strip()
        if not sym:
            continue
        paren_idx = sym.find(" (")
        if paren_idx > 0:
            sym = sym[:paren_idx].strip()
        if not sym:
            continue
        if sym.startswith("@") or sym.startswith("$") or sym.startswith("__@@_"):
            continue
        if sym.startswith(".") or sym == "@comp.id" or sym == "@feat.00":
            continue
        if "UNDEF" in line:
            undefined.add(sym)
        else:
            defined.add(sym)
            if not is_function:
                data_syms.add(sym)
    return defined, undefined, data_syms


def extract_defined_externals(dumpbin, lib_path):
    """Extract defined external symbols from a static library using dumpbin."""
    defined, _, _ = _parse_symbols(dumpbin, lib_path)
    return defined



_TARGET_DIR_RE = re.compile(r"(zeek_[\w-]+|plugin-[\w-]+)\.dir$")


def _scan_obj_files(scan_dir):
    """Find all .obj files under zeek_* and plugin-* CMakeFiles target dirs.

    Uses os.walk with followlinks=False to avoid infinite recursion from
    symlinks (e.g. the scripts -> source symlink created by the plugin build).
    """
    result = []
    for dirpath, dirnames, filenames in os.walk(scan_dir, followlinks=False):

        parts = os.path.normpath(dirpath).split(os.sep)
        if any(_TARGET_DIR_RE.match(p) for p in parts):
            for fn in filenames:
                if fn.endswith(".obj"):
                    result.append(os.path.join(dirpath, fn))
    return result


def _should_export(sym):
    """Return True if a symbol should be exported to plugins/JIT DLLs.

    Uses a whitelist approach: only export symbols in namespaces that
    plugins actually use, plus a few special categories.
    """

    if sym.startswith("??_C@"):
        return False


    if sym.startswith("?main@@") or sym.startswith("?main@hilti@@"):
        return False


    if sym.startswith("??_G") or sym.startswith("??_E"):
        return False




    whitelisted_ns = [
        "@zeek@@",
        "@plugin@@",
        "@hilti@@",
        "@spicy@@",
        "@doctest@@",
        "@binpac@@",
    ]


    if (
        sym.startswith("zeek_")
        or sym.startswith("version")
        or sym.startswith("spicy_")
        or sym.startswith("hilti_")
    ):
        return True


    if any(ns in sym for ns in whitelisted_ns):

        if (
            "ZInst" in sym
            or "ZBody" in sym
            or "ZAMCompiler" in sym
            or "CPPCompile" in sym
        ):
            return False


        if any(
            ns in sym
            for ns in [
                "@SNMP@@",
                "@DNS@@",
                "@HTTP@@",
                "@FTP@@",
                "@SMTP@@",
                "@SSH@@",
                "@SSL@@",
                "@SMB@@",
                "@NTP@@",
                "@MQTT@@",
                "@Modbus@@",
                "@MySQL@@",
                "@IMAP@@",
                "@IRC@@",
                "@KRB@@",
                "@Ident@@",
                "@SOCKS@@",
                "@RDP@@",
                "@SIP@@",
                "@RADIUS@@",
                "@POP3@@",
                "@XMPP@@",
                "@GTPv1@@",
                "@NetBIOS@@",
                "@Teredo@@",
                "@VXLAN@@",
                "@SteppingStone@@",
                "@BackDoor@@",
                "@InterConn@@",
                "@ARP@@",
                "@DCE_RPC@@",
                "@Login@@",
                "@Rlogin@@",
                "@RSH@@",
                "@DHCP@@",
                "@DNP3@@",
                "@NCP@@",
                "@BitTorrent@@",
            ]
        ):
            return False



        if sym.startswith("??$"):
            return False
        return True



    if sym.startswith("??_R") or sym.startswith("??_7"):
        return False


    return False


def main():
    if len(sys.argv) < 4:
        print(
            f"Usage: {sys.argv[0]} <dumpbin> <output.def> <lib1> [lib2 ...] "
            f"[--scan-dir <dir>] [-- <backing1> ...]",
            file=sys.stderr,
        )
        sys.exit(1)

    dumpbin = sys.argv[1]
    output_def = sys.argv[2]
    rest = sys.argv[3:]


    scan_dirs = []
    filtered_rest = []
    i = 0
    while i < len(rest):
        if rest[i] == "--scan-dir" and i + 1 < len(rest):
            scan_dirs.append(rest[i + 1])
            i += 2
        else:
            filtered_rest.append(rest[i])
            i += 1
    rest = filtered_rest


    extra_files = []
    if scan_dirs:
        for scan_dir in scan_dirs:
            extra_files.extend(_scan_obj_files(scan_dir))
        print(
            f"  Scanned {len(extra_files)} obj files from {len(scan_dirs)} directories",
            file=sys.stderr,
        )


    if "--" in rest:
        sep = rest.index("--")
        primary_files = rest[:sep] + extra_files
        backing_files = rest[sep + 1 :]
    else:
        primary_files = rest + extra_files
        backing_files = []


    all_symbols = set()
    all_undefs = set()
    all_data_syms = set()
    for lib in primary_files:
        defined, undefined, data_syms = _parse_symbols(dumpbin, lib)
        print(
            f"  {lib}: {len(defined)} defined, {len(undefined)} undefined",
            file=sys.stderr,
        )
        all_symbols.update(defined)
        all_undefs.update(undefined)
        all_data_syms.update(data_syms)


    unresolved = all_undefs - all_symbols


    if backing_files and unresolved:
        backing_exported = 0
        for lib in backing_files:
            defined, undefined, data_syms = _parse_symbols(dumpbin, lib)
            resolved = defined & unresolved
            if resolved:
                all_symbols.update(resolved)
                all_data_syms.update(data_syms & resolved)
                unresolved -= resolved

                all_undefs.update(undefined)
                backing_exported += len(resolved)
        print(
            f"  Backing libs resolved {backing_exported} additional symbols",
            file=sys.stderr,
        )


    exported = {sym for sym in all_symbols if _should_export(sym)}
    exported_data = all_data_syms & exported





    crt_alloc_symbols = [
        "??2@YAPEAX_K@Z",
        "??_U@YAPEAX_K@Z",
        "??3@YAXPEAX@Z",
        "??3@YAXPEAX_K@Z",
        "??_V@YAXPEAX@Z",
        "??_V@YAXPEAX_K@Z",
    ]
    exported.update(crt_alloc_symbols)

    excluded_count = len(all_symbols) - len(exported)
    print(f"  Excluded {excluded_count} non-exportable symbols", file=sys.stderr)
    print(
        f"  Total unique symbols: {len(exported)} ({len(exported_data)} data)",
        file=sys.stderr,
    )

    if len(exported) > 65000:
        print(
            f"WARNING: {len(exported)} symbols may exceed COFF limit of 65535",
            file=sys.stderr,
        )

    with open(output_def, "w") as f:
        f.write("EXPORTS\n")
        for sym in sorted(exported):
            f.write(f"    {sym}\n")

    print(f"  Wrote {output_def}", file=sys.stderr)


if __name__ == "__main__":
    main()
