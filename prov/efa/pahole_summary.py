#!/usr/bin/env python3
"""Run pahole over EFA provider object files and summarize results."""

import subprocess
import re
import os
import sys

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
EFA_SRC = os.path.join(SCRIPT_DIR, "src")


def find_object_files(path):
    result = []
    for root, _, files in os.walk(path):
        if ".libs" in root:
            continue
        for f in files:
            if f.endswith(".o"):
                result.append(os.path.join(root, f))
    return sorted(result)


def run_pahole(obj_files):
    """Run pahole on each file individually to avoid early-exit on bad files."""
    output = []
    for f in obj_files:
        try:
            r = subprocess.run(
                ["pahole", f],
                capture_output=True, text=True, timeout=30
            )
            if r.stdout:
                output.append(r.stdout)
        except subprocess.TimeoutExpired:
            print(f"  Timeout on {f}", file=sys.stderr)
    return "\n".join(output)


def parse_structs(output):
    structs = {}
    lines = output.splitlines()
    i = 0
    while i < len(lines):
        line = lines[i]
        m = re.match(r'^(struct|union)\s+(\w+)\s*\{', line)
        if m:
            name = m.group(2)
            block = [line]
            i += 1
            while i < len(lines):
                block.append(lines[i])
                if re.match(r'^\}', lines[i]):
                    break
                i += 1
            raw = "\n".join(block)
            if name not in structs or len(raw) > len(structs[name]["raw"]):
                structs[name] = parse_struct_info(name, raw)
        i += 1
    return structs


def parse_struct_info(name, raw):
    info = {
        "name": name,
        "raw": raw,
        "size": 0,
        "cachelines": 0,
        "members": 0,
        "holes": 0,
        "sum_holes": 0,
        "padding": 0,
        "sum_padding": 0,
        "forced_holes": 0,
        "sum_forced_holes": 0,
    }
    for pattern, key in [
        (r'size:\s*(\d+)', "size"),
        (r'cachelines:\s*(\d+)', "cachelines"),
        (r'members:\s*(\d+)', "members"),
        (r'\bholes:\s*(\d+)', "holes"),
        (r'sum holes:\s*(\d+)', "sum_holes"),
        (r'\bpadding:\s*(\d+)', "padding"),
        (r'sum paddings:\s*(\d+)', "sum_padding"),
        (r'forced holes:\s*(\d+)', "forced_holes"),
        (r'sum forced holes:\s*(\d+)', "sum_forced_holes"),
    ]:
        m = re.search(pattern, raw)
        if m:
            info[key] = int(m.group(1))

    info["total_wasted"] = (info["sum_holes"] - info["sum_forced_holes"]
                            + info["padding"] + info["sum_padding"])
    return info


def is_efa_struct(name):
    return name.startswith("efa_")


def print_table(title, structs, sort_key, limit=20):
    print(f"\n{'=' * 78}")
    print(f" {title}")
    print(f"{'=' * 78}")
    sorted_list = sorted(structs, key=lambda s: s[sort_key], reverse=True)
    print(f"  {'Struct':<45} {'Size':>6} {'Holes':>6} {'Wasted':>7} {'CL':>4}")
    print(f"  {'-'*45} {'-'*6} {'-'*6} {'-'*7} {'-'*4}")
    count = 0
    for s in sorted_list:
        if s[sort_key] == 0:
            break
        print(f"  {s['name']:<45} {s['size']:>6} {s['holes']:>6} "
              f"{s['total_wasted']:>7} {s['cachelines']:>4}")
        count += 1
        if count >= limit:
            break


def print_hole_details(structs):
    print(f"\n{'=' * 78}")
    print(f" Hole Details (EFA structs with wasted bytes)")
    print(f"{'=' * 78}")
    efa = [s for s in structs if is_efa_struct(s["name"]) and s["total_wasted"] > 0]
    efa.sort(key=lambda s: s["total_wasted"], reverse=True)
    for s in efa[:15]:
        print(f"\n  {s['name']} (size={s['size']}, holes={s['holes']}, "
              f"wasted={s['total_wasted']}B)")
        for line in s["raw"].splitlines():
            if "XXX" in line and "hole" in line:
                print(f"    {line.strip()}")
            elif "padding" in line and "/*" in line and "sum" not in line.lower():
                print(f"    {line.strip()}")


def main():
    obj_files = find_object_files(EFA_SRC)
    if not obj_files:
        print(f"No .o files found in {EFA_SRC}. Build with -g first.", file=sys.stderr)
        sys.exit(1)

    print(f"Scanning {len(obj_files)} object files in {EFA_SRC}...")
    output = run_pahole(obj_files)
    structs = parse_structs(output)
    all_structs = list(structs.values())
    efa_structs = [s for s in all_structs if is_efa_struct(s["name"])]

    print(f"\nTotal structs found: {len(all_structs)}")
    print(f"EFA-specific structs: {len(efa_structs)}")
    with_holes = [s for s in efa_structs if s["holes"] > 0]
    print(f"EFA structs with holes: {len(with_holes)}")
    total_wasted = sum(s["total_wasted"] for s in efa_structs)
    print(f"Total wasted bytes in EFA structs: {total_wasted}")

    print_table("Largest EFA Structs", efa_structs, "size")
    print_table("Most Holes (EFA)", efa_structs, "holes")
    print_table("Most Wasted Bytes (EFA)", efa_structs, "total_wasted")
    print_table("Largest All Structs", all_structs, "size", limit=25)
    print_table("Most Wasted Bytes (All)", all_structs, "total_wasted", limit=25)
    print_hole_details(all_structs)


if __name__ == "__main__":
    main()
