#!/usr/bin/env python3
"""Trace a 4 KiB abc file page back to ark_disasm pandasm entries.

The tool consumes the textual output produced by ``ark_disasm`` and an abc file
``offset``.  It reports all disassembly objects whose encoded offset falls in
``[offset, offset + 4096]``.  The parser is intentionally conservative: object
kinds that carry explicit abc offsets in normal pandasm output (STRING and
LITERALS) are matched exactly, while METHOD/RECORD ownership is inferred from
names and references in the surrounding disassembly text.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Iterable, Optional

PAGE_SIZE = 4096
SECTION_RE = re.compile(r"^#\s+(LITERALS|RECORDS|METHODS|STRING)\s*$")
LITERAL_RE = re.compile(r"^\s*(?P<index>\d+)\s+(?P<offset>0x[0-9a-fA-F]+|\d+)\s+(?P<body>\{.*)$")
STRING_RE = re.compile(r"^\s*\[\s*offset\s*:\s*(?P<offset>0x[0-9a-fA-F]+|\d+)\s*,\s*name_value\s*:\s*(?P<value>.*)\]\s*$")
RECORD_RE = re.compile(r"^\s*\.record\s+(?P<name>[^\s<{]+)")
FUNCTION_RE = re.compile(r"^\s*\.function\s+(?P<ret>\S+)\s+(?P<name>[^\s(]+)\((?P<args>[^)]*)\)(?P<meta>.*)$")
REFERENCE_RE = re.compile(r"(?P<kind>method|string)\s*:\s*(?P<value>\"(?:\\.|[^\"])*\"|[^,\]\s}]+)")
MODULE_REQUEST_RE = re.compile(r"module_request\s*:\s*(?P<value>[^,;\]}]+)")
LOCAL_NAME_RE = re.compile(r"(?:local_name|export_name|import_name)\s*:\s*(?P<value>[^,;\]}]+)")


@dataclass
class Owner:
    package: Optional[str]
    record: Optional[str]
    method: Optional[str]


@dataclass
class Hexdump:
    file: str
    start: int
    end: int
    requested_size: int
    available_size: int
    truncated: bool
    text: str


@dataclass
class Entry:
    kind: str
    offset: int
    end_offset: Optional[int]
    line_start: int
    line_end: int
    owner: Owner
    summary: str
    text: str
    references: list[dict[str, str]] = field(default_factory=list)


def parse_int(value: str) -> int:
    return int(value, 16) if value.lower().startswith("0x") else int(value)


def infer_owner(name: str | None, text: str = "") -> Owner:
    source = name or text
    package = None
    record = None
    method = name

    method_ref = re.search(r"method\s*:\s*([^,\]\s}]+)", text)
    if name is None and method_ref:
        source = method_ref.group(1)
        method = source

    # Common ArkTS names look like pkg/path/Class.method or Class.method.
    before_colon = source.split(":", 1)[0]
    before_colon = before_colon.strip('"')
    if "." in before_colon:
        prefix, leaf = before_colon.rsplit(".", 1)
        method = leaf
        record = prefix
        if "/" in prefix:
            package = prefix.rsplit("/", 1)[0]
    elif "/" in before_colon:
        package, leaf = before_colon.rsplit("/", 1)
        record = leaf

    module = MODULE_REQUEST_RE.search(text)
    if module:
        package = module.group("value").strip(' "')
    return Owner(package=package, record=record, method=method)


def collect_references(text: str) -> list[dict[str, str]]:
    refs = [m.groupdict() for m in REFERENCE_RE.finditer(text)]
    for m in MODULE_REQUEST_RE.finditer(text):
        refs.append({"kind": "module_request", "value": m.group("value").strip()})
    for m in LOCAL_NAME_RE.finditer(text):
        refs.append({"kind": "module_name", "value": m.group("value").strip()})
    return refs


def parse_disassembly(lines: list[str]) -> list[Entry]:
    entries: list[Entry] = []
    section = None
    current_record: Optional[str] = None
    i = 0
    while i < len(lines):
        line = lines[i].rstrip("\n")
        sec = SECTION_RE.match(line)
        if sec:
            section = sec.group(1)
            i += 1
            continue

        if section == "RECORDS":
            rec = RECORD_RE.match(line)
            if rec:
                current_record = rec.group("name")

        if section == "LITERALS":
            lit = LITERAL_RE.match(line)
            if lit:
                start = i
                balance = line.count("{") - line.count("}")
                block = [line]
                while balance > 0 and i + 1 < len(lines):
                    i += 1
                    nxt = lines[i].rstrip("\n")
                    block.append(nxt)
                    balance += nxt.count("{") - nxt.count("}")
                text = "\n".join(block)
                entries.append(Entry(
                    kind="literal",
                    offset=parse_int(lit.group("offset")),
                    end_offset=None,
                    line_start=start + 1,
                    line_end=i + 1,
                    owner=infer_owner(None, text),
                    summary=f"literal #{lit.group('index')}",
                    text=text,
                    references=collect_references(text),
                ))
        elif section == "STRING":
            sm = STRING_RE.match(line)
            if sm:
                value = sm.group("value")
                entries.append(Entry(
                    kind="string",
                    offset=parse_int(sm.group("offset")),
                    end_offset=None,
                    line_start=i + 1,
                    line_end=i + 1,
                    owner=infer_owner(None, value),
                    summary=value,
                    text=line,
                    references=[],
                ))
        elif section == "METHODS":
            fm = FUNCTION_RE.match(line)
            if fm:
                start = i
                depth = line.count("{") - line.count("}")
                block = [line]
                while depth > 0 and i + 1 < len(lines):
                    i += 1
                    nxt = lines[i].rstrip("\n")
                    block.append(nxt)
                    depth += nxt.count("{") - nxt.count("}")
                text = "\n".join(block)
                # Methods have no mandatory file offset in the documented
                # ark_disasm text, so attach them as provenance only when they
                # reference a matched object later.
                entries.append(Entry(
                    kind="method_context",
                    offset=-1,
                    end_offset=None,
                    line_start=start + 1,
                    line_end=i + 1,
                    owner=infer_owner(fm.group("name"), text),
                    summary=fm.group("name"),
                    text=text,
                    references=collect_references(text),
                ))
        i += 1
    return entries


def read_abc_hexdump(abc: Path, start: int, size: int) -> Hexdump:
    if start < 0:
        raise ValueError("offset must be non-negative")
    if size < 0:
        raise ValueError("size must be non-negative")

    with abc.open("rb") as f:
        f.seek(0, 2)
        file_size = f.tell()
        f.seek(min(start, file_size))
        data = f.read(size)

    lines = []
    for row_start in range(0, len(data), 16):
        chunk = data[row_start:row_start + 16]
        hex_bytes = " ".join(f"{b:02x}" for b in chunk)
        ascii_bytes = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        lines.append(f"{start + row_start:08x}  {hex_bytes:<47}  |{ascii_bytes}|")

    end = start + len(data)
    return Hexdump(
        file=str(abc),
        start=start,
        end=end,
        requested_size=size,
        available_size=len(data),
        truncated=len(data) < size,
        text="\n".join(lines),
    )


def page_entries(entries: Iterable[Entry], start: int, size: int) -> list[Entry]:
    end = start + size
    return [e for e in entries if e.offset >= 0 and start <= e.offset <= end]


def attach_method_context(matches: list[Entry], entries: list[Entry]) -> None:
    methods = [e for e in entries if e.kind == "method_context"]
    for match in matches:
        value = match.summary.strip('"')
        contexts = []
        for method in methods:
            if value and value in method.text:
                contexts.append(asdict(method.owner))
        if contexts:
            match.references.append({"kind": "method_context", "value": json.dumps(contexts, ensure_ascii=False)})


def render_text(matches: list[Entry], start: int, size: int, hexdump: Optional[Hexdump] = None) -> str:
    end = start + size
    out = [f"Page range: [0x{start:x}, 0x{end:x}] ({start}..{end})", f"Matched entries: {len(matches)}"]
    if hexdump is not None:
        out.extend([
            "",
            f"ABC file: {hexdump.file}",
            f"ABC bytes read: {hexdump.available_size}/{hexdump.requested_size}" + (" (truncated at EOF)" if hexdump.truncated else ""),
            "ABC hexdump:",
        ])
        if hexdump.text:
            out.extend(f"  {line}" for line in hexdump.text.splitlines())
        else:
            out.append("  <no bytes available in requested range>")

    for e in matches:
        owner = ", ".join(f"{k}={v}" for k, v in asdict(e.owner).items() if v) or "unknown"
        out.append("")
        out.append(f"- {e.kind} @ 0x{e.offset:x}, lines {e.line_start}-{e.line_end}, owner: {owner}")
        out.append(f"  summary: {e.summary}")
        if e.references:
            out.append("  references: " + json.dumps(e.references, ensure_ascii=False))
        out.append("  source:")
        out.extend(f"    {line}" for line in e.text.splitlines())
    return "\n".join(out)


def main(argv: Optional[list[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Trace a 4 KiB abc page in ark_disasm output.")
    parser.add_argument("offset", help="page start offset, decimal or hex such as 0x1000")
    parser.add_argument("disasm", type=Path, help="ark_disasm pandasm text file")
    parser.add_argument("abc", nargs="?", type=Path, help="optional abc file; when provided, dump the requested byte range for cross-checking")
    parser.add_argument("--size", type=lambda v: parse_int(v), default=PAGE_SIZE, help="range size, default 4096")
    parser.add_argument("--json", action="store_true", help="emit JSON instead of text")
    parser.add_argument("--hexdump-out", type=Path, help="write the abc range hexdump to this file")
    args = parser.parse_args(argv)

    start = parse_int(args.offset)
    hexdump = read_abc_hexdump(args.abc, start, args.size) if args.abc else None
    if hexdump is not None and args.hexdump_out:
        args.hexdump_out.write_text(hexdump.text + ("\n" if hexdump.text else ""), encoding="utf-8")

    lines = args.disasm.read_text(encoding="utf-8", errors="replace").splitlines()
    entries = parse_disassembly(lines)
    matches = page_entries(entries, start, args.size)
    attach_method_context(matches, entries)
    if args.json:
        print(json.dumps({"range": {"start": start, "end": start + args.size}, "hexdump": asdict(hexdump) if hexdump else None, "entries": [asdict(e) for e in matches]}, ensure_ascii=False, indent=2))
    else:
        print(render_text(matches, start, args.size, hexdump))
    return 0


if __name__ == "__main__":
    sys.exit(main())
