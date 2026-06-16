#!/usr/bin/env python3
"""Convert ark_disasm pandasm text into structured module/method JSON.

The script reads the textual disassembly produced by ``ark_disasm`` and emits a
compact JSON view of modules and their methods.  It is intentionally tolerant of
small pandasm format differences: ids are taken from explicit decimal/hex
metadata when present, and otherwise from stable synthetic ids derived from the
source line number.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Optional

SECTION_RE = re.compile(r"^#\s+(LITERALS|RECORDS|METHODS|STRING)\s*$")
RECORD_RE = re.compile(r"^\s*\.record\s+(?P<name>[^\s<{]+)")
FUNCTION_RE = re.compile(r"^\s*\.function\s+(?P<ret>\S+)\s+(?P<name>[^\s(]+)\((?P<args>[^)]*)\)(?P<meta>.*)$")
STRING_RE = re.compile(r"^\s*\[\s*offset\s*:\s*(?P<offset>0x[0-9a-fA-F]+|\d+)\s*,\s*name_value\s*:\s*(?P<value>.*)\]\s*$")
OFFSET_RE = re.compile(r"(?:^|[\s,;{\[])(?:id|method_id|offset|method_offset)\s*[:=]\s*(?P<value>0x[0-9a-fA-F]+|\d+)")
SIZE_RE = re.compile(r"(?:^|[\s,;{\[])(?:code_size|method_size|size)\s*[:=]\s*(?P<value>0x[0-9a-fA-F]+|\d+)")
LINE_NUMBER_RE = re.compile(r"\b(?P<value>0x[0-9a-fA-F]+|\d+)\b")
CALL_RE = re.compile(r"\b(?:call|call\.|definefunc|definemethod|createobjectwithbuffer|newlexenvwithname)\b[^\n]*?(?P<name>[#~@\w$&./<>*=:-]+)")
QUOTED_METHOD_RE = re.compile(r"method\s*:\s*\"(?P<name>[^\"]+)\"")


def parse_int(value: str) -> int:
    return int(value, 16) if value.lower().startswith("0x") else int(value)


def stable_line_id(line_number: int) -> int:
    # Negative ids make synthesized values obvious while staying deterministic.
    return -line_number


@dataclass
class MethodInfo:
    id: int
    name: str
    pid: int = 0
    refs: list[int] = field(default_factory=list)
    size: int = 0
    tag: str = "Func"
    line_start: int = 0
    line_end: int = 0


@dataclass
class ModuleInfo:
    id: int
    name: str
    methods: list[MethodInfo] = field(default_factory=list)


def extract_first_int(text: str, regex: re.Pattern[str]) -> Optional[int]:
    match = regex.search(text)
    return parse_int(match.group("value")) if match else None


def strip_method_name(name: str) -> str:
    return name.strip().strip('"')


def infer_module_name(method_name: str, current_record: Optional[str]) -> str:
    if current_record:
        return current_record
    name = strip_method_name(method_name)
    if "." in name:
        return name.rsplit(".", 1)[0]
    return "<unknown>"


def infer_short_method_name(method_name: str, module_name: str) -> str:
    name = strip_method_name(method_name)
    prefix = module_name + "."
    if module_name != "<unknown>" and name.startswith(prefix):
        return name[len(prefix):]
    return name.rsplit(".", 1)[-1] if "." in name else name


def parse_methods(lines: list[str]) -> dict[str, ModuleInfo]:
    modules: dict[str, ModuleInfo] = {}
    string_offsets: dict[str, int] = {}
    section: Optional[str] = None
    current_record: Optional[str] = None
    methods_by_name: dict[str, MethodInfo] = {}
    method_blocks: dict[int, str] = {}

    i = 0
    while i < len(lines):
        line = lines[i].rstrip("\n")
        sec = SECTION_RE.match(line)
        if sec:
            section = sec.group(1)
            i += 1
            continue

        if section == "STRING":
            sm = STRING_RE.match(line)
            if sm:
                string_offsets[sm.group("value").strip().strip('"')] = parse_int(sm.group("offset"))
        elif section == "RECORDS":
            rec = RECORD_RE.match(line)
            if rec:
                current_record = rec.group("name")
                modules.setdefault(current_record, ModuleInfo(id=string_offsets.get(current_record, stable_line_id(i + 1)), name=current_record))
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
                full_name = strip_method_name(fm.group("name"))
                module_name = infer_module_name(full_name, current_record)
                module = modules.setdefault(module_name, ModuleInfo(id=string_offsets.get(module_name, stable_line_id(start + 1)), name=module_name))
                explicit_id = extract_first_int(line + "\n" + "\n".join(block[:3]), OFFSET_RE)
                method_id = explicit_id if explicit_id is not None else string_offsets.get(full_name, stable_line_id(start + 1))
                size = extract_first_int(line, SIZE_RE)
                if size is None:
                    insns = [b for b in block[1:-1] if b.strip() and not b.lstrip().startswith("#")]
                    size = len(insns)
                method = MethodInfo(
                    id=method_id,
                    name=infer_short_method_name(full_name, module_name),
                    size=size,
                    line_start=start + 1,
                    line_end=i + 1,
                )
                module.methods.append(method)
                methods_by_name[full_name] = method
                methods_by_name[method.name] = method
                method_blocks[method.id] = text
        i += 1

    # Resolve method references after all methods are known.
    for module in modules.values():
        main = next((m for m in module.methods if m.name == "func_main_0"), None)
        for method in module.methods:
            text = method_blocks.get(method.id, "")
            refs: list[int] = []
            for matcher in (CALL_RE.finditer(text), QUOTED_METHOD_RE.finditer(text)):
                for match in matcher:
                    name = strip_method_name(match.group("name"))
                    target = methods_by_name.get(name) or methods_by_name.get(infer_short_method_name(name, module.name))
                    if target and target.id != method.id and target.id not in refs:
                        refs.append(target.id)
            method.refs = refs
        # A practical default for ArkTS nested/generated functions: methods that
        # are not referenced by another method are children of func_main_0.
        if main:
            referenced = {rid for m in module.methods for rid in m.refs}
            for method in module.methods:
                if method.id != main.id and method.pid == 0:
                    parent = next((m for m in module.methods if method.id in m.refs), None)
                    method.pid = parent.id if parent else main.id
                    if parent is None and method.id not in main.refs and method.id not in referenced:
                        main.refs.append(method.id)
    return modules


def main(argv: Optional[list[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Parse ark_disasm methods into structured module JSON.")
    parser.add_argument("disasm", type=Path, help="ark_disasm pandasm text file")
    parser.add_argument("-o", "--output", type=Path, help="write JSON to this file instead of stdout")
    args = parser.parse_args(argv)

    lines = args.disasm.read_text(encoding="utf-8", errors="replace").splitlines()
    data = {"modules": [asdict(m) for m in parse_methods(lines).values()]}
    payload = json.dumps(data, ensure_ascii=False, indent=4)
    if args.output:
        args.output.write_text(payload + "\n", encoding="utf-8")
    else:
        print(payload)
    return 0


if __name__ == "__main__":
    sys.exit(main())
