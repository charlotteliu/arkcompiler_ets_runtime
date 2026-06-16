# ark_disasm page trace utility

`ark_disasm_page_trace.py` 用于把 abc 文件中的一个偏移范围和 `ark_disasm` 生成的 pandasm 文本进行对照分析。默认分析范围为从输入偏移开始的 4 KiB 页面，也可以通过 `--size` 指定其它范围。

## 功能

- 解析 `ark_disasm` 文本中的 `# STRING` 和 `# LITERALS` 段，找出落在目标偏移范围内的 string/literal 条目。
- 从 `# METHODS` 段中收集方法上下文；当匹配到的 string/literal 被方法引用时，在输出中附带该方法上下文，帮助定位所属包、record 或方法。
- 可选读取原始 abc 文件，在同一个偏移范围内生成 hex + ASCII 形式的 hexdump，用于和 disasm 解析结果交叉验证。
- 当 disasm 没有找到对应 symbol 或 string 时，可以通过保存 4 KiB hexdump 继续做离线分析。
- 支持文本输出和 JSON 输出，便于人工排查或接入自动化分析流程。

## 基本用法

```bash
python3 ark_disasm_page_trace.py <offset> <disasm.txt> [abc-file] [options]
```

参数说明：

- `<offset>`：待分析范围的起始偏移，支持十进制或十六进制，例如 `4096` 或 `0x1000`。
- `<disasm.txt>`：`ark_disasm` 生成的 pandasm 文本文件。
- `[abc-file]`：可选的原始 abc 文件。提供后，脚本会从该文件读取同一偏移范围并输出 hexdump。

常用选项：

- `--size <size>`：分析范围大小，支持十进制或十六进制，默认 `4096` 字节。
- `--json`：以 JSON 格式输出结果。
- `--hexdump-out <file>`：把 abc 文件中该偏移范围的 hexdump 单独写入指定文件，便于后续保存和分析。

## 示例

### 只根据 disasm 文本查找偏移范围内的条目

```bash
python3 ark_disasm_page_trace.py 0x1000 app.disasm.txt
```

该命令会输出 `[0x1000, 0x2000]` 范围内从 disasm 文本解析出的 string/literal 条目，以及可能关联到的方法上下文。

### 同时读取 abc 文件并输出 4 KiB hexdump

```bash
python3 ark_disasm_page_trace.py 0x1000 app.disasm.txt app.abc
```

该命令除了输出 disasm 匹配项，还会读取 `app.abc` 中从 `0x1000` 开始的 4 KiB 字节，并以如下形式展示：

```text
00001000  12 34 56 78 ...  |.4Vx...|
```

这可以用于确认 disasm 中记录的偏移是否真的对应 abc 文件中的原始内容。

### 保存 hexdump 供进一步分析

```bash
python3 ark_disasm_page_trace.py 0x1000 app.disasm.txt app.abc --hexdump-out page_0x1000.hex
```

当 disasm 没有找到匹配 symbol/string，或者需要把现场数据交给其它工具继续分析时，可以使用该选项保存当前页面的 hexdump。

### 输出 JSON

```bash
python3 ark_disasm_page_trace.py 0x1000 app.disasm.txt app.abc --json
```

JSON 输出包含：

- `range`：本次分析的起止偏移。
- `hexdump`：abc 文件读取结果；如果没有传入 abc 文件则为 `null`。
- `entries`：disasm 中匹配到的 string/literal 条目及其引用信息。

## 推荐分析流程

1. 使用目标偏移、disasm 文本和原始 abc 文件运行脚本。
2. 先查看 `Matched entries`，确认 disasm 是否在该范围内解析到 string/literal。
3. 对照 `ABC hexdump` 中的原始字节，确认偏移、内容和 disasm 输出是否一致。
4. 如果没有匹配项，使用 `--hexdump-out` 保存 4 KiB hexdump，后续结合 abc 格式、其它符号信息或二进制分析工具继续排查。

## 方法结构化 JSON 导出

`ark_disasm_methods_to_json.py` 用于把 `ark_disasm` 生成的 pandasm 文本转换为按模块聚合的方法结构化 JSON。输出结构以 `modules` 为根节点，每个 module 包含模块 `id`、`name` 和 `methods`；每个 method 包含 `id`、`name`、`pid`、`refs`、`size`、`tag`，并额外保留 `line_start`/`line_end` 方便回溯到原始反汇编文件。

```bash
python3 ark_disasm_methods_to_json.py app.disasm.txt -o methods.json
```

字段说明：

- `id`：优先读取反汇编文本中显式的 `id`、`method_id`、`offset` 或 `method_offset`；没有显式值时使用稳定的负数行号作为合成 id。
- `pid`：解析到调用/定义关系时指向父方法 id；对 ArkTS 常见的生成函数，默认把未显式归属的非 `func_main_0` 方法挂到同模块的 `func_main_0` 下。
- `refs`：方法体中可解析到的其它方法引用 id。
- `size`：优先读取显式的 `size`、`code_size` 或 `method_size`；没有显式值时按方法体中的有效指令行数估算。
- `line_start`/`line_end`：方法在输入反汇编文本中的 1-based 行号，便于人工复核。

示例输出：

```json
{
    "modules": [
        {
            "id": 256,
            "name": "Lmod;",
            "methods": [
                {
                    "id": 272,
                    "name": "func_main_0",
                    "pid": 0,
                    "refs": [288],
                    "size": 2,
                    "tag": "Func",
                    "line_start": 8,
                    "line_end": 10
                }
            ]
        }
    ]
}
```
