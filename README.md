<div align="center">

```
██████╗ ███████╗██╗   ██╗██╗  ██╗██╗████████╗
██╔══██╗██╔════╝██║   ██║██║ ██╔╝██║╚══██╔══╝
██████╔╝█████╗  ██║   ██║█████╔╝ ██║   ██║   
██╔══██╗██╔══╝  ╚██╗ ██╔╝██╔═██╗ ██║   ██║   
██║  ██║███████╗ ╚████╔╝ ██║  ██╗██║   ██║   
╚═╝  ╚═╝╚══════╝  ╚═══╝  ╚═╝  ╚═╝╚═╝   ╚═╝   
```

**kernel memory RE tool — MCP server for AI agents**

![Platform](https://img.shields.io/badge/platform-Windows%2010%2F11-blue?style=flat-square)
![Arch](https://img.shields.io/badge/arch-x64-lightgrey?style=flat-square)
![Driver](https://img.shields.io/badge/driver-kernel%20mode-red?style=flat-square)
![MCP](https://img.shields.io/badge/protocol-MCP-blueviolet?style=flat-square)
![License](https://img.shields.io/badge/license-MIT-green?style=flat-square)

</div>

---

revkit is a kernel-mode memory inspection tool that exposes a [Model Context Protocol](https://modelcontextprotocol.io) server so AI agents (Claude, GPT-4, Cursor, Windsurf, etc.) can read and write process memory, disassemble code, parse PE files, and scan strings — all from ring-0.

It ships with a clean web-based UI built on WebView2 and a kernel driver loaded via kdmapper.

<div align="center">
<img src="assets/ui.png" alt="revkit UI" width="800"/>
</div>

---

## features

- **kernel driver** — reads/writes memory from ring-0, bypasses most usermode protections
- **physical PTE writes** — stealth memory writes via page table manipulation
- **MCP server** — HTTP JSON-RPC on localhost, plug into any MCP-compatible AI agent
- **web UI** — real-time log, activity graphs, status panel, write memory dialog
- **disassembler** — x64 disassembly with full SSE/AVX support
- **PE parser** — sections, exports, imports, full module info
- **scanner** — pattern scan, value scan, string scan, xref scan, pointer chains

---

## requirements

- Windows 10 / 11 x64
- Admin rights
- Test signing enabled **or** secure boot off
- Microsoft Edge / WebView2 runtime (installed on most machines)
- [kdmapper](https://github.com/TheCruZ/kdmapper) — place `kdmapper.exe` in `tools/`

### enable test signing

```bat
bcdedit /set testsigning on
```

Reboot after. To undo: `bcdedit /set testsigning off`

---

## setup

```
revkit/
├── revkit.exe          — main app
├── revkit-driver.sys   — kernel driver
├── kdmapper.exe        — driver loader
├── WebView2Loader.dll  — WebView2 bootstrap
└── app.html            — web UI
```

1. Drop all files into the same folder
2. Run `revkit.exe` as **Administrator**
3. The driver loads automatically on startup

---

## MCP config

Add to your agent's MCP config (Claude Code, Cursor, Windsurf, etc.):

```json
{
  "mcpServers": {
    "revkit": {
      "command": "C:\\path\\to\\revkit.exe",
      "args": []
    }
  }
}
```

For Claude Code specifically: `~/.claude.json` or via `/mcp add`.

---

## tools

| tool | description |
|------|-------------|
| `process_attach` | attach to a process by name or PID |
| `process_detach` | detach |
| `process_list` | list all running processes |
| `process_status` | check current attach state |
| `module_list` | list all loaded modules |
| `module_find` | find a module by name |
| `module_info_full` | detailed module info |
| `memory_read` | read bytes at address |
| `memory_write` | write bytes (kernel copy) |
| `memory_write_physical` | write via PTE (stealth) |
| `memory_query` | query region info |
| `memory_regions` | list all memory regions |
| `memory_scan` | scan for byte pattern |
| `value_scan` | scan for typed value |
| `string_scan` | scan for ASCII/UTF-16 strings |
| `xref_scan` | find references to an address |
| `pointer_chain` | walk a pointer chain |
| `pe_info` | PE headers |
| `pe_exports` | export table |
| `pe_imports` | import table |
| `pe_sections` | section headers |
| `disassemble` | disassemble at address |

---

## example — attach and read

```
process_attach  →  { "name": "target.exe" }
module_list     →  find base address
memory_read     →  { "address": "0x...", "size": 64 }
disassemble     →  { "address": "0x...", "count": 20 }
```

---

## building

Requires Visual Studio 2019+ with MSVC v142, Windows SDK 10.0.

```bat
# open revkit.sln in Visual Studio
# build → Release x64
# output goes to bin/Release/
```

The post-build event auto-copies:
- `WebView2Loader.dll`
- `app.html`
- `revkit-driver.sys`
- `kdmapper.exe` (from `tools/` if present)

---

## how it works

```
revkit.exe
├── WebView2 window  ←  renders app.html (Chromium)
├── HTTP server      ←  MCP JSON-RPC on :13338
└── kernel driver    ←  loaded via kdmapper
       └── IOCTL bridge  ←  ring-0 memory r/w
```

AI agent connects to the MCP server → calls tools → revkit forwards to the kernel driver → reads/writes ring-0 → returns results to the agent.

---

## notes

- `memory_write_physical` modifies PTEs directly — use carefully
- Physics OverlapSphere and transform queries must be on the Unity main thread if targeting Unity games
- Detach before the target process exits to avoid driver state issues

---

<div align="center">
MIT license — use it, break it, improve it
</div>
