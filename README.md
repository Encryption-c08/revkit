<div align="center">

<img src="assets/logo.svg" alt="revkit" width="520"/>

**kernel memory RE tool - MCP server for AI agents**

![Platform](https://img.shields.io/badge/platform-Windows%2010%2F11-blue?style=flat-square)
![Arch](https://img.shields.io/badge/arch-x64-lightgrey?style=flat-square)
![Driver](https://img.shields.io/badge/driver-kernel%20mode-red?style=flat-square)
![MCP](https://img.shields.io/badge/protocol-MCP-blueviolet?style=flat-square)
![License](https://img.shields.io/badge/license-MIT-green?style=flat-square)

</div>

---

revkit is a Windows kernel-mode memory tool with a built-in [Model Context Protocol](https://modelcontextprotocol.io) server. It lets AI agents read and write process memory, disassemble code, parse PE headers, scan for patterns and strings, all from ring-0, bypassing the usual usermode restrictions.

Ships with a web-based UI built on WebView2.

<div align="center">
<img src="assets/ui.png" alt="revkit UI" width="800"/>
</div>

---

## what the driver does

The kernel driver (`revkit-driver.sys`) loads into ring-0 via kdmapper. It never touches the normal driver loading path (no INF, no service entry, no PatchGuard interaction). Once loaded it creates a device object (name derived from a compile-time seed, e.g. `\Device\7E4A9C3F`) that the usermode app communicates with over IOCTL.

From ring-0 it can:

- **Read process memory** - uses `MmCopyVirtualMemory` internally. No handle required, no `OpenProcess`, nothing visible in usermode. Works on protected processes (anti-cheat, DRM, system processes) that block `ReadProcessMemory`.

- **Write process memory** - two modes:
  - **Kernel copy** - `MmCopyVirtualMemory` into the target. Fast and reliable.
  - **Physical PTE write** - walks the page table manually, remaps the physical page, writes directly. The target process never sees a write operation. No dirty page flags, no exception, nothing logged. Use this when the target scans its own memory or has write guards.

- **Query virtual memory** - `ZwQueryVirtualMemory` from kernel context. Gets base, size, protection, type and state of any region in any process.

- **Self-unload** - a dedicated IOCTL sends the driver an unload signal. It removes the symlink, deletes the device, and exits cleanly without a reboot.

### what it can be used for

- **Game reverse engineering** - read memory from games with anti-cheat (BattlEye, EAC, Vanguard). Most anti-cheats only block usermode; kernel reads are invisible to them.
- **Malware analysis** - inspect a running malware sample without touching it from usermode. Read its heap, stack, loaded modules.
- **DRM research** - read memory regions of protected processes that deny all usermode handles.
- **Fuzzing / instrumentation** - inject values into a running process mid-execution to observe behaviour without modifying the binary on disk.
- **AI-assisted RE** - the whole point of the MCP layer. Let any agent drive the analysis. Ask it to find a function, follow a pointer chain, decode a struct, it calls the tools and gives you results in plain English.
- **Debugging without a debugger** - read process state from ring-0 when a debugger would be detected or is unavailable.

---

## features

- kernel read/write (ring-0, no handle needed)
- physical PTE stealth writes
- MCP HTTP server on localhost, any AI agent can connect
- web UI (WebView2 / Chromium) with real-time logs, activity graphs, write dialog
- x64 disassembler with full SSE/AVX opcode support
- PE parser - sections, exports, imports, full headers
- pattern scanner, value scanner, string scanner (ASCII + UTF-16)
- xref scanner - find all code that references an address
- pointer chain walker
- module list with base addresses and sizes

---

## requirements

| thing | notes |
|-------|-------|
| Windows 10 / 11 x64 | tested on Win11 22H2+ |
| Administrator | required for driver loading |
| Microsoft Edge / WebView2 | already on most machines, if not install the [WebView2 runtime](https://developer.microsoft.com/en-us/microsoft-edge/webview2/) |
| [kdmapper.exe](https://github.com/TheCruZ/kdmapper/releases) | place next to `revkit.exe` |

**No test signing required.** kdmapper loads the driver by exploiting a signed vulnerable Intel driver, bypassing Windows driver signature enforcement entirely. No bcdedit, no reboots, no BIOS changes.

---

## setup

### files you need

```
revkit.exe            - main application (web UI embedded inside)
revkit-driver.sys     - kernel driver (built from source)
kdmapper.exe          - driver loader (get from TheCruZ/kdmapper)
WebView2Loader.dll    - WebView2 bootstrap (included in release)
```

All files must be in the same folder. Run `revkit.exe` as Administrator. The driver loads automatically on startup.

### MCP config

Paste this into your AI agent's MCP config file (Cursor, Windsurf, or any MCP-compatible client).

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

Replace the path with wherever your `revkit.exe` lives. The agent will start revkit automatically when it needs it.

---

## tools reference

| tool | what it does |
|------|-------------|
| `process_attach` | attach to a process by name or PID |
| `process_detach` | detach from current process |
| `process_list` | list all running processes with PID and path |
| `process_status` | check current attach state |
| `module_list` | all loaded modules with base address and size |
| `module_find` | find a specific module by name |
| `module_info_full` | detailed PE info for a loaded module |
| `memory_read` | read bytes at an address, returns hex dump |
| `memory_write` | write bytes via kernel copy |
| `memory_write_physical` | write via PTE, stealth, leaves no trace |
| `memory_query` | query a single region (base, size, protect, type) |
| `memory_regions` | list all mapped regions in the process |
| `memory_scan` | scan for a byte pattern with wildcards |
| `value_scan` | scan for a typed value (float, int, etc.) |
| `string_scan` | scan for ASCII or UTF-16 strings |
| `xref_scan` | find all addresses that reference a given address |
| `pointer_chain` | walk a chain of offsets from a base address |
| `pe_info` | parse PE headers at an address |
| `pe_exports` | dump the export table |
| `pe_imports` | dump the import table |
| `pe_sections` | list PE sections with addresses and flags |
| `disassemble` | disassemble x64 instructions at an address |
| `disassemble_function` | disassemble a whole function body from a start address |

---

## example session

```
process_attach  ->  name: "target.exe"
module_list     ->  find "engine.dll" at 0x7FF800000000
memory_read     ->  address: 0x7FF800000000, size: 64
pe_exports      ->  address: 0x7FF800000000
disassemble     ->  address: 0x7FF800401234, count: 30
pointer_chain   ->  base: 0x7FF900000000, offsets: [0x10, 0x28, 0x8]
```

---

## dev section

### architecture

```
revkit.exe
+-- WebView2 window       (Chromium renders app.html)
|   +-- JS <-> C++ bridge (PostWebMessageAsString / addEventListener)
+-- HTTP server (:13338)  (JSON-RPC 2.0, MCP protocol)
|   +-- tool dispatch     (routes tool calls to handlers)
+-- driver backend
    +-- IOCTL client      (sends requests to \Device\7E4A9C3F)
    +-- fallback (RPM)    (ReadProcessMemory if driver not loaded)
```

### driver internals

The driver is a minimal kernel module with no WDF or WDM framework, just direct NT APIs.

**Entry point** - `DriverEntry` is called by kdmapper with `DriverObject == NULL` since kdmapper does not go through the normal driver init path. The driver detects this and calls `IoCreateDriver` manually to get a real DriverObject, then calls DriverEntry again with it.

**Device creation** - the device name is derived from a compile-time seed constant, producing a fixed hex string (`\Device\7E4A9C3F`). No plaintext device name appears in either binary. The usermode app derives the same name independently when it opens the device. If a stale device exists from a previous crash the symlink is deleted and recreated.

**IOCTL dispatch** - all ops go through one DeviceControl handler:

| IOCTL | operation |
|-------|-----------|
| attach | store target EPROCESS pointer |
| detach | release EPROCESS reference |
| read | `MmCopyVirtualMemory` from target |
| write | `MmCopyVirtualMemory` into target |
| query | `ZwQueryVirtualMemory` on target |
| unload | self-destruct, remove device + symlink |
| physical write | PTE remap + write |

**Physical write path** - `MmGetPhysicalAddress` to find the physical frame, temporarily maps it into kernel address space, writes the bytes, flushes TLB. The target process page tables are modified directly with no copy-on-write and no dirty bit from the target's perspective.

**Unload** - `DriverSelfUnload` deletes the symlink, derefs the EPROCESS, marks dispatch slots as `DeviceOffline` so in-flight IRPs do not crash, then returns. kdmapper handles the actual memory cleanup.

### MCP server

Minimal Winsock TCP server parsing raw HTTP/1.1, speaking [JSON-RPC 2.0](https://www.jsonrpc.org/specification) and following the [MCP spec](https://spec.modelcontextprotocol.io). Tools are registered at startup with a JSON schema describing their arguments. When a `tools/call` comes in it validates args, calls the handler, returns the result.

Runs on a background thread. All driver calls happen synchronously since reads are fast.

### string obfuscation

Sensitive strings (registry paths, export names) are encrypted at compile time using a 4-layer XOR scheme: three independent position-keyed streams plus a CBC-like diffusion pass using the previous plaintext byte as part of the key. The encrypted bytes sit in `.rdata`; decryption happens inline at the point of use via a `constexpr` template. The C driver uses an equivalent runtime XOR with the same key constants, so no sensitive strings appear in the binary in plaintext.

### UI bridge

WebView2 loads `app.html` from an embedded Windows resource (RCDATA). C++ pushes events to JS via `ICoreWebView2::PostWebMessageAsString` with a JSON payload. JS sends commands back via `window.chrome.webview.postMessage`. C++ to JS is one-way push for logs and status, JS to C++ is for user commands.

### adding a tool

1. Add the schema and handler in `src/mcp/tools/` (follow existing pattern)
2. Register it in `src/mcp/server.cpp`
3. Add a new IOCTL if it needs a new kernel op, or reuse existing ones

The handler receives a `nlohmann::json` args object and returns a `nlohmann::json` result. Errors are thrown as `std::runtime_error`.

### building from source

- Visual Studio 2019 or 2022 with MSVC v142 toolset
- Windows SDK 10.0.26100 or later
- Windows Driver Kit (WDK) matching your SDK - for the driver project only
- No other external dependencies (nlohmann/json and WebView2 SDK are vendored)

Open `revkit.sln`, set configuration to Release x64, build. Post-build automatically copies `WebView2Loader.dll`, `revkit-driver.sys`, and `kdmapper.exe` (from `tools/`) to `bin\Release\`. The UI (`app.html`) is embedded directly into the executable as an RCDATA resource — no separate file needed.

To rebuild the driver separately:

```bat
msbuild driver\revkit-driver.vcxproj /p:Configuration=Release /p:Platform=x64
```

---

## notes

- `memory_write_physical` modifies PTEs directly. Writing to the wrong address will bugcheck the system. Double check your target address.
- Always call `process_detach` before the target process exits. The driver holds an EPROCESS reference and if the process dies with it held you will BSOD on next access.
- The driver is unsigned but kdmapper handles that. No test signing needed.
- The device name is derived from a compile-time seed constant, so no static string like `\Device\RvKit` appears in the binary that AC signatures can match on. Still, nothing guarantees stealth against all kernel-level AC drivers.


