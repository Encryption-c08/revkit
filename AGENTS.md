# revkit — AI Agent Reference

revkit is a Windows kernel-mode memory reverse engineering server. It loads a signed kernel driver via kdmapper to read and write process memory from ring-0, then exposes every capability over a local MCP (Model Context Protocol) HTTP server. Any MCP-capable agent can attach to a live process and perform memory analysis without leaving the conversation.

---

## What revkit Does

- Loads `revkit-driver.sys` into the kernel at startup using kdmapper, bypassing DSE on test-signing or debug kernels
- Runs an MCP HTTP server on `http://localhost:13338`
- Provides structured tools for process inspection, memory I/O, PE analysis, disassembly, and pattern scanning
- Displays a Win32 dark-theme GUI showing live server status and tool call logs

All reads and writes go through the kernel driver, so they work on protected processes that block user-mode access (anti-cheat, system services, etc.).

---

## Requirements

- Windows 10 or Windows 11 (x64)
- Run as Administrator — driver loading requires SeLoadDriverPrivilege
- One of the following kernel modes:
  - **Test Signing enabled** — `bcdedit /set testsigning on` then reboot
  - **Kernel Debug mode** — attach WinDbg or set via `bcdedit /debug on`
  - Secure Boot must be **disabled** if using test signing

---

## Starting revkit

```
revkit.exe
```

Run from an elevated command prompt or right-click > "Run as administrator". The GUI window will appear and the MCP server starts automatically on port 13338. You will see a "Server running" status indicator in the GUI.

Do not close the GUI window while agents are using the server.

---

## MCP Configuration

Add revkit to your agent's MCP config. The server speaks standard MCP over HTTP.

### Cursor / Windsurf / any MCP client

```json
{
  "mcpServers": {
    "revkit": {
      "type": "http",
      "url": "http://localhost:13338"
    }
  }
}
```

### Cursor / Windsurf (`.cursor/mcp.json` or equivalent)

```json
{
  "mcpServers": {
    "revkit": {
      "url": "http://localhost:13338",
      "type": "http"
    }
  }
}
```

### Generic MCP client

Point the client at `http://localhost:13338`. No authentication required. The server uses standard MCP JSON-RPC over HTTP POST.

---

## Tool Reference

Always call `process_attach` before any other tool. All subsequent calls operate on the attached process until you call `process_detach`.

| Tool | Description |
|---|---|
| `process_attach` | Attach to a process by name or PID. Required before all other tools. |
| `process_detach` | Release the current process handle. Call when done. |
| `module_list` | List all loaded modules (DLLs/EXEs) in the attached process with their base addresses and sizes. |
| `module_find` | Find a single module by name, returns base address and size. |
| `memory_read` | Read bytes from a virtual address. Returns a hex dump. |
| `memory_write` | Write bytes to a virtual address. Takes address and hex-encoded payload. |
| `memory_regions` | Enumerate all committed virtual memory regions with protection flags and types. |
| `memory_query` | Query the VirtualQuery info for a single address (state, type, protection). |
| `memory_scan` | Scan a memory range for a byte pattern (supports wildcards). Returns matching addresses. |
| `disassemble` | Disassemble instructions at an address. Takes address and instruction count. |
| `disassemble_function` | Disassemble a whole function body from a start address until a terminating instruction. |
| `pe_info` | Return PE headers and metadata for a loaded module. |
| `pe_exports` | List all exports from a module by name and RVA. |
| `pe_imports` | List all imported functions and their source DLLs. |
| `pe_sections` | List PE sections with names, virtual addresses, sizes, and characteristics. |
| `string_scan` | Scan a module or address range for ASCII/Unicode strings above a minimum length. |
| `value_scan` | Scan memory for a specific integer or float value (useful for cheat table workflows). |
| `xref_scan` | Find all cross-references to a given address within a module or range. |
| `pointer_chain` | Follow a chain of pointer offsets from a base address, returns the resolved address at each step. |

---

## Common Workflows

### Attach to a game and read memory

```
1. process_attach(name="game.exe")
2. module_list()                          -- find the main module base address
3. memory_read(address=<base>, size=256)  -- read the first 256 bytes
4. process_detach()
```

### Find a function by pattern scan

```
1. process_attach(name="target.exe")
2. module_find(name="target.exe")         -- get base and size
3. memory_scan(
     start=<base>,
     size=<module_size>,
     pattern="48 8B 05 ?? ?? ?? ?? 48 85 C0"
   )                                      -- wildcard byte pattern scan
4. disassemble(address=<match>, count=20) -- confirm the match
5. process_detach()
```

### Disassemble code at an address

```
1. process_attach(name="target.exe")
2. disassemble(address=0x140001000, count=50)
   -- returns mnemonic, operands, and bytes for each instruction
3. process_detach()
```

### Walk a pointer chain

```
1. process_attach(name="game.exe")
2. module_find(name="game.exe")
3. pointer_chain(
     base=<module_base>,
     offsets=[0x01D3A8, 0x8, 0x120, 0x4]
   )
   -- follows: [[base + 0x01D3A8] + 0x8] + 0x120] + 0x4
   -- returns the resolved value and each intermediate address
4. process_detach()
```

### Find all strings in a module

```
1. process_attach(name="target.exe")
2. module_find(name="target.dll")
3. string_scan(
     start=<base>,
     size=<module_size>,
     min_length=6,
     encoding="both"     -- ASCII and Unicode
   )
4. process_detach()
```

---

## Tips

- **Always call `process_attach` first.** Every other tool will fail without an active attachment.
- **Use `module_list` to find base addresses.** Do not guess or hardcode addresses — ASLR means they change on every launch.
- **`memory_read` returns a hex dump.** Parse it as little-endian bytes for pointer reads (e.g., 8-byte addresses on x64).
- **`disassemble` takes an absolute virtual address and an instruction count**, not a byte count. Start with 20–50 instructions.
- **`pointer_chain` offsets are applied sequentially.** Each step dereferences the previous result then adds the next offset.
- **`memory_scan` supports `??` as a wildcard byte.** Patterns are space-separated hex bytes.
- **`value_scan` is slow on large ranges.** Narrow the range with `memory_regions` first to target heap or specific sections.
- **`xref_scan` searches for 4-byte relative references and 8-byte absolute references.** Use it to find callers of a function.
- **The kernel driver runs at ring-0**, so protected or anti-cheat guarded memory is readable. You do not need to disable protection separately.
- **Detach when done.** Leaving handles open across sessions can cause issues if the target process exits.

---

## Error Reference

| Error | Meaning |
|---|---|
| `ERR_NO_PROCESS` | No process is attached. Call `process_attach` first. |
| `ERR_INVALID_ADDRESS` | Address is not in a committed, accessible region. |
| `ERR_DRIVER_NOT_LOADED` | revkit-driver.sys failed to load. Check test signing and admin rights. |
| `ERR_PROCESS_NOT_FOUND` | No process matched the given name or PID. |
| `ERR_ACCESS_DENIED` | OS refused the operation despite driver load. Check integrity level. |
| `ERR_PATTERN_NOT_FOUND` | `memory_scan` completed the range with no matches. |
