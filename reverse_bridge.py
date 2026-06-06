"""
reverse_bridge.py  —  MCP stdio bridge for revkit

Architecture (same pattern as ida-mcp):
    Claude Code  ──stdio──>  reverse_bridge.py  ──HTTP──>  revkit.exe

Usage:
    python reverse_bridge.py [--port 13338]

Add to Claude Code settings (~/.claude/settings.json):
    "revkit": {
      "command": "C:\\Program Files\\Python311\\python.exe",
      "args": ["C:\\Users\\token\\Desktop\\Utility\\claude-reverse\\reverse_bridge.py",
               "--port", "13338"]
    }

Requires:
    pip install mcp
"""

import argparse
import asyncio
import json
import sys
import urllib.request
import urllib.error
from mcp.server import Server
from mcp import types
import mcp.server.stdio

# ── args ─────────────────────────────────────────────────────────────────────

parser = argparse.ArgumentParser(description="revkit MCP bridge")
parser.add_argument("--port", type=int, default=13338)
args = parser.parse_args()

# ── HTTP client ───────────────────────────────────────────────────────────────

class ReverseClient:
    def __init__(self, port: int):
        self.base = f"http://127.0.0.1:{port}"
        self._id  = 0

    def call(self, method: str, **params):
        self._id += 1
        payload = json.dumps({
            "jsonrpc": "2.0",
            "id":      self._id,
            "method":  method,
            "params":  params or {},
        }).encode()
        req = urllib.request.Request(
            self.base,
            data=payload,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=30) as resp:
                data = json.loads(resp.read())
        except urllib.error.URLError as e:
            raise ConnectionError(
                f"Cannot reach revkit on port {args.port}: {e}\n"
                f"Make sure revkit.exe is running before using these tools."
            )
        if "error" in data:
            raise RuntimeError(data["error"].get("message", str(data["error"])))
        return data.get("result")

reverse = ReverseClient(args.port)

# ── tool schemas (hardcoded so tools show up even before exe starts) ──────────

TOOLS = [
    types.Tool(name="process_list",    description="List all running processes",
               inputSchema={"type":"object","properties":{},"required":[]}),
    types.Tool(name="process_attach",  description="Attach to a process by PID or name",
               inputSchema={"type":"object","properties":{"pid":{"type":"integer","description":"Process ID"},"name":{"type":"string","description":"Process name"}},"required":[]}),
    types.Tool(name="process_detach",  description="Detach from the current process",
               inputSchema={"type":"object","properties":{},"required":[]}),
    types.Tool(name="process_status",  description="Get current attach status",
               inputSchema={"type":"object","properties":{},"required":[]}),
    types.Tool(name="module_list",     description="List modules in the attached process",
               inputSchema={"type":"object","properties":{},"required":[]}),
    types.Tool(name="module_find",     description="Find a module by name in the attached process",
               inputSchema={"type":"object","properties":{"name":{"type":"string","description":"Module name"}},"required":["name"]}),
    types.Tool(name="module_info_full",description="Get comprehensive module info: PE header, sections, exports, imports, and memory regions",
               inputSchema={"type":"object","properties":{"module":{"type":"string","description":"Module name"},"base":{"type":"string","description":"Base address (hex)"}},"required":[]}),
    types.Tool(name="memory_read",     description="Read memory from the attached process",
               inputSchema={"type":"object","properties":{"address":{"type":"string","description":"Address (hex string)"},"size":{"type":"integer","description":"Number of bytes to read"},"format":{"type":"string","enum":["hexdump","hex","base64"],"default":"hexdump","description":"Output format"}},"required":["address","size"]}),
    types.Tool(name="memory_write_physical", description="Write bytes directly to physical RAM via PTE manipulation — most stealthy write method, bypasses all kernel API monitoring",
               inputSchema={"type":"object","properties":{"address":{"type":"string","description":"Target virtual address (hex)"},"bytes":{"type":"string","description":"Hex bytes e.g. \"C8 00 00 00\""}},"required":["address","bytes"]}),
    types.Tool(name="memory_write",    description="Write bytes to process memory",
               inputSchema={"type":"object","properties":{"address":{"type":"string","description":"Target address (hex string)"},"bytes":{"type":"string","description":"Hex bytes e.g. \"48 8B C0\" or \"488BC0\""}},"required":["address","bytes"]}),
    types.Tool(name="memory_query",    description="Query a memory region at the given address",
               inputSchema={"type":"object","properties":{"address":{"type":"string","description":"Address to query"}},"required":["address"]}),
    types.Tool(name="memory_regions",  description="Enumerate committed memory regions in the attached process",
               inputSchema={"type":"object","properties":{"filter":{"type":"string","enum":["all","image","mapped","private"],"default":"all","description":"Filter by region type"}},"required":[]}),
    types.Tool(name="memory_scan",     description="Scan process memory for a byte pattern (IDA-style, ?? wildcards)",
               inputSchema={"type":"object","properties":{"pattern":{"type":"string","description":"IDA pattern e.g. \"48 8B ?? 05 ??\""},"start":{"type":"string","description":"Start address for range scan"},"size":{"type":"integer","description":"Size for range scan"},"max_results":{"type":"integer","default":50,"description":"Max matches to return"}},"required":["pattern"]}),
    types.Tool(name="pointer_chain",   description="Resolve a multi-level pointer chain",
               inputSchema={"type":"object","properties":{"base":{"type":"string","description":"Base address"},"offsets":{"type":"array","items":{"type":"integer"},"description":"Array of integer offsets"}},"required":["base","offsets"]}),
    types.Tool(name="value_scan",      description="Scan process memory for a specific integer or float value",
               inputSchema={"type":"object","properties":{"value":{"type":"number","description":"Value to scan for"},"type":{"type":"string","enum":["i32","u32","i64","u64","f32","f64"],"default":"i32","description":"Value type"},"max_results":{"type":"integer","default":256,"description":"Max results to return"}},"required":["value"]}),
    types.Tool(name="string_scan",     description="Scan a memory region for printable strings",
               inputSchema={"type":"object","properties":{"address":{"type":"string","description":"Start address"},"size":{"type":"integer","description":"Region size in bytes"},"min_len":{"type":"integer","default":8,"description":"Minimum string length"},"encoding":{"type":"string","enum":["ascii","utf16","both"],"default":"both","description":"String encoding to scan for"}},"required":["address","size"]}),
    types.Tool(name="pe_info",         description="Read PE header information from a loaded module",
               inputSchema={"type":"object","properties":{"module":{"type":"string","description":"Module name"},"base":{"type":"string","description":"Base address (hex)"}},"required":[]}),
    types.Tool(name="pe_exports",      description="Read PE export table from a loaded module",
               inputSchema={"type":"object","properties":{"module":{"type":"string","description":"Module name"},"base":{"type":"string","description":"Base address (hex)"}},"required":[]}),
    types.Tool(name="pe_imports",      description="Read PE import table from a loaded module",
               inputSchema={"type":"object","properties":{"module":{"type":"string","description":"Module name"},"base":{"type":"string","description":"Base address (hex)"}},"required":[]}),
    types.Tool(name="pe_sections",     description="List PE sections from a loaded module",
               inputSchema={"type":"object","properties":{"module":{"type":"string","description":"Module name"},"base":{"type":"string","description":"Base address (hex)"}},"required":[]}),
    types.Tool(name="disassemble",     description="Disassemble instructions at an address in the attached process",
               inputSchema={"type":"object","properties":{"address":{"type":"string","description":"Start address (hex)"},"count":{"type":"integer","default":20,"description":"Number of instructions to disassemble"}},"required":["address"]}),
    types.Tool(name="xref_scan",       description="Scan process memory for references (call/jmp/lea) to a target address",
               inputSchema={"type":"object","properties":{"address":{"type":"string","description":"Target address to find references to"},"module":{"type":"string","description":"Limit scan to this module name"},"max_results":{"type":"integer","default":128,"description":"Max results"}},"required":["address"]}),

]

# ── MCP server ────────────────────────────────────────────────────────────────

server = Server("revkit")

@server.list_tools()
async def list_tools() -> list[types.Tool]:
    return TOOLS

@server.call_tool()
async def call_tool(name: str, arguments: dict) -> list[types.TextContent]:
    try:
        result = reverse.call("tools/call", name=name, arguments=arguments)
        if result and "content" in result:
            return [
                types.TextContent(type=item["type"], text=item["text"])
                for item in result["content"]
                if item.get("type") == "text"
            ]
        return [types.TextContent(type="text", text=json.dumps(result, indent=2))]
    except ConnectionError as e:
        return [types.TextContent(type="text", text=f"ERROR: {e}")]
    except RuntimeError as e:
        return [types.TextContent(type="text", text=f"Error: {e}")]
    except Exception as e:
        return [types.TextContent(type="text", text=f"Unexpected error: {e}")]

# ── entry point ───────────────────────────────────────────────────────────────

async def main():
    async with mcp.server.stdio.stdio_server() as (read_stream, write_stream):
        await server.run(
            read_stream,
            write_stream,
            server.create_initialization_options(),
        )

if __name__ == "__main__":
    asyncio.run(main())
