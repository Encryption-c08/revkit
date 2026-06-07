# revkit — Setup Guide

Get revkit running in under 5 minutes.

---

## Requirements

- Windows 10 or Windows 11 (x64 only)
- Administrator account
- Secure Boot disabled (required for test signing or kernel debug)
- One of:
  - Test Signing mode (easiest, works without a debugger attached)
  - Kernel Debug mode (for existing WinDbg setups)

---

## Quick Start

### Step 1 — Enable Test Signing (one-time, requires reboot)

Open an elevated command prompt and run:

```cmd
bcdedit /set testsigning on
```

Then reboot. After reboot you will see a "Test Mode" watermark in the bottom-right corner of the desktop. This is expected.

To disable test signing later:

```cmd
bcdedit /set testsigning off
```

### Step 2 — Disable Secure Boot

Reboot into UEFI/BIOS firmware settings (usually Del, F2, or F10 on POST). Find the Secure Boot option under the Security or Boot tab and set it to Disabled. Save and exit.

### Step 3 — Run revkit

Right-click `revkit.exe` and select "Run as administrator", or from an elevated prompt:

```cmd
revkit.exe
```

The GUI window will open. The status bar will show "Driver loaded" followed by "MCP server running on :13338" within a few seconds.

### Step 4 — Configure your agent

See the MCP config snippets below. Restart your agent/IDE after adding the config.

---

## File Reference

| File | Role |
|---|---|
| `revkit.exe` | Main application. Hosts the GUI and the MCP HTTP server. Must run as Administrator. |
| `revkit-driver.sys` | Kernel driver. Loaded by revkit.exe at startup via kdmapper. Must be in the same directory as revkit.exe. |
| `kdmapper.dll` | Driver mapping library used internally by revkit.exe to load the driver without DSE. Do not run directly. |
| `kdmapper.exe` | Standalone kdmapper binary included for reference and manual testing. Not required for normal operation. |

All four files must be in the same directory. Do not move them individually.

---

## MCP Configuration

### MCP Client config

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

### Cursor

In `.cursor/mcp.json` (project-level) or the Cursor global MCP settings:

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

### Windsurf

In `.windsurf/mcp.json` or the Windsurf MCP settings panel:

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

### Any generic MCP client

- Transport: HTTP (not stdio, not WebSocket)
- URL: `http://localhost:13338`
- Authentication: none
- Protocol: standard MCP JSON-RPC 2.0

---

## Troubleshooting

### Driver won't load — "driver load failed" in the GUI

**Cause 1: Test signing not enabled.**
Run `bcdedit /set testsigning on` in an elevated prompt and reboot. Confirm by looking for the "Test Mode" watermark after reboot.

**Cause 2: Secure Boot is still enabled.**
Test-signed drivers are rejected by Secure Boot. Disable Secure Boot in your UEFI firmware settings.

**Cause 3: revkit.exe not running as Administrator.**
The SE_LOAD_DRIVER_PRIVILEGE required for driver loading is only available to elevated processes. Right-click > Run as administrator.

**Cause 4: revkit-driver.sys missing or wrong directory.**
Ensure `revkit-driver.sys` and `kdmapper.dll` are in the same folder as `revkit.exe`.

**Cause 5: Another instance of revkit is already running.**
The driver cannot be loaded twice. Check Task Manager for an existing `revkit.exe` process and close it before launching again.

---

### Port 13338 is already in use

Check what is using the port:

```cmd
netstat -ano | findstr :13338
```

The second column shows the PID. End the conflicting process via Task Manager or:

```cmd
taskkill /PID <pid> /F
```

If revkit itself is the culprit (crashed without releasing the port), wait 30 seconds for Windows to reclaim the socket or reboot.

---

### "Access denied" when reading memory

The kernel driver is loaded but a specific read failed. Common causes:

- The target address is not in a committed memory region. Use `memory_regions` to list valid ranges before reading.
- The target process has exited. Call `process_detach` and `process_attach` again.
- You are reading from a region marked `PAGE_NOACCESS`. Even ring-0 reads can fail on explicitly no-access pages set by the application.

---

### Agent cannot find the revkit tools

1. Confirm revkit.exe is running and the GUI shows "MCP server running".
2. Test the server manually: open a browser or curl and hit `http://localhost:13338`. You should receive a JSON response.
3. Confirm your agent's MCP config file is in the correct location and uses valid JSON (no trailing commas).
4. Restart the agent or IDE after editing the MCP config. Most clients only read MCP config at startup.

---

### Windows Defender / antivirus removes revkit-driver.sys

kdmapper and unsigned kernel drivers are flagged by many AV products. Add the revkit directory to your AV exclusion list, or temporarily disable real-time protection before extracting the files. This is expected behavior for any kernel-level tooling.

---

## Kernel Debug Mode (Alternative to Test Signing)

If you prefer not to enable test signing system-wide, you can run revkit with a kernel debugger attached instead.

```cmd
bcdedit /debug on
bcdedit /dbgsettings net hostip:192.168.1.x port:50000 key:1.2.3.4
```

Attach WinDbg on the host machine. With an active kernel debug session, revkit can load the driver without test signing. Revert with:

```cmd
bcdedit /debug off
```
