# revkit — Setup Guide

Get revkit running in under 5 minutes.

---

## Requirements

- Windows 10 or Windows 11 (x64 only)
- Administrator account
- **No test signing or Secure Boot changes required.** revkit uses kdmapper to load the driver by exploiting a signed vulnerable Intel driver, bypassing Windows driver signature enforcement entirely. No bcdedit, no reboots, no BIOS changes.

---

## Quick Start

### Step 1 — Run revkit

Right-click `revkit.exe` and select "Run as administrator", or from an elevated prompt:

```cmd
revkit.exe
```

The GUI window will open. The status bar will show "Driver loaded" followed by "MCP server running on :13338" within a few seconds. If the driver fails to map, the GUI shows "running in usermode fallback (RPM)" — the kernel features are unavailable but usermode tools still work.

---

## File Reference

| File | Role |
|---|---|
| `revkit.exe` | Main application. Hosts the GUI and the MCP HTTP server. Can live anywhere; must run as Administrator. |
| `revkit-driver.sys` | Kernel driver. Mapped by kdmapper at startup. Must sit in the same folder as `revkit.exe`. |
| `kdmapper.exe` | Mapper that loads the driver without DSE. Must sit in the same folder as `revkit.exe`. |

`revkit.exe` can be placed anywhere, but `revkit-driver.sys` and `kdmapper.exe` must be in its own folder so it can find and map the driver. Keep those two files together with `revkit.exe`; do not move them individually.

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

### Driver won't load — "device not found" / "running in usermode fallback (RPM)"

The driver loads via kdmapper, which needs a vulnerable Intel driver to gain kernel write. Common causes:

**Cause 1: revkit.exe not running as Administrator.**
The SE_LOAD_DRIVER_PRIVILEGE (and the kdmapper exploit) require elevation. Right-click > Run as administrator.

**Cause 2: A stale driver device object from a previous mapping.**
Each map creates `\Device\7E4A9C3F`. A prior mapping that was not cleanly unloaded leaves the device behind, so the new map collides and aborts (`DriverEntry returned 0xc0000035`). revkit now cleans this up automatically on re-map. To force a clean swap: open the in-app console and run `/reload` (unload + re-map), or `/unload` then replace `revkit-driver.sys` and `/load`. A reboot always works too.

**Cause 3: HVCI / memory integrity is enabled.**
Virtualization-based Code Integrity blocks the vulnerable driver kdmapper relies on. Check Settings > Core Isolation > Memory Integrity and turn it off if mapping fails. revkit detects this and offers to disable it (requires reboot).

**Cause 4: revkit-driver.sys missing or wrong directory.**
Ensure `revkit-driver.sys` and `kdmapper.exe` are in the same folder as `revkit.exe`.

**Cause 5: Another instance of revkit is already running.**
The device name is fixed, so the driver maps once per boot. Close any existing `revkit.exe` before launching again.

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

Attach WinDbg on the host machine. With an active kernel debug session the vulnerable driver loads more reliably. Revert with:

```cmd
bcdedit /debug off
```

---

## Reloading the driver without a reboot

kdmapper maps the driver into kernel memory but does not register a service, so Windows does not track it as a normal driver. To load a freshly rebuilt `revkit-driver.sys`:

1. Open the in-app console in the revkit GUI.
2. Run `/reload` — this sends the unload signal (removes the device + symlink) and re-maps the driver via kdmapper in one step.
3. If you prefer manual steps: `/unload`, replace `revkit-driver.sys` in the revkit folder, then `/load`.

A leftover device object from a crashed/forced-close mapping is cleaned up automatically on re-map, so a prior failure will not block the next load.
