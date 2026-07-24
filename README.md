# remoted

A tiny **tray-resident SSH gateway** for shared lab hardware. It is *just a convenient
sshd* (with key-only auth) that also exposes a variable number of **serial ports** over
SSH, and shows a friendly **full-screen "occupied" overlay** whenever anyone is connected.

It is deliberately HAPS-agnostic: how to burn / reset / flash is entirely up to whoever
deploys it — they drop their own `.bat` / scripts into the shell directory and run them
over `ssh`. remoted only provides the SSH channel + shared serial consoles (the COM port
itself is opened exclusively) + the occupancy prompt.

## What it does

- **SSH server** (libssh) on a configurable port (NOT the standard sshd / port 22).
  Key-only auth, no domain integration. Runs as the current interactive user.
- **Shell / exec** → `cmd.exe`, landing in a configurable directory. Streams stdout live.
  `ssh haps "burn.bat"` "just works".
- **Serial forwarding** — each configured COM port gets its **own SSH listener port**, so
  `ssh haps0` drops you straight on the UART console. COM ports are matched by a **stable
  USB parent id** (falls back to the COM number) and opened **exclusively**; multiple SSH
  sessions may attach to the same console at once — all see the output and all can type.
- **Occupancy overlay** — any *authenticated* session triggers a topmost full-screen prompt
  ("occupied by X, please Love & Peace"); retracts a few seconds after the *last* session
  drops. Minimize / disconnect-all from the overlay or tray. Closes to the system tray.
- **No auto-start**, no service. Run it once (e.g. over VNC); it stays in the tray.

```
control machine                       lab PC (domain Win10)
┌──────────────┐   ssh (key, no pw)  ┌────────────────────────────┐
│ ssh haps     │ ───── :9721 ──────▶ │ remoted.exe (tray)          │
│ ssh haps0    │                     │  libssh : main + per-serial │
│ MobaXterm    │                     │  COM → shared console        │
│ agent        │                     │  overlay + tray              │
└──────────────┘                     └────────────────────────────┘
```

## Build

### Prerequisites
- Visual Studio 2026 BuildTools (MSVC) — or any VS with the C++ workload.
- CMake ≥ 4.2 (the `Visual Studio 18 2026` generator was added in 4.2; older CMake
  works if you swap in an older generator in `CMakePresets.json`).
- **vcpkg**, as a real **git checkout** with `VCPKG_ROOT` pointing at it.

> **vcpkg gotcha:** the vcpkg bundled inside Visual Studio (`<VS>\VC\vcpkg`) is a non-git
> snapshot whose baseline commit is not in the public registry, so manifest mode cannot
> resolve versions. Use a standalone clone:
> ```bat
> git clone --depth 1 https://github.com/microsoft/vcpkg.git D:\vcpkg
> D:\vcpkg\bootstrap-vcpkg.bat -disableMetrics
> setx VCPKG_ROOT D:\vcpkg
> ```
> The `builtin-baseline` in `vcpkg.json` must equal that clone's HEAD (`git -C %VCPKG_ROOT% rev-parse HEAD`).

### Configure & build
```bat
cmake --preset default
cmake --build --preset default
```
Output: `build\Release\remoted.exe` (+ copied `ssh.dll`, `libcrypto-3-x64.dll`).

## Deploy (on the lab PC)

1. Copy `remoted.exe`, `ssh.dll`, `libcrypto-3-x64.dll` into a folder (e.g. `C:\remoted\`).
2. Copy `remoted.json.example` → `remoted.json` next to the exe, edit to taste.
3. On your **control machine**, generate a keypair:
   ```bat
   ssh-keygen -t ed25519 -f %USERPROFILE%\.ssh\remoted_key
   ```
4. Append the public key into `C:\remoted\keys\authorized_keys` on the lab PC.
   > **Priority gotcha:** while `authorized_keys` stays at its default
   > (`keys/authorized_keys`) and `%USERPROFILE%\.ssh\authorized_keys` exists, the
   > **profile file wins** (OpenSSH convention — it is logged at startup). Either put
   > your keys there, or point `ssh.authorized_keys` at an explicit path.
5. Get the key's fingerprint. On successful auth the full SHA256 fingerprint is always
   in `remoted.log`; on failed auth the last offered fingerprint is logged once per
   unique key (plus a tray balloon). Or locally:
   ```bat
   ssh-keygen -lf %USERPROFILE%\.ssh\remoted_key.pub
   ```
   Map it to a name in `remoted.json` → `identities` (used by the overlay).
6. Run `remoted.exe` once (over VNC). It generates a host key, listens, and hides in the tray.

## Configuration (`remoted.json`)

```jsonc
{
  "ssh": {
    "listen": "0.0.0.0:9721",            // host:port for the main shell
    "host_key": "keys/ed25519_key",      // auto-generated on first run
    "authorized_keys": "keys/authorized_keys",
    "shell_dir": "."                     // where `ssh haps` lands (exe dir if ".")
  },
  "identities": {
    "SHA256:....": { "name": "张三", "contact": "wx: zhang / 工位 B12" }
  },
  "serial": [
    { "name": "haps0", "com": "COM44", "usb_id": "7&1895985a&0&0000", "baud": 115200, "listen_port": 9722 },
    { "name": "host",  "com": "COM23", "usb_id": "DK0EBG2H",          "baud": 115200, "listen_port": 9726 }
  ],
  "overlay": { "enabled": true, "retract_delay_sec": 3, "message": "HAPS 调试机远程占用中，请勿操作，谢谢配合" }
}
```
Relative paths resolve against the exe folder. `serial[].usb_id` is matched as a substring
against the device's **USB parent id** (stable per physical port); if it does not match the
`com` field is used instead. Any number of serial entries — names must be unique (a
duplicate name is ignored after the first entry, with a log line).

> Keys and the host key live under the exe folder with inherited ACLs. On machines
> where other people can log in, restrict the folder to your account + SYSTEM
> (`icacls C:\remoted /inheritance:r /grant:r "%USERNAME%:F" "SYSTEM:F"`).

### Finding the USB parent id of a COM port
Run on the lab PC:
```powershell
Get-PnpDevice -Class Ports | Where-Object Status -eq 'OK' | ForEach-Object {
  $com = ([regex]::Match($_.FriendlyName, '\(COM\d+\)')).Value
  $par = ($_ | Get-PnpDeviceProperty -KeyName 'DEVPKEY_Device_Parent').Data
  [pscustomobject]@{ Com = $com; Parent = $par }
} | Format-List
```
Use the stable tail of `Parent` (e.g. `7&1895985a&0&0000`, or a real serial like `DK0EBG2H`).

### `authorized_keys` options

Standard per-key options are supported and **enforced**:

```
from="10.0.*,!10.0.13.37",no-pty ssh-ed25519 AAAA... alice
command="burn.bat 0" ssh-ed25519 AAAA... burner-bot
```

- `command="..."` — forced command: replaces whatever the client asks to run on the
  main shell. Keys with a forced command are **rejected on the serial consoles**.
- `no-pty` — pty requests from this key are refused (remoted has no real pty anyway).
- `from="patterns"` — peer IP must match the comma-separated list; `!` negates,
  `*`/`?` are wildcards, first match decides, no match denies. IPv4 CIDR
  (`10.0.0.0/24`) is supported; patterns otherwise match **numeric IPs only**
  (hostnames never match; IPv4-mapped IPv6 peers are normalized to IPv4 first;
  IPv6 CIDR is not implemented and never matches).
- The `no-*-forwarding` family (`no-agent-forwarding`, `no-x11-forwarding`,
  `no-port-forwarding`, `restrict`, `permitopen`, `permitlisten`) is inherently
  satisfied — remoted implements no forwarding at all.
- Any other option is **ignored and logged** at connect time — do not rely on it.

Failed sessions are throttled per source IP: 10 failures within 60 s gets new
connections from that address dropped early (a successful login resets the counter),
and a bad signature costs a 1 s delay. Concurrent sessions are capped at 64.

## Usage

Control-machine `~/.ssh/config` (or `%USERPROFILE%\.ssh\config`):
```
Host haps
    HostName 10.x.x.x
    Port 9721
    User haps
    IdentityFile ~/.ssh/remoted_key

Host haps0
    HostName 10.x.x.x
    Port 9722
    User haps
    IdentityFile ~/.ssh/remoted_key
    RequestTTY yes
```
Then:
```bash
ssh haps                  # shell (drops in shell_dir)
ssh haps "burn.bat 0"     # run a script, logs stream back
ssh haps0                 # directly on the haps0 UART console (own listener port)
```
> Each serial is its own ssh listener port (see `.ssh/config` `Host haps0`), so
> `ssh haps0` is the way to reach a UART. Do **not** use `ssh haps -t haps0` —
> that would just run `cmd /C haps0` on the main shell.
>
> Note: if several people connect to the same serial port at once they share one console —
> everyone sees the same output and each person's keystrokes go to the UART, so input is
> visible to (and can conflict with) the other sessions.
`ssh haps` prints a **banner** listing every serial, its port, and status (`[ready]` /
`[in-use <holder>]` / `[absent]`).

## Tray / overlay

- Any authenticated session shows the overlay; it retracts `retract_delay_sec` after the
  last session ends.
- Tray menu: **Status**, **Disconnect all remote**, **Show overlay**, **Edit config** (opens
  `remoted.json` in notepad), **Reload config**, **Exit**.
  Reload applies `identities` / `overlay` / `authorized_keys` / `shell_dir` immediately.
  For `serial` entries, `com` / `usb_id` / `baud` apply to *new* sessions — a console
  already in use keeps its current device until all its sessions disconnect (attaching
  with changed settings is refused while the old bridge lives). New or changed
  `listen_port`s (main or serial) require restarting the process; a parse failure keeps
  the previous config and says so in a balloon.
- Overlay buttons: **Disconnect remote** (kills all ssh sessions), **Minimize** (hide overlay
  only). It is a courtesy prompt, not a hard lock.

## Logs
`remoted.log` is written next to the exe (rotated at 1 MB to `remoted.log.old`).
Fatal crashes append one line to `remoted.crash.log` (exception code + address).

## License
MIT.
