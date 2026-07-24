#pragma once
#include "config.h"
#include "pnp.h"
#include <windows.h>
#include <atomic>
#include <mutex>
#include <vector>
#include <string>
#include <unordered_map>
#include <map>

#define WM_APP_STATE   (WM_APP + 1)   // occupancy changed -> refresh overlay
#define WM_APP_TRAY    (WM_APP + 2)   // tray icon callback
#define WM_APP_EXIT    (WM_APP + 3)   // request quit
#define WM_APP_BALLOON  (WM_APP + 4)   // 2nd instance asked us to re-announce
#define WM_APP_NOTIFY   (WM_APP + 5)   // a pending balloon notification
#define WM_APP_REFRESH  (WM_APP + 6)   // refresh overlay text only if visible
#define TIMER_RETRACT  9001

struct SerialStatus {
    std::string name;
    std::string com;
    uint16_t    listen_port = 0;
    bool        present = false;
    std::map<int,std::string> holders;   // session token -> display name
};

class Overlay;

// resolve relative paths against exe_dir and apply the
// %USERPROFILE%\.ssh\authorized_keys preference (startup and reload share this)
void resolve_config_paths(AppConfig& c, const std::wstring& exe_dir);

class App {
public:
    std::string  config_path;
    std::wstring exe_dir;              // base dir for resolving relative config paths
    HWND      hwnd_main = nullptr;     // owner window (tray) for PostMessage

    // load config from config_path, resolve paths, ensure the key dir exists.
    // Returns false on a parse error (defaults are in effect). Called once at
    // startup; reload() handles later changes.
    bool init();
    void start();                      // enumerate devices, build status table
    void refresh() const;              // re-enumerate COM ports, rebuild status table
    // reload config from config_path and re-apply (keeps listeners bound at startup).
    // Returns false (and KEEPS the old config) when the file fails to parse.
    bool reload();

    // thread-safe config accessors: cfg_ is swapped under m_ by reload(), so
    // every reader goes through one of these (each returns a copy under m_).
    std::string authorized_keys_path() const;
    std::string host_key_path() const;
    std::string listen_host() const;
    uint16_t    listen_port() const;
    std::string shell_dir() const;
    OverlayCfg  overlay_cfg() const;
    std::vector<SerialCfg> serial_cfgs() const;
    bool serial_cfg_for(const std::string& name, SerialCfg& out) const;
    bool identity_for(const std::string& fp, Identity& out) const;

    std::vector<SerialStatus> snapshot() const;            // for MOTD
    std::string find_com_for(const std::string& name) const;

    // session occupancy (drives overlay). token returned to pair start/end.
    // scope = "shell" (main shell user) or the serial name.
    int  session_start(const std::string& scope, const std::string& display_name);
    void session_end(int token);
    int  active_count() const;         // live session count (UI reads this, not msg payloads)
    std::vector<std::string> shell_holders() const;

    // serial hold registry (status only; sharing is handled by the ssh layer).
    // keyed by session token so two sessions of the same name don't clobber each other.
    bool mark_busy(const std::string& name, int token, const std::string& holder);
    void clear_busy(const std::string& name, int token);

    // request a tray balloon (thread-safe; drained by the tray window)
    void request_notify(const std::wstring& title, const std::wstring& body);
    std::mutex nm_;
    std::vector<std::pair<std::wstring, std::wstring>> pending_notify_;

    // build the text shown on the overlay (message + active holders)
    std::wstring overlay_text() const;
private:
    AppConfig                cfg_;       // swapped under m_ by reload()
    mutable std::vector<EnumCom>     devs_;    // refreshed on demand by refresh()
    mutable std::mutex       m_;
    std::atomic<int>         next_token_{1};
    int                      active_ = 0;
    std::unordered_map<int, std::pair<std::string,std::string>> holders_;  // token -> {scope, name}
    mutable std::vector<SerialStatus> status_;
};
