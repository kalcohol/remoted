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
#define WM_APP_BALLOON (WM_APP + 4)   // 2nd instance asked us to re-announce
#define WM_APP_NOTIFY  (WM_APP + 5)   // a pending balloon notification
#define TIMER_RETRACT  9001

struct SerialStatus {
    std::string name;
    std::string com;
    uint16_t    listen_port = 0;
    bool        present = false;
    std::map<int,std::string> holders;   // session token -> display name
};

class Overlay;

class App {
public:
    AppConfig cfg;
    std::string config_path;
    HWND      hwnd_main = nullptr;     // owner window (tray) for PostMessage
    Overlay*  overlay  = nullptr;

    void start();                      // enumerate devices, build status table

    std::vector<SerialStatus> snapshot() const;            // for MOTD
    std::string find_com_for(const std::string& name) const;

    // session occupancy (drives overlay). token returned to pair start/end.
    // scope = "shell" (main shell user) or the serial name.
    int  session_start(const std::string& scope, const std::string& display_name);
    void session_end(int token);
    std::vector<std::string> shell_holders() const;

    // serial hold registry (status only; sharing is handled by the ssh layer).
    // keyed by session token so two sessions of the same name don't clobber each other.
    bool mark_busy(const std::string& name, int token, const std::string& holder);
    void clear_busy(const std::string& name, int token);

    const Identity* identity_for(const std::string& fp) const;

    // request a tray balloon (thread-safe; drained by the tray window)
    void request_notify(const std::wstring& title, const std::wstring& body);
    std::mutex nm_;
    std::vector<std::pair<std::wstring, std::wstring>> pending_notify_;

    // build the text shown on the overlay (message + active holders)
    std::wstring overlay_text() const;
private:
    std::vector<EnumCom>     devs_;
    mutable std::mutex       m_;
    std::atomic<int>         next_token_{1};
    int                      active_ = 0;
    std::unordered_map<int, std::pair<std::string,std::string>> holders_;  // token -> {scope, name}
    std::vector<SerialStatus> status_;
};
