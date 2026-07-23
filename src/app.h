#pragma once
#include "config.h"
#include "pnp.h"
#include <windows.h>
#include <atomic>
#include <mutex>
#include <vector>
#include <string>
#include <unordered_map>

#define WM_APP_STATE   (WM_APP + 1)   // occupancy changed -> refresh overlay
#define WM_APP_TRAY    (WM_APP + 2)   // tray icon callback
#define WM_APP_EXIT    (WM_APP + 3)   // request quit
#define WM_APP_BALLOON (WM_APP + 4)   // 2nd instance asked us to re-announce
#define TIMER_RETRACT  9001

struct SerialStatus {
    std::string name;
    std::string com;
    uint16_t    listen_port = 0;
    bool        present = false;
    std::vector<std::string> holders;   // display names currently attached
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
    int  session_start(const std::string& display_name);
    void session_end(int token);

    // serial hold registry (status only; sharing is handled by the ssh layer)
    bool mark_busy(const std::string& name, const std::string& holder);
    void clear_busy(const std::string& name, const std::string& holder);

    const Identity* identity_for(const std::string& fp) const;

    // build the text shown on the overlay (message + active holders)
    std::wstring overlay_text() const;
private:
    std::vector<EnumCom>     devs_;
    mutable std::mutex       m_;
    std::atomic<int>         next_token_{1};
    int                      active_ = 0;
    std::unordered_map<int, std::string> holders_;      // token -> display name
    std::vector<SerialStatus> status_;
};
