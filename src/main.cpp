#include "config.h"
#include "app.h"
#include "overlay.h"
#include "tray.h"
#include "ssh.h"
#include "log.h"
#include "util.h"

#include <windows.h>
#include <string>

static std::string abs_path(const std::wstring& exe_dir, const std::string& p) {
    if (p.empty()) return p;
    if (p.size() >= 2 && p[1] == ':') return p;      // X:\...
    if (p[0] == '\\' || p[0] == '/') return p;        // root / UNC
    std::string d = wide_to_utf8(exe_dir);
    if (p == ".") return d;
    if (p.rfind("./", 0) == 0 || p.rfind(".\\", 0) == 0) return d + "\\" + p.substr(2);
    return d + "\\" + p;
}

int WINAPI wWinMain(HINSTANCE hInst, HINSTANCE, LPWSTR, int) {
    wchar_t exe[MAX_PATH];
    GetModuleFileNameW(nullptr, exe, MAX_PATH);
    std::wstring exe_path(exe);
    auto slash = exe_path.find_last_of(L"\\/");
    std::wstring exe_dir = (slash != std::wstring::npos) ? exe_path.substr(0, slash) : exe_path;

    log_init(exe_dir + L"\\remoted.log");
    LOG("=== remoted starting (exe_dir=%s) ===", wide_to_utf8(exe_dir).c_str());

    std::string cfg_path = wide_to_utf8(exe_dir) + "\\remoted.json";

    App app;
    app.config_path = cfg_path;
    app.cfg = load_config(cfg_path);

    app.cfg.host_key        = abs_path(exe_dir, app.cfg.host_key);
    app.cfg.authorized_keys = abs_path(exe_dir, app.cfg.authorized_keys);
    app.cfg.shell_dir       = abs_path(exe_dir, app.cfg.shell_dir);

    auto kp = app.cfg.host_key.find_last_of("/\\");
    if (kp != std::string::npos)
        CreateDirectoryW(utf8_to_wide(app.cfg.host_key.substr(0, kp)).c_str(), nullptr);

    app.start();

    Overlay overlay;
    if (!overlay.create(&app, hInst)) { LOG("overlay create failed"); }
    app.overlay = &overlay;

    Tray tray;
    if (!tray.create(&app, &overlay, hInst)) {
        MessageBoxW(nullptr, L"tray init failed", L"remoted", MB_ICONERROR);
        return 1;
    }

    ssh_start(&app);

    int ret = tray.loop();
    LOG("remoted exiting (code %d)", ret);
    return ret;
}
