#include "config.h"
#include "app.h"
#include "overlay.h"
#include "tray.h"
#include "ssh.h"
#include "log.h"
#include "util.h"

#include <windows.h>
#include <cstdio>
#include <string>

// ---- crash capture: vectored exception handler writes a crash log ----
static wchar_t g_crashlog[MAX_PATH] = L"";

static LONG WINAPI veh_handler(PEXCEPTION_POINTERS ep) {
    DWORD code = ep->ExceptionRecord->ExceptionCode;
    // ignore benign / first-chance "exceptions":
    //  0xE06D7363         C++ exception
    //  0x40010005/0006    OutputDebugString (wide/ansi) - raised by logging itself
    //  EXCEPTION_BREAKPOINT / SINGLE_STEP
    if (code == 0xE06D7363) return EXCEPTION_CONTINUE_SEARCH;
    if (code == 0x40010005 || code == 0x40010006) return EXCEPTION_CONTINUE_SEARCH;
    if (code == EXCEPTION_BREAKPOINT || code == EXCEPTION_SINGLE_STEP) return EXCEPTION_CONTINUE_SEARCH;
    // only log genuinely fatal ones once (access violation, etc.)
    static volatile LONG logged = 0;
    if (InterlockedCompareExchange(&logged, 1, 0) != 0) return EXCEPTION_CONTINUE_SEARCH;
    char buf[300];
    int n = snprintf(buf, sizeof buf,
                     "[CRASH] code=0x%08lX addr=0x%p flags=0x%lX\r\n",
                     code, ep->ExceptionRecord->ExceptionAddress,
                     ep->ExceptionRecord->ExceptionFlags);
    if (g_crashlog[0]) {
        HANDLE h = CreateFileW(g_crashlog, FILE_APPEND_DATA,
                               FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr,
                               OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (h != INVALID_HANDLE_VALUE) { DWORD w; WriteFile(h, buf, (DWORD)n, &w, nullptr); CloseHandle(h); }
    }
    return EXCEPTION_CONTINUE_SEARCH;
}

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
    AddVectoredExceptionHandler(1, veh_handler);

    wchar_t exe[MAX_PATH];
    GetModuleFileNameW(nullptr, exe, MAX_PATH);
    std::wstring exe_path(exe);
    auto slash = exe_path.find_last_of(L"\\/");
    std::wstring exe_dir = (slash != std::wstring::npos) ? exe_path.substr(0, slash) : exe_path;

    std::wstring logpath  = exe_dir + L"\\remoted.log";
    std::wstring crashp   = exe_dir + L"\\remoted.crash.log";
    wcscpy_s(g_crashlog, crashp.c_str());
    log_init(logpath);
    LOG("=== remoted starting (exe_dir=%s) ===", wide_to_utf8(exe_dir).c_str());

    try {

    // single-instance: tell the running copy to re-announce itself, then exit
    {
        HANDLE single = CreateMutexW(nullptr, TRUE, L"Local\\remoted-singleton-v1");
        if (GetLastError() == ERROR_ALREADY_EXISTS) {
            HWND h = FindWindowW(L"remoted_tray", nullptr);
            if (h) PostMessageW(h, WM_APP_BALLOON, 0, 0);
            LOG("another instance is running - exiting");
            return 0;
        }
    }
    LOG("step: mutex ok");

    std::string cfg_path = wide_to_utf8(exe_dir) + "\\remoted.json";

    App app;
    app.config_path = cfg_path;
    LOG("step: loading config");
    app.cfg = load_config(cfg_path);
    LOG("step: config loaded");

    app.cfg.host_key        = abs_path(exe_dir, app.cfg.host_key);
    app.cfg.authorized_keys = abs_path(exe_dir, app.cfg.authorized_keys);
    app.cfg.shell_dir       = abs_path(exe_dir, app.cfg.shell_dir);

    LOG("step: ensuring keys dir");
    auto kp = app.cfg.host_key.find_last_of("/\\");
    if (kp != std::string::npos)
        CreateDirectoryW(utf8_to_wide(app.cfg.host_key.substr(0, kp)).c_str(), nullptr);

    LOG("step: enumerating serial ports");
    app.start();
    LOG("step: app started");

    Overlay overlay;
    LOG("step: creating overlay");
    if (!overlay.create(&app, hInst)) { LOG("overlay create FAILED"); }
    app.overlay = &overlay;

    Tray tray;
    LOG("step: creating tray");
    if (!tray.create(&app, &overlay, hInst)) {
        MessageBoxW(nullptr, L"tray init failed", L"remoted", MB_ICONERROR);
        return 1;
    }

    LOG("step: starting ssh");
    ssh_start(&app);

    {
        std::wstring body = L"ssh :" + std::to_wstring(app.cfg.listen_port) +
                            L" ready. (if no tray icon, check the overflow / hidden-icons area)";
        tray.show_balloon(L"remoted running", body);
    }

    LOG("step: entering message loop");
    int ret = tray.loop();
    LOG("remoted exiting (code %d)", ret);
    return ret;

    } catch (const std::exception& e) {
        LOG("FATAL std::exception: %s", e.what());
        MessageBoxA(nullptr, e.what(), "remoted fatal", MB_ICONERROR);
        return 2;
    } catch (...) {
        LOG("FATAL unknown exception");
        MessageBoxW(nullptr, L"unknown fatal exception", L"remoted fatal", MB_ICONERROR);
        return 2;
    }
}
