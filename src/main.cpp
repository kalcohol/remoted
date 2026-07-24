#include "config.h"
#include "app.h"
#include "overlay.h"
#include "tray.h"
#include "ssh.h"
#include "codepage.h"
#include "log.h"
#include "util.h"

#include <windows.h>
#include <cstdio>
#include <string>

// ---- crash capture: vectored exception handler writes a crash log ----
// NOTE: this runs in exception context - snprintf/CreateFile are not strictly
// async-safe (a crash while holding a CRT/heap lock could deadlock the handler
// itself). Worst case we lose the crash log; it never makes the crash worse.
static wchar_t g_crashlog[MAX_PATH] = L"";

static LONG WINAPI veh_handler(PEXCEPTION_POINTERS ep) {
    DWORD code = ep->ExceptionRecord->ExceptionCode;
    // ignore benign / first-chance "exceptions":
    //  0xE06D7363         C++ exception
    //  0x40010005/0006    debugger control / OutputDebugString - raised by logging
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

int WINAPI wWinMain(HINSTANCE hInst, HINSTANCE, LPWSTR, int) {
    AddVectoredExceptionHandler(1, veh_handler);

    wchar_t exe[MAX_PATH];
    DWORD exe_len = GetModuleFileNameW(nullptr, exe, MAX_PATH);
    if (exe_len == 0 || exe_len >= MAX_PATH) {   // 0 = error; MAX_PATH = truncated
        MessageBoxW(nullptr, L"cannot resolve exe path (too long?)", L"remoted", MB_ICONERROR);
        return 1;
    }
    std::wstring exe_path(exe);
    auto slash = exe_path.find_last_of(L"\\/");
    std::wstring exe_dir = (slash != std::wstring::npos) ? exe_path.substr(0, slash) : exe_path;

    std::wstring logpath  = exe_dir + L"\\remoted.log";
    std::wstring crashp   = exe_dir + L"\\remoted.crash.log";
    wcsncpy_s(g_crashlog, MAX_PATH, crashp.c_str(), _TRUNCATE);
    log_init(logpath);
    LOG("=== remoted starting (exe_dir=%s) ===", wide_to_utf8(exe_dir).c_str());

    try {

    // single-instance: tell the running copy to re-announce itself, then exit.
    // the mutex handle must stay open for the process lifetime (that IS the
    // singleton), so it is parked in a static; the OS reclaims it at exit.
    static HANDLE g_single = nullptr;
    g_single = CreateMutexW(nullptr, TRUE, L"Local\\remoted-singleton-v1");
    if (!g_single) {
        // object-manager/ACL failure: log it and keep running (a port clash
        // with a real second instance is caught later by the bind failure)
        LOG("single-instance mutex failed err=%lu - continuing anyway", GetLastError());
    } else if (GetLastError() == ERROR_ALREADY_EXISTS) {
        HWND h = FindWindowW(L"remoted_tray", nullptr);
        if (h) PostMessageW(h, WM_APP_BALLOON, 0, 0);
        LOG("another instance is running - exiting");
        CloseHandle(g_single);   // this copy is exiting; the other one holds its own
        g_single = nullptr;
        return 0;
    }
    LOG("step: mutex ok");

    std::string cfg_path = wide_to_utf8(exe_dir) + "\\remoted.json";

    // App is heap-allocated and intentionally never deleted: shutdown gives
    // stragglers a 2s join budget and then detaches them, so a worker can
    // still be unwinding (and touching App) after the message loop exits.
    // A leaked App outlives every thread; process exit reclaims it.
    App* app = new App();
    app->config_path = cfg_path;
    app->exe_dir     = exe_dir;
    LOG("step: loading config");
    bool cfg_ok = app->init();
    LOG("step: config loaded (ok=%d)", cfg_ok ? 1 : 0);
    if (!cfg_ok) {
        MessageBoxW(nullptr,
            L"remoted.json failed to parse - using defaults. Check the file (must be UTF-8).",
            L"remoted config", MB_ICONWARNING);
    }

    LOG("step: enumerating serial ports");
    app->start();
    LOG("step: app started");

    Overlay overlay;
    LOG("step: creating overlay");
    if (!overlay.create(app, hInst)) { LOG("overlay create FAILED"); }

    Tray tray;
    LOG("step: creating tray");
    if (!tray.create(app, &overlay, hInst)) {
        MessageBoxW(nullptr, L"tray init failed", L"remoted", MB_ICONERROR);
        return 1;
    }

    LOG("step: starting ssh");
    cp_init();
    ssh_start(app);

    {
        std::wstring body = L"ssh :" + std::to_wstring(app->listen_port()) +
                            L" ready. (if no tray icon, check the overflow / hidden-icons area)";
        tray.show_balloon(L"remoted running", body);
    }

    LOG("step: entering message loop");
    int ret = tray.loop();
    // every exit path funnels here (menu Exit, WM_CLOSE/taskkill, GetMessage
    // error): stop the ssh side so no worker outlives the process teardown.
    // safe to call twice (IDM_EXIT already did): it is idempotent.
    ssh_request_shutdown();
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
