#include "tray.h"
#include "app.h"
#include "overlay.h"
#include "ssh.h"
#include "util.h"
#include "log.h"
#include <windows.h>
#include <shellapi.h>
#include <dbt.h>
#include <sstream>
#include <vector>
#include <utility>

enum { IDM_STATUS = 1001, IDM_DISC, IDM_SHOW, IDM_CFG, IDM_RELOAD, IDM_EXIT };
#define TIMER_PNP 9002   // device-change debounce

static HICON load_icon(bool& owned) {
    HICON icon = nullptr;
    SHSTOCKICONINFO sii{}; sii.cbSize = sizeof(sii);
    if (SUCCEEDED(SHGetStockIconInfo(SIID_DESKTOPPC, SHGSI_ICON | SHGSI_LARGEICON, &sii))) {
        icon = sii.hIcon;
        owned = true;   // SHGSI_ICON transfers ownership; DestroyIcon when done
    }
    if (!icon) {
        icon = (HICON)LoadImageW(nullptr, IDI_APPLICATION, IMAGE_ICON, 0, 0, LR_SHARED);
        owned = false;  // LR_SHARED: do NOT destroy
    }
    return icon;
}

Tray::~Tray() {
    if (icon_owned_ && nid_.hIcon) DestroyIcon(nid_.hIcon);
}

bool Tray::create(App* app, Overlay* overlay, HINSTANCE hi) {
    app_ = app; overlay_ = overlay; inst_ = hi;
    taskbar_created_msg_ = RegisterWindowMessageW(L"TaskbarCreated");

    WNDCLASSW wc{};
    wc.lpfnWndProc   = Tray::WndProc;
    wc.hInstance     = hi;
    wc.lpszClassName = L"remoted_tray";
    RegisterClassW(&wc);

    hwnd_ = CreateWindowExW(0, L"remoted_tray", L"remoted", WS_OVERLAPPEDWINDOW,
                            CW_USEDEFAULT, CW_USEDEFAULT, CW_USEDEFAULT, CW_USEDEFAULT,
                            nullptr, nullptr, hi, nullptr);
    if (!hwnd_) return false;
    SetWindowLongPtrW(hwnd_, GWLP_USERDATA, (LONG_PTR)this);

    nid_.cbSize           = sizeof(nid_);
    nid_.hWnd             = hwnd_;
    nid_.uID              = 1;
    nid_.uFlags           = NIF_ICON | NIF_MESSAGE | NIF_TIP;
    nid_.uCallbackMessage = WM_APP_TRAY;
    nid_.hIcon            = load_icon(icon_owned_);
    wcscpy_s(nid_.szTip, L"remoted");
    BOOL icn = Shell_NotifyIconW(NIM_ADD, &nid_);
    LOG("tray icon NIM_ADD: %s (hIcon=%p hwnd=%p cbSize=%u)",
        icn ? "ok" : "FAIL", nid_.hIcon, hwnd_, (unsigned)nid_.cbSize);

    app_->hwnd_main = hwnd_;
    LOG("tray ready");
    return true;
}

void Tray::show_balloon(const std::wstring& title, const std::wstring& body) {
    nid_.uFlags |= NIF_INFO;
    nid_.dwInfoFlags = NIIF_INFO;
    wcsncpy_s(nid_.szInfoTitle, title.c_str(), _TRUNCATE);
    wcsncpy_s(nid_.szInfo, body.c_str(), _TRUNCATE);
    Shell_NotifyIconW(NIM_MODIFY, &nid_);
}

int Tray::loop() {
    MSG msg{};
    for (;;) {
        BOOL r = GetMessageW(&msg, nullptr, 0, 0);
        if (r == 0) break;                    // WM_QUIT
        if (r == -1) {                        // error: don't spin silently
            LOG("GetMessage failed err=%lu - exiting message loop", GetLastError());
            return -1;
        }
        TranslateMessage(&msg); DispatchMessageW(&msg);
    }
    return (int)msg.wParam;
}

LRESULT CALLBACK Tray::WndProc(HWND h, UINT msg, WPARAM wp, LPARAM lp) {
    Tray* self = (Tray*)GetWindowLongPtrW(h, GWLP_USERDATA);
    App* app = self ? self->app_ : nullptr;
    Overlay* ov = self ? self->overlay_ : nullptr;

    if (self && msg == self->taskbar_created_msg_) {
        // explorer restarted: re-add the icon, but strip any stale balloon
        // state or NIM_ADD would replay an hours-old notification
        self->nid_.uFlags &= ~NIF_INFO;
        self->nid_.szInfo[0] = 0;
        self->nid_.szInfoTitle[0] = 0;
        Shell_NotifyIconW(NIM_ADD, &self->nid_);
        return 0;
    }

    switch (msg) {
    case WM_APP_BALLOON:
        // a second instance asked us to re-announce; this has nothing to do
        // with the overlay, so guard on the tray itself
        if (self) self->show_balloon(L"remoted already running",
                                     L"ssh session is up - see the tray icon.");
        return 0;
    case WM_APP_NOTIFY: {
        std::vector<std::pair<std::wstring, std::wstring>> v;
        if (app) { std::lock_guard<std::mutex> lk(app->nm_); v.swap(app->pending_notify_); }
        if (self && !v.empty()) {
            if (v.size() == 1) self->show_balloon(v[0].first, v[0].second);
            else {   // multiple -> collapse (successive NIM_MODIFY would only show the last)
                std::wstring body;
                for (auto& p : v) { if (!body.empty()) body += L"\r\n"; body += p.second; }
                self->show_balloon(L"remoted", body);
            }
        }
        return 0;
    }
    case WM_APP_REFRESH:
        // holder list changed; refresh the overlay text only if it's already up
        // (don't re-pop a minimized overlay on every attach/detach).
        if (ov && IsWindowVisible(ov->hwnd())) ov->show_now();
        return 0;
    case WM_APP_STATE: {
        // query the real count instead of trusting wp: cross-thread PostMessage
        // ordering is not guaranteed, a stale payload must not retract the
        // overlay while sessions are still live
        int active = app ? app->active_count() : 0;
        OverlayCfg oc = app ? app->overlay_cfg() : OverlayCfg{};   // range-clamped at load
        if (app && oc.enabled && ov) {
            if (active > 0) { ov->show_now(); KillTimer(h, TIMER_RETRACT); }
            else SetTimer(h, TIMER_RETRACT, oc.retract_delay_sec * 1000, nullptr);
        }
        return 0;
    }
    case WM_DEVICECHANGE:
        // coalesce pnp broadcasts (plug storms fire many per second): re-resolve
        // configured serials once, 300ms after the last change
        if (app && wp == DBT_DEVNODES_CHANGED) SetTimer(h, TIMER_PNP, 300, nullptr);
        return 0;
    case WM_TIMER:
        if (wp == TIMER_RETRACT) {
            KillTimer(h, TIMER_RETRACT);
            if (ov) ov->hide_now();
        } else if (wp == TIMER_PNP) {
            KillTimer(h, TIMER_PNP);
            if (app) app->refresh();
        }
        return 0;
    case WM_APP_TRAY: {
        if (lp == WM_RBUTTONUP) {
            HMENU m = CreatePopupMenu();
            AppendMenuW(m, MF_STRING, IDM_STATUS, L"Status...");
            AppendMenuW(m, MF_STRING, IDM_DISC,  L"Disconnect all remote");
            AppendMenuW(m, MF_STRING, IDM_SHOW,  L"Show overlay");
            AppendMenuW(m, MF_SEPARATOR, 0, nullptr);
            AppendMenuW(m, MF_STRING, IDM_CFG,    L"Edit config");
            AppendMenuW(m, MF_STRING, IDM_RELOAD, L"Reload config");
            AppendMenuW(m, MF_SEPARATOR, 0, nullptr);
            AppendMenuW(m, MF_STRING, IDM_EXIT,  L"Exit");
            POINT pt; GetCursorPos(&pt);
            SetForegroundWindow(h);
            TrackPopupMenu(m, TPM_RIGHTBUTTON, pt.x, pt.y, 0, h, nullptr);
            PostMessageW(h, WM_NULL, 0, 0);   // per MSDN: lets the menu dismiss cleanly
            DestroyMenu(m);
        } else if (lp == WM_LBUTTONDBLCLK) {
            PostMessageW(h, WM_COMMAND, IDM_STATUS, 0);
        }
        return 0;
    }
    case WM_COMMAND: {
        if (!self || !app) return 0;
        switch (LOWORD(wp)) {
        case IDM_STATUS: {
            std::ostringstream os;
            auto snap = app->snapshot();
            os << "remoted status\n\n";
            for (auto& s : snap) {
                os << "  " << s.name << "  " << s.com << "  :" << s.listen_port << "  ";
                if (!s.present) os << "[absent]";
                else if (s.holders.empty()) os << "[ready]";
                else {
                    os << "[in-use: ";
                    bool first = true;
                    for (const auto& hp : s.holders) { if (!first) os << ", "; os << hp.second; first = false; }
                    os << "]";
                }
                os << "\n";
            }
            std::wstring ws = utf8_to_wide(os.str());
            MessageBoxW(h, ws.c_str(), L"remoted", MB_OK | MB_ICONINFORMATION);
            break;
        }
        case IDM_DISC:
            LOG("disconnect-all requested via tray menu");
            ssh_disconnect_all();
            break;
        case IDM_SHOW:
            if (ov) ov->show_now();
            break;
        case IDM_CFG: {
            std::wstring p = utf8_to_wide(app->config_path);
            HINSTANCE r = ShellExecuteW(h, L"open", L"notepad.exe", p.c_str(), nullptr, SW_SHOWNORMAL);
            if ((INT_PTR)r <= 32) {   // ShellExecute returns <= 32 on failure
                LOG("open config in notepad failed (%d)", (int)(INT_PTR)r);
                self->show_balloon(L"remoted", L"could not open remoted.json in notepad");
            }
            break;
        }
        case IDM_RELOAD:
            if (app->reload())
                self->show_balloon(L"remoted", L"config reloaded (listen port changes need restart)");
            else
                self->show_balloon(L"remoted", L"config parse FAILED - kept the previous config");
            break;
        case IDM_EXIT:
            Shell_NotifyIconW(NIM_DELETE, &self->nid_);
            ssh_request_shutdown();   // stops accept loops and joins workers (bounded)
            PostQuitMessage(0);
            break;
        }
        return 0;
    }
    case WM_DESTROY:
        KillTimer(h, TIMER_RETRACT);
        KillTimer(h, TIMER_PNP);
        PostQuitMessage(0);
        return 0;
    }
    return DefWindowProcW(h, msg, wp, lp);
}
