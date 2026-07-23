#include "tray.h"
#include "app.h"
#include "overlay.h"
#include "ssh.h"
#include "util.h"
#include "log.h"
#include <windows.h>
#include <shellapi.h>
#include <sstream>

enum { IDM_STATUS = 1001, IDM_DISC, IDM_SHOW, IDM_CFG, IDM_EXIT };

static HICON load_icon() {
    HICON icon = nullptr;
    SHSTOCKICONINFO sii{}; sii.cbSize = sizeof(sii);
    if (SUCCEEDED(SHGetStockIconInfo(SIID_DESKTOPPC, SHGSI_ICON | SHGSI_LARGEICON, &sii)))
        icon = sii.hIcon;
    if (!icon) icon = (HICON)LoadImageW(nullptr, IDI_APPLICATION, IMAGE_ICON, 0, 0, LR_SHARED);
    return icon;
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
    nid_.hIcon            = load_icon();
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
    nid_.uTimeout = 10000;
    Shell_NotifyIconW(NIM_MODIFY, &nid_);
}

int Tray::loop() {
    MSG msg;
    while (GetMessageW(&msg, nullptr, 0, 0) > 0) {
        TranslateMessage(&msg); DispatchMessageW(&msg);
    }
    return (int)msg.wParam;
}

void Tray::quit() { PostQuitMessage(0); }

void Tray::notify_unknown_key(const std::string& fp) {
    nid_.dwInfoFlags = NIIF_INFO;
    wcscpy_s(nid_.szInfo,    L"unknown public key connected");
    std::wstring w = utf8_to_wide(fp);
    wcsncpy_s(nid_.szInfoTitle, w.c_str(), _TRUNCATE);
    nid_.uTimeout = 8000;
    Shell_NotifyIconW(NIM_MODIFY, &nid_);
}

LRESULT CALLBACK Tray::WndProc(HWND h, UINT msg, WPARAM wp, LPARAM lp) {
    Tray* self = (Tray*)GetWindowLongPtrW(h, GWLP_USERDATA);
    App* app = self ? self->app_ : nullptr;
    Overlay* ov = self ? self->overlay_ : nullptr;

    if (self && msg == self->taskbar_created_msg_) {
        Shell_NotifyIconW(NIM_ADD, &self->nid_);
        return 0;
    }

    switch (msg) {
    case WM_APP_BALLOON:
        if (ov) self->show_balloon(L"remoted already running",
                                   L"ssh session is up - see the tray icon.");
        return 0;
    case WM_APP_STATE: {
        int active = (int)wp;
        if (app && app->cfg.overlay.enabled && ov) {
            if (active > 0) { ov->show_now(); KillTimer(h, TIMER_RETRACT); }
            else SetTimer(h, TIMER_RETRACT, app->cfg.overlay.retract_delay_sec * 1000, nullptr);
        }
        return 0;
    }
    case WM_TIMER:
        if (wp == TIMER_RETRACT) {
            KillTimer(h, TIMER_RETRACT);
            if (ov) ov->hide_now();
        }
        return 0;
    case WM_APP_TRAY: {
        if (lp == WM_RBUTTONUP) {
            HMENU m = CreatePopupMenu();
            AppendMenuW(m, MF_STRING, IDM_STATUS, L"Status...");
            AppendMenuW(m, MF_STRING, IDM_DISC,  L"Disconnect all remote");
            AppendMenuW(m, MF_STRING, IDM_SHOW,  L"Show overlay");
            AppendMenuW(m, MF_SEPARATOR, 0, nullptr);
            AppendMenuW(m, MF_STRING, IDM_CFG,   L"Edit config");
            AppendMenuW(m, MF_SEPARATOR, 0, nullptr);
            AppendMenuW(m, MF_STRING, IDM_EXIT,  L"Exit");
            POINT pt; GetCursorPos(&pt);
            SetForegroundWindow(h);
            TrackPopupMenu(m, TPM_RIGHTBUTTON, pt.x, pt.y, 0, h, nullptr);
            DestroyMenu(m);
        } else if (lp == WM_LBUTTONDBLCLK) {
            PostMessageW(h, WM_COMMAND, IDM_STATUS, 0);
        }
        return 0;
    }
    case WM_COMMAND: {
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
            ShellExecuteW(h, L"open", L"notepad.exe", p.c_str(), nullptr, SW_SHOWNORMAL);
            break;
        }
        case IDM_EXIT:
            Shell_NotifyIconW(NIM_DELETE, &self->nid_);
            ssh_request_shutdown();   // stop accept loops + drop sessions cleanly
            Sleep(150);
            PostQuitMessage(0);
            break;
        }
        return 0;
    }
    case WM_DESTROY:
        PostQuitMessage(0);
        return 0;
    }
    return DefWindowProcW(h, msg, wp, lp);
}
