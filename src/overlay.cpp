#include "overlay.h"
#include "app.h"
#include "ssh.h"
#include "log.h"
#include <windows.h>

enum { IDC_DISC = 101, IDC_MIN = 102 };

static LRESULT CALLBACK OverlayProc(HWND h, UINT msg, WPARAM wp, LPARAM lp) {
    Overlay* self = (Overlay*)GetWindowLongPtrW(h, GWLP_USERDATA);
    switch (msg) {
    case WM_CTLCOLORSTATIC: {
        HDC dc = (HDC)wp;
        SetTextColor(dc, RGB(255, 255, 255));
        SetBkColor(dc, RGB(0, 0, 0));
        if (self) return (LRESULT)self->brush();
        return (LRESULT)GetStockObject(BLACK_BRUSH);
    }
    case WM_COMMAND:
        if (LOWORD(wp) == IDC_DISC) { LOG("disconnect-all requested via overlay button"); ssh_disconnect_all(); }
        else if (LOWORD(wp) == IDC_MIN) { ShowWindow(h, SW_HIDE); }
        return 0;
    case WM_ERASEBKGND: {
        RECT rc; GetClientRect(h, &rc);
        FillRect((HDC)wp, &rc, self ? self->brush() : (HBRUSH)GetStockObject(BLACK_BRUSH));
        return 1;
    }
    }
    return DefWindowProcW(h, msg, wp, lp);
}

LRESULT CALLBACK Overlay::WndProc(HWND h, UINT msg, WPARAM wp, LPARAM lp) {
    return OverlayProc(h, msg, wp, lp);
}

bool Overlay::create(App* app, HINSTANCE hi) {
    app_ = app; inst_ = hi;
    brush_ = CreateSolidBrush(RGB(0, 0, 0));
    font_  = CreateFontW(28, 0, 0, 0, FW_SEMIBOLD, FALSE, FALSE, FALSE,
                         DEFAULT_CHARSET, OUT_DEFAULT_PRECIS,
                         CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY,
                         FF_DONTCARE, L"Segoe UI");

    WNDCLASSW wc{};
    wc.lpfnWndProc   = Overlay::WndProc;
    wc.hInstance     = hi;
    wc.lpszClassName = L"remoted_overlay";
    wc.hCursor       = LoadCursor(nullptr, IDC_ARROW);
    wc.hbrBackground = brush_;
    RegisterClassW(&wc);

    hwnd_ = CreateWindowExW(WS_EX_TOPMOST | WS_EX_TOOLWINDOW, L"remoted_overlay",
                            L"remoted", WS_POPUP, 0, 0, 100, 100,
                            nullptr, nullptr, hi, nullptr);
    if (!hwnd_) return false;
    SetWindowLongPtrW(hwnd_, GWLP_USERDATA, (LONG_PTR)this);

    htext_ = CreateWindowExW(0, L"STATIC", L"", WS_CHILD | WS_VISIBLE | SS_CENTER,
                             0, 0, 100, 50, hwnd_, (HMENU)200, hi, nullptr);
    SendMessageW(htext_, WM_SETFONT, (WPARAM)font_, TRUE);

    HFONT btnfont = CreateFontW(20, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE,
                                DEFAULT_CHARSET, OUT_DEFAULT_PRECIS,
                                CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY,
                                FF_DONTCARE, L"Segoe UI");
    hdisc_ = CreateWindowExW(0, L"BUTTON", L"Disconnect remote",
                             WS_CHILD | WS_VISIBLE, 0, 0, 200, 44,
                             hwnd_, (HMENU)IDC_DISC, hi, nullptr);
    hmin_  = CreateWindowExW(0, L"BUTTON", L"Minimize",
                             WS_CHILD | WS_VISIBLE, 0, 0, 160, 44,
                             hwnd_, (HMENU)IDC_MIN, hi, nullptr);
    SendMessageW(hdisc_, WM_SETFONT, (WPARAM)btnfont, TRUE);
    SendMessageW(hmin_,  WM_SETFONT, (WPARAM)btnfont, TRUE);

    return true;
}

void Overlay::layout(int w, int h) {
    int btnw = 220, btnh = 48, gap = 20;
    int by = h - btnh - 60;
    int totalw = btnw * 2 + gap;
    int bx = (w - totalw) / 2;
    MoveWindow(hdisc_, bx, by, btnw, btnh, TRUE);
    MoveWindow(hmin_,  bx + btnw + gap, by, btnw, btnh, TRUE);
    MoveWindow(htext_, w / 10, by - 280, w - w / 5, 260, TRUE);
}

void Overlay::show_now() {
    SetWindowTextW(htext_, app_->overlay_text().c_str());
    int x = GetSystemMetrics(SM_XVIRTUALSCREEN);
    int y = GetSystemMetrics(SM_YVIRTUALSCREEN);
    int w = GetSystemMetrics(SM_CXVIRTUALSCREEN);
    int h = GetSystemMetrics(SM_CYVIRTUALSCREEN);
    MoveWindow(hwnd_, x, y, w, h, TRUE);
    layout(w, h);
    ShowWindow(hwnd_, SW_SHOWNORMAL);
    SetWindowPos(hwnd_, HWND_TOPMOST, 0, 0, 0, 0,
                 SWP_NOACTIVATE | SWP_NOMOVE | SWP_NOSIZE);
}

void Overlay::hide_now() {
    ShowWindow(hwnd_, SW_HIDE);
}
