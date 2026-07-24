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
    case WM_CLOSE:
        // DefWindowProc would DestroyWindow here (e.g. Alt+F4) and leave every
        // stored HWND dangling; the overlay is a reusable prompt -> hide instead
        ShowWindow(h, SW_HIDE);
        return 0;
    case WM_DPICHANGED:
        if (self) self->on_dpi_changed(LOWORD(wp));
        return 0;
    case WM_ERASEBKGND: {
        RECT rc; GetClientRect(h, &rc);
        FillRect((HDC)wp, &rc, self ? self->brush() : (HBRUSH)GetStockObject(BLACK_BRUSH));
        return 1;
    }
    }
    return DefWindowProcW(h, msg, wp, lp);
}

Overlay::~Overlay() {
    if (hwnd_) DestroyWindow(hwnd_);
    if (font_) DeleteObject(font_);
    if (btnfont_) DeleteObject(btnfont_);
    if (brush_) DeleteObject(brush_);
}

// fonts are per-DPI objects (manifest declares PerMonitorV2, so nothing scales
// them for us): (re)create on DPI change and hand them back to the controls
void Overlay::make_fonts(UINT dpi) {
    dpi_ = dpi ? dpi : 96;
    HFONT f = CreateFontW(scale(28), 0, 0, 0, FW_SEMIBOLD, FALSE, FALSE, FALSE,
                          DEFAULT_CHARSET, OUT_DEFAULT_PRECIS,
                          CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY,
                          FF_DONTCARE, L"Segoe UI");
    HFONT bf = CreateFontW(scale(20), 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE,
                           DEFAULT_CHARSET, OUT_DEFAULT_PRECIS,
                           CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY,
                           FF_DONTCARE, L"Segoe UI");
    if (f) { if (font_) DeleteObject(font_); font_ = f; }
    if (bf) { if (btnfont_) DeleteObject(btnfont_); btnfont_ = bf; }
    if (htext_) SendMessageW(htext_, WM_SETFONT, (WPARAM)font_, TRUE);
    if (hdisc_) SendMessageW(hdisc_, WM_SETFONT, (WPARAM)btnfont_, TRUE);
    if (hmin_)  SendMessageW(hmin_,  WM_SETFONT, (WPARAM)btnfont_, TRUE);
}

void Overlay::on_dpi_changed(UINT dpi) {
    make_fonts(dpi);
    RECT rc; GetClientRect(hwnd_, &rc);
    layout(rc.right - rc.left, rc.bottom - rc.top);
}

bool Overlay::create(App* app, HINSTANCE hi) {
    app_ = app; inst_ = hi;
    brush_ = CreateSolidBrush(RGB(0, 0, 0));

    WNDCLASSW wc{};
    wc.lpfnWndProc   = OverlayProc;
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
    hdisc_ = CreateWindowExW(0, L"BUTTON", L"Disconnect remote",
                             WS_CHILD | WS_VISIBLE, 0, 0, 200, 44,
                             hwnd_, (HMENU)IDC_DISC, hi, nullptr);
    hmin_  = CreateWindowExW(0, L"BUTTON", L"Minimize",
                             WS_CHILD | WS_VISIBLE, 0, 0, 160, 44,
                             hwnd_, (HMENU)IDC_MIN, hi, nullptr);
    make_fonts(GetDpiForWindow(hwnd_));

    return true;
}

void Overlay::layout(int w, int h) {
    int btnw = scale(220), btnh = scale(48), gap = scale(20);
    int by = h - btnh - scale(60);
    int totalw = btnw * 2 + gap;
    int bx = (w - totalw) / 2;
    MoveWindow(hdisc_, bx, by, btnw, btnh, TRUE);
    MoveWindow(hmin_,  bx + btnw + gap, by, btnw, btnh, TRUE);
    MoveWindow(htext_, w / 10, by - scale(280), w - w / 5, scale(260), TRUE);
}

// union of every monitor's PHYSICAL pixel rect: under PerMonitorV2 the
// SM_*VIRTUALSCREEN metrics are reported in system-DPI coordinates, which
// under-covers the desktop on mixed-DPI multi-monitor setups
static RECT virtual_screen_rect() {
    RECT u{ 0, 0, 0, 0 };
    EnumDisplayMonitors(nullptr, nullptr, [](HMONITOR, HDC, LPRECT r, LPARAM p) -> BOOL {
        RECT* u = (RECT*)p;
        UnionRect(u, u, r);
        return TRUE;
    }, (LPARAM)&u);
    if (u.right <= u.left || u.bottom <= u.top) {   // no monitors?? fall back
        u.left = GetSystemMetrics(SM_XVIRTUALSCREEN);
        u.top = GetSystemMetrics(SM_YVIRTUALSCREEN);
        u.right = u.left + GetSystemMetrics(SM_CXVIRTUALSCREEN);
        u.bottom = u.top + GetSystemMetrics(SM_CYVIRTUALSCREEN);
    }
    return u;
}

void Overlay::show_now() {
    if (!hwnd_) return;   // creation failed at startup
    UINT dpi = GetDpiForWindow(hwnd_);
    if (dpi != dpi_) make_fonts(dpi);   // moved to a different-DPI monitor
    SetWindowTextW(htext_, app_->overlay_text().c_str());
    RECT v = virtual_screen_rect();
    int w = v.right - v.left, h = v.bottom - v.top;
    MoveWindow(hwnd_, v.left, v.top, w, h, TRUE);
    layout(w, h);
    ShowWindow(hwnd_, SW_SHOWNA);   // show WITHOUT stealing focus
    SetWindowPos(hwnd_, HWND_TOPMOST, 0, 0, 0, 0,
                 SWP_NOACTIVATE | SWP_NOMOVE | SWP_NOSIZE);
}

void Overlay::hide_now() {
    if (!hwnd_) return;
    ShowWindow(hwnd_, SW_HIDE);
}
