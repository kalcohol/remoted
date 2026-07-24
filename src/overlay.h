#pragma once
#include <windows.h>
#include <string>

class App;

class Overlay {
public:
    ~Overlay();          // destroys the window and releases GDI objects
    bool create(App* app, HINSTANCE hInst);
    void show_now();     // pulls text from app_->overlay_text()
    void hide_now();
    void on_dpi_changed(UINT dpi);
    HWND hwnd() const { return hwnd_; }
    HBRUSH brush() const { return brush_; }
private:
    void layout(int w, int h);
    void make_fonts(UINT dpi);   // (re)create dpi-scaled fonts, reassign to controls
    int  scale(int v) const { return MulDiv(v, (int)dpi_, 96); }
    HWND      hwnd_   = nullptr;
    HWND      htext_  = nullptr;
    HWND      hdisc_  = nullptr;
    HWND      hmin_   = nullptr;
    HFONT     font_   = nullptr;
    HFONT     btnfont_ = nullptr;
    HBRUSH    brush_  = nullptr;
    App*      app_    = nullptr;
    HINSTANCE inst_   = nullptr;
    UINT      dpi_    = 96;
};
