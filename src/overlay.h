#pragma once
#include <windows.h>
#include <string>

class App;

class Overlay {
public:
    bool create(App* app, HINSTANCE hInst);
    void show_now();     // pulls text from app_->overlay_text()
    void hide_now();
    HWND hwnd() const { return hwnd_; }
    HBRUSH brush() const { return brush_; }
private:
    static LRESULT CALLBACK WndProc(HWND, UINT, WPARAM, LPARAM);
    void layout(int w, int h);
    HWND      hwnd_  = nullptr;
    HWND      htext_ = nullptr;
    HWND      hdisc_ = nullptr;
    HWND      hmin_  = nullptr;
    HFONT     font_  = nullptr;
    HBRUSH    brush_ = nullptr;
    App*      app_   = nullptr;
    HINSTANCE inst_  = nullptr;
};
