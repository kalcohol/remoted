#pragma once
#include <windows.h>
#include <shellapi.h>
#include <string>

class App;
class Overlay;

// Owns the hidden message window + tray icon and runs the main message loop.
class Tray {
public:
    ~Tray();           // releases the tray icon resource if we own it
    bool create(App* app, Overlay* overlay, HINSTANCE hInst);
    int  loop();          // GetMessage/DispatchMessage; returns on WM_QUIT
    void show_balloon(const std::wstring& title, const std::wstring& body);
    static LRESULT CALLBACK WndProc(HWND, UINT, WPARAM, LPARAM);
private:
    App*       app_     = nullptr;
    Overlay*   overlay_ = nullptr;
    HINSTANCE  inst_    = nullptr;
    HWND       hwnd_    = nullptr;
    NOTIFYICONDATAW nid_ {};
    UINT       taskbar_created_msg_ = 0;
    bool       icon_owned_ = false;   // SHGetStockIconInfo icons need DestroyIcon
};
