#include "log.h"
#include <windows.h>
#include <cstdarg>
#include <cstdio>
#include <mutex>

static std::wstring g_path;
static std::mutex   g_m;
static HANDLE       g_h = INVALID_HANDLE_VALUE;   // kept open between lines

void log_init(const std::wstring& p) { g_path = p; }

// (called under g_m) open the log on first use, rotate past 1 MB.
static HANDLE log_handle() {
    auto open_fresh = []() {
        HANDLE h = CreateFileW(g_path.c_str(), FILE_APPEND_DATA,
                               FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr,
                               OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (h != INVALID_HANDLE_VALUE) {
            DWORD hi = 0, lo = GetFileSize(h, &hi);
            if (lo == 0 && hi == 0) { DWORD w = 0; WriteFile(h, "\xef\xbb\xbf", 3, &w, nullptr); }  // UTF-8 BOM
        }
        return h;
    };
    if (g_h == INVALID_HANDLE_VALUE) g_h = open_fresh();
    if (g_h == INVALID_HANDLE_VALUE) return g_h;

    LARGE_INTEGER sz{};
    if (GetFileSizeEx(g_h, &sz) && sz.QuadPart > 1024 * 1024) {
        CloseHandle(g_h); g_h = INVALID_HANDLE_VALUE;
        std::wstring old = g_path + L".old";
        MoveFileExW(g_path.c_str(), old.c_str(), MOVEFILE_REPLACE_EXISTING);
        g_h = open_fresh();
    }
    return g_h;
}

void log_line(const char* fmt, ...) {
    char buf[2048];
    va_list ap; va_start(ap, fmt);
    int n = vsnprintf(buf, sizeof buf, fmt, ap);
    va_end(ap);
    if (n < 0) return;
    if (n > (int)sizeof(buf) - 1) n = (int)sizeof(buf) - 1;

    SYSTEMTIME st; GetLocalTime(&st);
    char line[2300];
    int pre = snprintf(line, sizeof line, "[%02d:%02d:%02d] ",
                       st.wHour, st.wMinute, st.wSecond);
    if (pre < 0) return;
    memcpy(line + pre, buf, n);
    line[pre + n] = '\n';
    line[pre + n + 1] = 0;

    OutputDebugStringA(line);

    std::lock_guard<std::mutex> lk(g_m);
    if (g_path.empty()) return;

    HANDLE h = log_handle();
    if (h != INVALID_HANDLE_VALUE) {
        DWORD w = 0; WriteFile(h, line, (DWORD)(pre + n + 1), &w, nullptr);
    }
}
