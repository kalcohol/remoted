#include "log.h"
#include <windows.h>
#include <cstdarg>
#include <cstdio>
#include <mutex>

static std::wstring g_path;
static std::mutex   g_m;

void log_init(const std::wstring& p) { g_path = p; }

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
    if (!g_path.empty()) {
        HANDLE h = CreateFileW(g_path.c_str(), FILE_APPEND_DATA,
                               FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr,
                               OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (h != INVALID_HANDLE_VALUE) {
            DWORD w = 0; WriteFile(h, line, (DWORD)(pre + n + 1), &w, nullptr);
            CloseHandle(h);
        }
    }
}
