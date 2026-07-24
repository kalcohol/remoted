#include "log.h"
#include <windows.h>
#include <cstdarg>
#include <cstdio>
#include <cstring>
#include <mutex>

// leaked on purpose: a shutdown straggler may still LOG while the CRT destroys
// statics - a leaked object outlives them all (the OS reclaims the handle).
namespace {
struct LogStatics {
    std::wstring path;
    std::mutex   m;
    HANDLE       h = INVALID_HANDLE_VALUE;   // kept open between lines
    ULONGLONG    last_rotate_warn = 0;
};
}
static LogStatics& L() { static auto* p = new LogStatics(); return *p; }

void log_init(const std::wstring& p) { L().path = p; }

// (called under L().m) open the log on first use, rotate past 1 MB.
static HANDLE log_handle() {
    auto open_fresh = []() {
        HANDLE h = CreateFileW(L().path.c_str(), FILE_APPEND_DATA,
                               FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr,
                               OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (h != INVALID_HANDLE_VALUE) {
            DWORD hi = 0, lo = GetFileSize(h, &hi);
            if (lo == 0 && hi == 0) { DWORD w = 0; WriteFile(h, "\xef\xbb\xbf", 3, &w, nullptr); }  // UTF-8 BOM
        }
        return h;
    };
    if (L().h == INVALID_HANDLE_VALUE) L().h = open_fresh();
    if (L().h == INVALID_HANDLE_VALUE) return L().h;

    LARGE_INTEGER sz{};
    if (GetFileSizeEx(L().h, &sz) && sz.QuadPart > 1024 * 1024) {
        ULONGLONG now = GetTickCount64();
        // rate-limit the whole rotation ATTEMPT (not just the warning): when the
        // file is held by another process every retry is a wasted close+move+open
        if (now - L().last_rotate_warn > 60000) {
            L().last_rotate_warn = now;
            CloseHandle(L().h); L().h = INVALID_HANDLE_VALUE;
            std::wstring old = L().path + L".old";
            if (MoveFileExW(L().path.c_str(), old.c_str(), MOVEFILE_REPLACE_EXISTING)) {
                L().h = open_fresh();
            } else {
                L().h = open_fresh();   // keep appending to the big one, but say so
                if (L().h != INVALID_HANDLE_VALUE) {
                    const char* m = "log rotation failed (remoted.log held by another process?)\n";
                    DWORD w = 0; WriteFile(L().h, m, (DWORD)strlen(m), &w, nullptr);
                }
            }
        }
    }
    return L().h;
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

    std::lock_guard<std::mutex> lk(L().m);
    if (L().path.empty()) return;

    HANDLE h = log_handle();
    if (h != INVALID_HANDLE_VALUE) {
        DWORD w = 0; WriteFile(h, line, (DWORD)(pre + n + 1), &w, nullptr);
    }
}
