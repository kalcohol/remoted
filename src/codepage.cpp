#include "codepage.h"
#include "log.h"
#include <cstdlib>

static UINT g_oemcp = 936;

void cp_init() {
    g_oemcp = 0;
    HKEY k;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE,
            L"SYSTEM\\CurrentControlSet\\Control\\Nls\\CodePage", 0, KEY_READ, &k) == ERROR_SUCCESS) {
        wchar_t v[16]{}; DWORD sz = sizeof(v); DWORD type = 0;
        if (RegQueryValueExW(k, L"OEMCP", nullptr, &type, (LPBYTE)v, &sz) == ERROR_SUCCESS)
            g_oemcp = (UINT)_wtoi(v);
        RegCloseKey(k);
    }
    if (g_oemcp == 0) g_oemcp = 936;
    LOG("codepage: child OEM=%u (shell transcoding OEM<->UTF-8)", g_oemcp);
}

static std::string cvt(UINT from, UINT to, const char* data, size_t n) {
    if (n == 0) return "";
    int w = MultiByteToWideChar(from, 0, data, (int)n, nullptr, 0);
    if (w <= 0) return "";
    std::wstring ws(w, 0);
    MultiByteToWideChar(from, 0, data, (int)n, &ws[0], w);
    BOOL used = FALSE;
    int m = WideCharToMultiByte(to, 0, ws.c_str(), (int)ws.size(), nullptr, 0, nullptr, &used);
    if (m <= 0) return "";
    std::string out(m, 0);
    WideCharToMultiByte(to, 0, ws.c_str(), (int)ws.size(), &out[0], m, nullptr, &used);
    return out;
}

std::string cp_oem2utf8(const char* data, size_t n, std::string& carry) {
    std::string all = carry + std::string(data, n);
    carry.clear();
    size_t end = all.size();
    // GBK/DBCS lead byte 0x81..0xFE with no trailing byte -> carry it.
    if (end > 0) {
        unsigned char last = (unsigned char)all[end - 1];
        if (last >= 0x81 && last <= 0xFE) { carry.assign(1, all[end - 1]); end -= 1; }
    }
    if (end == 0) return "";
    return cvt(g_oemcp, CP_UTF8, all.data(), end);
}

std::string cp_utf82oem(const char* data, size_t n, std::string& carry) {
    std::string all = carry + std::string(data, n);
    carry.clear();
    size_t end = all.size();
    if (end > 0) {
        size_t i = end;
        while (i > 0 && (all[i - 1] & 0xC0) == 0x80) i--;   // skip continuation bytes
        if (i > 0) {
            unsigned char lead = (unsigned char)all[i - 1];
            int need = (lead & 0x80) == 0 ? 1 :
                       (lead & 0xE0) == 0xC0 ? 2 :
                       (lead & 0xF0) == 0xE0 ? 3 :
                       (lead & 0xF8) == 0xF0 ? 4 : 1;
            int have = (int)(end - (i - 1));
            if (have < need) { carry = all.substr(i - 1); end = i - 1; }
        }
    }
    if (end == 0) return "";
    return cvt(CP_UTF8, g_oemcp, all.data(), end);
}
