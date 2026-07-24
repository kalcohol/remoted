#include "codepage.h"
#include "log.h"
#include <cstdlib>

static UINT g_oemcp = 936;

// Only codepages whose lead byte is 0x81..0xFE (GBK/Big5) use the DBCS
// forward-parse below. Shift-JIS(932) has single-byte half-width katakana in
// 0xA1..0xDF and a different lead range, so it is NOT handled here (falls back
// to no-carry); EUC-KR(949) likewise. Rare on a Chinese lab host.
static bool is_dbcs(UINT cp) {
    return cp == 936 || cp == 950;
}

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
    int wr = MultiByteToWideChar(from, 0, data, (int)n, &ws[0], w);
    if (wr <= 0) return "";
    ws.resize(wr);   // don't trust the probe length blindly
    // lpDefaultChar/lpUsedDefaultChar must be NULL for CP_UTF8 (and flags=0
    // already gives the default '?' replacement for unmappable chars elsewhere)
    int m = WideCharToMultiByte(to, 0, ws.c_str(), (int)ws.size(), nullptr, 0, nullptr, nullptr);
    if (m <= 0) return "";
    std::string out(m, 0);
    int mr = WideCharToMultiByte(to, 0, ws.c_str(), (int)ws.size(), &out[0], m, nullptr, nullptr);
    if (mr <= 0) return "";
    out.resize(mr);
    return out;
}

std::string cp_oem2utf8(const char* data, size_t n, std::string& carry) {
    std::string all = carry + std::string(data, n);
    carry.clear();
    size_t end = all.size();
    if (g_oemcp == 65001) {
        // UTF-8: drop an incomplete trailing sequence
        size_t i = end;
        while (i > 0 && (all[i - 1] & 0xC0) == 0x80) i--;
        if (i > 0) {
            unsigned char lead = (unsigned char)all[i - 1];
            int need = (lead & 0x80) == 0 ? 1 :
                       (lead & 0xE0) == 0xC0 ? 2 :
                       (lead & 0xF0) == 0xE0 ? 3 :
                       (lead & 0xF8) == 0xF0 ? 4 : 1;
            int have = (int)(end - (i - 1));
            if (have < need) { carry = all.substr(i - 1); end = i - 1; }
        }
    } else if (is_dbcs(g_oemcp)) {
        // DBCS: forward-parse from the (known) boundary. A lead byte 0x81..0xFE
        // consumes the next byte as its trail; a lone trailing lead is carried.
        // (A backward parity count would mis-fire on GBK trails in 0x40..0x7E.)
        size_t i = 0;
        while (i < all.size()) {
            unsigned char c = (unsigned char)all[i];
            if (c >= 0x81 && c <= 0xFE) {
                if (i + 1 < all.size()) i += 2; else break;
            } else i += 1;
        }
        end = i;
        if (end < all.size()) carry.assign(1, all[end]);
    }
    // SBCS: every byte is one char, no carry needed.
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
