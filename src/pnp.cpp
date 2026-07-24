#include "pnp.h"
#include "util.h"
#include "log.h"
#include <windows.h>
#include <setupapi.h>
#include <initguid.h>
#include <devpkey.h>
#include <regex>
#include <algorithm>
#include <cctype>
#include <mutex>

// {4d36e978-e325-11ce-bfc1-08002be10318}  Ports class
static const GUID GUID_DEVCLASS_PORTS = {
    0x4d36e978, 0xe325, 0x11ce, {0xbf,0xc1,0x08,0x00,0x2b,0xe1,0x03,0x18} };

static std::string lower(std::string s) {
    std::transform(s.begin(), s.end(), s.begin(),
                   [](unsigned char ch){ return (char)std::tolower(ch); });
    return s;
}

std::vector<EnumCom> enumerate_com_ports() {
    std::vector<EnumCom> out;
    HDEVINFO h = SetupDiGetClassDevsW(&GUID_DEVCLASS_PORTS, nullptr, nullptr, DIGCF_PRESENT);
    if (h == INVALID_HANDLE_VALUE) return out;

    SP_DEVINFO_DATA d; d.cbSize = sizeof(d);
    static const std::wregex re_com(L"\\(COM(\\d+)\\)");

    for (DWORD i = 0; SetupDiEnumDeviceInfo(h, i, &d); ++i) {
        wchar_t fname[256] = {};
        DWORD pt = 0;
        if (!SetupDiGetDevicePropertyW(h, &d, &DEVPKEY_Device_FriendlyName,
                &pt, (PBYTE)fname, sizeof(fname), nullptr, 0)) {
            SetupDiGetDeviceRegistryPropertyW(h, &d, SPDRP_FRIENDLYNAME,
                nullptr, (PBYTE)fname, sizeof(fname), nullptr);
        }
        std::wstring ws(fname);
        std::wsmatch m;
        if (!std::regex_search(ws, m, re_com)) continue;

        EnumCom e;
        e.com = "COM" + wide_to_utf8(m[1].str());

        wchar_t par[512] = {}; DWORD pt2 = 0;
        SetupDiGetDevicePropertyW(h, &d, &DEVPKEY_Device_Parent,
            &pt2, (PBYTE)par, sizeof(par), nullptr, 0);
        e.parent = wide_to_utf8(par);

        out.push_back(e);
    }
    SetupDiDestroyDeviceInfoList(h);

    // this runs on every status query / connection: only log when the set
    // actually changes, or routine MOTDs bury real diagnostics
    static std::mutex* cache_m = new std::mutex();                            // leaked: exit-safe
    static std::vector<std::string>* prev = new std::vector<std::string>();
    std::vector<std::string> cur;
    for (const auto& e : out) cur.push_back(e.com + "|" + e.parent);
    {
        std::lock_guard<std::mutex> lk(*cache_m);
        if (cur != *prev) {
            for (const auto& e : out) LOG("enum: %-7s parent=%s", e.com.c_str(), e.parent.c_str());
            *prev = std::move(cur);
        }
    }
    return out;
}

std::string resolve_com(const SerialCfg& cfg, const std::vector<EnumCom>& devs) {
    if (!cfg.usb_id.empty()) {
        std::string id = lower(cfg.usb_id);
        for (const auto& e : devs)
            if (lower(e.parent).find(id) != std::string::npos) return e.com;
    }
    return cfg.com;
}
