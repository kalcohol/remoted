#pragma once
#include <string>
#include <windows.h>

inline std::wstring utf8_to_wide(const std::string& s) {
    int w = MultiByteToWideChar(CP_UTF8, 0, s.c_str(), (int)s.size(), nullptr, 0);
    std::wstring r(w, 0);
    MultiByteToWideChar(CP_UTF8, 0, s.c_str(), (int)s.size(), &r[0], w);
    return r;
}

inline std::string wide_to_utf8(const std::wstring& s) {
    int n = WideCharToMultiByte(CP_UTF8, 0, s.c_str(), (int)s.size(), nullptr, 0, nullptr, nullptr);
    std::string r(n, 0);
    WideCharToMultiByte(CP_UTF8, 0, s.c_str(), (int)s.size(), &r[0], n, nullptr, nullptr);
    return r;
}

// create a directory recursively (CreateDirectoryW is single-level only)
inline void ensure_dir(const std::string& dir) {
    std::wstring w = utf8_to_wide(dir);
    for (size_t i = 1; i < w.size(); ++i) {   // i=1: skip a UNC/drive leading separator
        if (w[i] == L'\\' || w[i] == L'/') {
            wchar_t c = w[i]; w[i] = 0;
            CreateDirectoryW(w.c_str(), nullptr);   // "already exists" is fine
            w[i] = c;
        }
    }
    CreateDirectoryW(w.c_str(), nullptr);
}
