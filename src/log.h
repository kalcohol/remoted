#pragma once
#include <string>

void log_init(const std::wstring& path);
void log_line(const char* fmt, ...);

#define LOG(...) log_line(__VA_ARGS__)
