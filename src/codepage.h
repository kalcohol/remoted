#pragma once
#include <string>
#include <windows.h>

// Read the system OEM codepage from the registry (our manifest forces this
// process to UTF-8, so GetOEMCP() would wrongly return 65001 - but the child
// cmd.exe still uses the real system OEM page, e.g. 936/GBK).
void cp_init();

// Convert between the child's OEM codepage and UTF-8, carrying any incomplete
// trailing bytes across calls (4KB read blocks can split a multibyte char).
std::string cp_oem2utf8(const char* data, size_t n, std::string& carry);
std::string cp_utf82oem(const char* data, size_t n, std::string& carry);
