#pragma once
#include <string>
#include <windows.h>
#include <cstdint>

// Exclusive COM port handle using overlapped I/O.
class SerialPort {
public:
    SerialPort() = default;
    ~SerialPort();
    bool open(const std::string& com, uint32_t baud);
    void close();
    bool ok() const { return h_ != INVALID_HANDLE_VALUE; }
    // blocking read up to len bytes (returns 0 on timeout, <0 on error)
    int  read(void* buf, int len, DWORD timeout_ms = 50);
    int  write(const void* buf, int len);
private:
    HANDLE h_  = INVALID_HANDLE_VALUE;
};
