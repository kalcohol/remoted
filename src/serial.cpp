#include "serial.h"
#include "util.h"
#include "log.h"
#include <windows.h>

SerialPort::~SerialPort() { close(); }

bool SerialPort::open(const std::string& com, uint32_t baud) {
    close();
    std::wstring dev = L"\\\\.\\" + utf8_to_wide(com);
    h_ = CreateFileW(dev.c_str(), GENERIC_READ | GENERIC_WRITE, 0,
                     nullptr, OPEN_EXISTING, FILE_FLAG_OVERLAPPED, nullptr);
    if (h_ == INVALID_HANDLE_VALUE) {
        LOG("serial open failed %s err=%lu", com.c_str(), GetLastError());
        return false;
    }
    DCB dcb{}; dcb.DCBlength = sizeof(dcb);
    if (GetCommState(h_, &dcb)) {
        dcb.BaudRate = baud;
        dcb.ByteSize = 8; dcb.Parity = NOPARITY; dcb.StopBits = ONESTOPBIT;
        dcb.fBinary = TRUE; dcb.fParity = FALSE;
        SetCommState(h_, &dcb);
    }
    COMMTIMEOUTS to{};   // all zero: overlapped reads pend until data arrives
    SetCommTimeouts(h_, &to);
    PurgeComm(h_, PURGE_RXCLEAR | PURGE_TXCLEAR);
    LOG("serial opened %s @%u", com.c_str(), baud);
    return true;
}

void SerialPort::close() {
    if (h_ != INVALID_HANDLE_VALUE) { CloseHandle(h_); h_ = INVALID_HANDLE_VALUE; }
}

int SerialPort::read(void* buf, int len, DWORD timeout_ms) {
    if (!ok()) return -1;
    HANDLE ev = CreateEvent(nullptr, TRUE, FALSE, nullptr);
    OVERLAPPED ov{}; ov.hEvent = ev;
    DWORD got = 0;
    BOOL ok = ReadFile(h_, buf, (DWORD)len, &got, &ov);
    int ret;
    if (!ok) {
        DWORD e = GetLastError();
        if (e == ERROR_IO_PENDING) {
            DWORD r = WaitForSingleObject(ev, timeout_ms);
            if (r == WAIT_OBJECT_0) { GetOverlappedResult(h_, &ov, &got, FALSE); ret = (int)got; }
            else { CancelIo(h_); ret = 0; }
        } else ret = -1;
    } else ret = (int)got;
    CloseHandle(ev);
    return ret;
}

int SerialPort::write(const void* buf, int len) {
    if (!ok() || len <= 0) return 0;
    HANDLE ev = CreateEvent(nullptr, TRUE, FALSE, nullptr);
    OVERLAPPED ov{}; ov.hEvent = ev;
    DWORD wrote = 0;
    BOOL ok = WriteFile(h_, buf, (DWORD)len, &wrote, &ov);
    int ret;
    if (!ok) {
        DWORD e = GetLastError();
        if (e == ERROR_IO_PENDING) { WaitForSingleObject(ev, 2000); GetOverlappedResult(h_, &ov, &wrote, FALSE); ret = (int)wrote; }
        else ret = -1;
    } else ret = (int)wrote;
    CloseHandle(ev);
    return ret;
}
