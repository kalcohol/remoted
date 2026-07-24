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
    if (!GetCommState(h_, &dcb)) {
        LOG("serial GetCommState failed %s err=%lu", com.c_str(), GetLastError());
        close();
        return false;
    }
    dcb.BaudRate = baud;
    dcb.ByteSize = 8; dcb.Parity = NOPARITY; dcb.StopBits = ONESTOPBIT;
    dcb.fBinary = TRUE; dcb.fParity = FALSE;
    // no flow control; drive DTR/RTS so USB-serial / MAX3232 powered off
    // these lines actually transceive; keep null bytes (binary-safe).
    dcb.fOutxCtsFlow = FALSE; dcb.fOutxDsrFlow = FALSE;
    dcb.fOutX = FALSE; dcb.fInX = FALSE;
    dcb.fDtrControl = DTR_CONTROL_ENABLE;
    dcb.fRtsControl = RTS_CONTROL_ENABLE;
    dcb.fNull = FALSE;
    if (!SetCommState(h_, &dcb)) {
        // running at the driver's default settings (e.g. 9600) would produce
        // garbage while claiming success - fail loudly instead
        LOG("serial SetCommState failed %s err=%lu", com.c_str(), GetLastError());
        close();
        return false;
    }
    // MAXDWORD interval + zero totals would complete EVERY read immediately
    // (0 bytes included) and spin the reader at 100% CPU. The documented
    // pattern for "return at once if bytes are buffered, otherwise wait up to
    // N ms" is MAXDWORD interval + zero multiplier + N as the constant - which
    // is exactly our 100ms poll cadence, enforced driver-side.
    COMMTIMEOUTS to{};
    to.ReadIntervalTimeout = MAXDWORD;
    to.ReadTotalTimeoutConstant = 100;
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
    if (!ev) { LOG("serial: CreateEvent failed err=%lu", GetLastError()); return -1; }
    OVERLAPPED ov{}; ov.hEvent = ev;
    DWORD got = 0;
    BOOL ok = ReadFile(h_, buf, (DWORD)len, &got, &ov);
    int ret;
    if (!ok) {
        DWORD e = GetLastError();
        if (e == ERROR_IO_PENDING) {
            DWORD r = WaitForSingleObject(ev, timeout_ms);
            if (r == WAIT_OBJECT_0) {
                // device yanked mid-read completes the IRP with an ERROR - the
                // event still signals, so check the result, not just the wait
                if (!GetOverlappedResult(h_, &ov, &got, FALSE)) ret = -1;
                else ret = (int)got;
            }
            else {
                CancelIo(h_);
                // reap the IRP: if it completed between the timeout and the
                // cancel, those bytes are real data - don't drop them
                if (GetOverlappedResult(h_, &ov, &got, TRUE)) ret = (int)got;
                else ret = 0;
            }
        } else ret = -1;
    } else ret = (int)got;
    CloseHandle(ev);
    return ret;
}

int SerialPort::write(const void* buf, int len) {
    if (!ok() || len <= 0) return 0;
    HANDLE ev = CreateEvent(nullptr, TRUE, FALSE, nullptr);
    if (!ev) { LOG("serial: CreateEvent failed err=%lu", GetLastError()); return -1; }
    OVERLAPPED ov{}; ov.hEvent = ev;
    DWORD wrote = 0;
    BOOL ok = WriteFile(h_, buf, (DWORD)len, &wrote, &ov);
    int ret;
    if (!ok) {
        DWORD e = GetLastError();
        if (e == ERROR_IO_PENDING) {
            DWORD r = WaitForSingleObject(ev, 2000);
            if (r == WAIT_OBJECT_0) {
                if (!GetOverlappedResult(h_, &ov, &wrote, FALSE)) ret = -1;
                else ret = (int)wrote;
            }
            else { CancelIo(h_); GetOverlappedResult(h_, &ov, &wrote, TRUE); LOG("serial write timeout (%d bytes)", len); ret = (int)wrote; }
        } else ret = -1;
    } else ret = (int)wrote;
    CloseHandle(ev);
    return ret;
}
