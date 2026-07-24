#include "ssh_internal.h"

#include <ioapiset.h>
#include <objbase.h>
#include <cstring>

ssh_channel accept_channel(ssh_session s) {
    for (int i = 0; i < 32; ++i) {   // budget: a client must not stall us here forever
        ssh_message msg = ssh_message_get(s);
        if (!msg) return nullptr;
        if (ssh_message_type(msg) == SSH_REQUEST_CHANNEL_OPEN &&
            ssh_message_subtype(msg) == SSH_CHANNEL_SESSION) {
            ssh_channel ch = ssh_message_channel_request_open_reply_accept(msg);
            ssh_message_free(msg);
            return ch;
        }
        ssh_message_reply_default(msg);
        ssh_message_free(msg);
    }
    LOG("accept_channel: request budget exhausted - dropping");
    return nullptr;
}

ChanReq wait_channel_requests(ssh_session s, bool allow_pty) {
    ChanReq r;
    for (int i = 0; i < 64 && !(r.shell || r.exec); ++i) {
        ssh_message msg = ssh_message_get(s);
        if (!msg) break;
        if (ssh_message_type(msg) == SSH_REQUEST_CHANNEL) {
            int st = ssh_message_subtype(msg);
            if (st == SSH_CHANNEL_REQUEST_PTY) {
                // honor the key's no-pty option; remoted has no real pty anyway,
                // refusing is honest and the shell works fine without one
                if (allow_pty) ssh_message_channel_request_reply_success(msg);
                else ssh_message_reply_default(msg);
            }
            else if (st == SSH_CHANNEL_REQUEST_WINDOW_CHANGE){ ssh_message_channel_request_reply_success(msg); }
            else if (st == SSH_CHANNEL_REQUEST_ENV)          { ssh_message_channel_request_reply_success(msg); }
            else if (st == SSH_CHANNEL_REQUEST_SHELL)        { ssh_message_channel_request_reply_success(msg); r.shell = true; }
            else if (st == SSH_CHANNEL_REQUEST_EXEC) {
                const char* cmd = ssh_message_channel_request_command(msg);
                r.exec_cmd = cmd ? cmd : "";
                ssh_message_channel_request_reply_success(msg);
                r.exec = true;
            } else ssh_message_reply_default(msg);
        } else ssh_message_reply_default(msg);
        ssh_message_free(msg);
    }
    return r;
}

void send_motd(ssh_channel ch, App& app) {
    std::string m = "\r\n=== remoted ===\r\nSerial consoles (ssh alias / ssh -p <port>):\r\n";
    for (auto& st : app.snapshot()) {
        std::string state;
        if (!st.present) state = "[absent]";
        else if (st.holders.empty()) state = "[ready]";
        else {
            state = "[in-use: "; bool first = true;
            for (const auto& hp : st.holders) { if (!first) state += ", "; state += hp.second; first = false; }
            state += "]";
        }
        m += "  " + st.name + "  " + st.com + "  :" + std::to_string(st.listen_port) + "  " + state + "\r\n";
    }
    m += "================\r\n\r\n";
    ch_write_str(ch, m);
}

// unguessable pipe name (a predictable name would let any same-user process
// connect as the pipe client and inject data into the shell's output stream)
static std::wstring pipe_name() {
    GUID g{};
    CoCreateGuid(&g);
    wchar_t buf[48] = {};
    StringFromGUID2(g, buf, 48);
    return L"\\\\.\\pipe\\remoted_" + std::wstring(buf);
}

// anonymous pipe whose READ end is overlapped, so CancelIoEx can cancel a
// blocked read on teardown (closing a handle does NOT cancel in-flight sync I/O,
// and a synchronous pipe read can't otherwise be interrupted).
static bool make_overlapped_pipe(HANDLE& rd, HANDLE& wr) {
    std::wstring name = pipe_name();
    rd = CreateNamedPipeW(name.c_str(), PIPE_ACCESS_INBOUND | FILE_FLAG_OVERLAPPED,
                          PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT, 1, 8192, 8192, 0, nullptr);
    if (rd == INVALID_HANDLE_VALUE) return false;
    SECURITY_ATTRIBUTES sa{ sizeof(sa), nullptr, TRUE };
    wr = CreateFileW(name.c_str(), GENERIC_WRITE, 0, &sa, OPEN_EXISTING, 0, nullptr);
    if (wr == INVALID_HANDLE_VALUE) { CloseHandle(rd); rd = INVALID_HANDLE_VALUE; return false; }
    return true;
}

// same idea for the child's stdin: OUR write end is overlapped, so a child that
// stops reading can't pin the session in a blocking WriteFile. The child's read
// end is a plain synchronous handle.
static bool make_overlapped_pipe_out(HANDLE& rd, HANDLE& wr) {
    std::wstring name = pipe_name();
    wr = CreateNamedPipeW(name.c_str(), PIPE_ACCESS_OUTBOUND | FILE_FLAG_OVERLAPPED,
                          PIPE_TYPE_BYTE | PIPE_WAIT, 1, 8192, 8192, 0, nullptr);
    if (wr == INVALID_HANDLE_VALUE) return false;
    SECURITY_ATTRIBUTES sa{ sizeof(sa), nullptr, TRUE };
    rd = CreateFileW(name.c_str(), GENERIC_READ, 0, &sa, OPEN_EXISTING, 0, nullptr);
    if (rd == INVALID_HANDLE_VALUE) { CloseHandle(wr); wr = INVALID_HANDLE_VALUE; return false; }
    return true;
}

// bounded overlapped write to child stdin; polls abort while the pipe is full
// and gives up after 3s, so teardown always stays responsive
static bool write_all_ov(HANDLE h, const char* data, size_t n,
                         const std::shared_ptr<std::atomic<bool>>& abort) {
    HANDLE ev = CreateEvent(nullptr, TRUE, FALSE, nullptr);
    if (!ev) { LOG("write_all_ov: CreateEvent failed err=%lu", GetLastError()); return false; }
    size_t off = 0;
    bool ok = true;
    while (ok && off < n) {
        OVERLAPPED ov{}; ov.hEvent = ev;
        ResetEvent(ev);
        DWORD w = 0;
        if (!WriteFile(h, data + off, (DWORD)(n - off), &w, &ov)) {
            if (GetLastError() != ERROR_IO_PENDING) { ok = false; break; }
            ULONGLONG t0 = GetTickCount64();
            for (;;) {
                if (WaitForSingleObject(ev, 100) == WAIT_OBJECT_0) break;
                if (abort->load() || GetTickCount64() - t0 > 3000) {
                    CancelIoEx(h, &ov);
                    DWORD tmp = 0; GetOverlappedResult(h, &ov, &tmp, TRUE);   // reap
                    ok = false;
                    break;
                }
            }
            if (!ok) break;
            if (!GetOverlappedResult(h, &ov, &w, FALSE)) { ok = false; break; }
        }
        if (w == 0) ok = false;
        else off += w;
    }
    CloseHandle(ev);
    return ok;
}

// ---- child process pump (pipes + OEM<->UTF-8 transcoding) ----
// exec: cmd /C <cmd>. interactive shell: cmd /K with local echo + \r->\r\n.
// All ssh_channel_* calls are on this thread only; the reader pushes child
// output (already converted to UTF-8) into a queue. The stdout read end is an
// overlapped pipe so we can CancelIoEx it on teardown -> the reader always
// unblocks and join() never deadlocks (even if a grandchild holds the pipe).
void run_shell(ssh_channel ch, const std::string& shell_dir, bool exec, const std::string& exec_cmd,
               const std::shared_ptr<std::atomic<bool>>& abort) {
    std::wstring cmdline = exec ? (L"cmd.exe /C " + utf8_to_wide(exec_cmd)) : L"cmd.exe /K";
    std::wstring cwd = utf8_to_wide(shell_dir);

    HANDLE cInR, cInW;
    if (!make_overlapped_pipe_out(cInR, cInW)) return;
    SetHandleInformation(cInW, HANDLE_FLAG_INHERIT, 0);
    HANDLE cOutR, cOutW;
    if (!make_overlapped_pipe(cOutR, cOutW)) { CloseHandle(cInR); CloseHandle(cInW); return; }

    // whitelist only the two pipe ends for inheritance: bInheritHandles=TRUE
    // would otherwise hand the child every inheritable handle in the process
    // (other sessions' pipes, listen/session sockets...)
    PROCESS_INFORMATION pi{};
    HANDLE inherit_list[2] = { cInR, cOutW };
    SIZE_T alen = 0;
    InitializeProcThreadAttributeList(nullptr, 1, 0, &alen);   // alen query (fails by design)
    std::vector<BYTE> abuf(alen);
    auto alist = (LPPROC_THREAD_ATTRIBUTE_LIST)abuf.data();
    STARTUPINFOEXW six{};
    BOOL ok = FALSE;
    bool used_ex = false;
    if (alen && InitializeProcThreadAttributeList(alist, 1, 0, &alen)) {
        if (UpdateProcThreadAttribute(alist, 0, PROC_THREAD_ATTRIBUTE_HANDLE_LIST,
                                      inherit_list, sizeof(inherit_list), nullptr, nullptr)) {
            used_ex = true;
            six.StartupInfo.cb = sizeof(six);
            six.StartupInfo.dwFlags = STARTF_USESTDHANDLES;
            six.StartupInfo.hStdInput = cInR;
            six.StartupInfo.hStdOutput = cOutW;
            six.StartupInfo.hStdError = cOutW;
            six.lpAttributeList = alist;
            std::vector<wchar_t> cl(cmdline.begin(), cmdline.end()); cl.push_back(0);
            ok = CreateProcessW(nullptr, cl.data(), nullptr, nullptr, TRUE,
                                EXTENDED_STARTUPINFO_PRESENT | CREATE_NO_WINDOW, nullptr,
                                cwd.empty() ? nullptr : cwd.c_str(), &six.StartupInfo, &pi);
        }
        DeleteProcThreadAttributeList(alist);
    }
    if (!used_ex) {   // attribute lists unavailable (shouldn't happen on Win10): legacy path
        LOG("proc attribute list unavailable - falling back to full handle inheritance");
        STARTUPINFOW si{}; si.cb = sizeof(si);
        si.dwFlags = STARTF_USESTDHANDLES;
        si.hStdInput = cInR; si.hStdOutput = cOutW; si.hStdError = cOutW;
        std::vector<wchar_t> cl(cmdline.begin(), cmdline.end()); cl.push_back(0);
        ok = CreateProcessW(nullptr, cl.data(), nullptr, nullptr, TRUE,
                            CREATE_NO_WINDOW, nullptr,
                            cwd.empty() ? nullptr : cwd.c_str(), &si, &pi);
    }
    CloseHandle(cInR); CloseHandle(cOutW);
    if (!ok) {
        ch_write_str(ch, "remoted: CreateProcess failed\r\n");
        CloseHandle(cInW); CloseHandle(cOutR);
        return;
    }
    CloseHandle(pi.hThread);   // we don't need the thread handle

    // kill-on-close job: teardown takes down the whole process tree -- a bare
    // TerminateProcess would orphan grandchildren (e.g. a flasher started by a
    // batch file). If job setup fails we fall back to TerminateProcess below.
    HANDLE job = CreateJobObjectW(nullptr, nullptr);
    if (job) {
        JOBOBJECT_EXTENDED_LIMIT_INFORMATION jeli{};
        jeli.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
        if (!SetInformationJobObject(job, JobObjectExtendedLimitInformation, &jeli, sizeof(jeli)) ||
            !AssignProcessToJobObject(job, pi.hProcess)) {
            CloseHandle(job);
            job = nullptr;
        }
    }
    auto kill_tree = [&]() {
        if (job) TerminateJobObject(job, 1);      // kills the whole tree
        else TerminateProcess(pi.hProcess, 1);    // fallback if job setup failed
    };

    // reader: child stdout (OEM) -> UTF-8 -> queue (never touches the channel)
    struct Q { std::mutex m; std::deque<std::string> q; bool eof = false; unsigned dropped = 0; };
    auto Q_ = std::make_shared<Q>();
    auto oemCarry = std::make_shared<std::string>();
    HANDLE readEv = CreateEvent(nullptr, TRUE, FALSE, nullptr);
    HANDLE stopEv = CreateEvent(nullptr, TRUE, FALSE, nullptr);
    if (!readEv || !stopEv) {
        LOG("run_shell: CreateEvent failed err=%lu", GetLastError());
        kill_tree();
        WaitForSingleObject(pi.hProcess, 1000);
        if (readEv) CloseHandle(readEv);
        if (stopEv) CloseHandle(stopEv);
        CloseHandle(cInW); CloseHandle(cOutR);
        if (job) CloseHandle(job);
        CloseHandle(pi.hProcess);
        return;
    }
    std::thread reader([cOutR, readEv, stopEv, Q_, oemCarry]() {
        char b[8192]; DWORD n;
        for (;;) {
            OVERLAPPED ov{}; ov.hEvent = readEv;
            ResetEvent(readEv);
            BOOL ok = ReadFile(cOutR, b, sizeof b, &n, &ov);
            if (ok) { if (n == 0) break; }
            else if (GetLastError() == ERROR_IO_PENDING) {
                HANDLE hs[2] = { readEv, stopEv };
                DWORD w = WaitForMultipleObjects(2, hs, FALSE, INFINITE);
                if (w == WAIT_OBJECT_0 + 1) {   // stop: cancel even a freshly-pending read
                    CancelIoEx(cOutR, &ov);
                    DWORD got = 0; GetOverlappedResult(cOutR, &ov, &got, TRUE);
                    break;
                }
                DWORD got = 0;
                if (!GetOverlappedResult(cOutR, &ov, &got, FALSE)) break;  // cancelled / error
                n = got;
                if (n == 0) break;
            } else break;
            std::string s = cp_oem2utf8(b, n, *oemCarry);
            if (!s.empty()) {
                std::lock_guard<std::mutex> lk(Q_->m);
                if (Q_->q.size() < 256) Q_->q.push_back(s);   // cap: drop if the main loop is slow
                // rate-limited: first drop + every 100th, not per chunk
                else if (++Q_->dropped == 1 || Q_->dropped % 100 == 0)
                    LOG("shell output queue full; %u chunk(s) dropped", Q_->dropped);
            }
        }
        std::lock_guard<std::mutex> lk(Q_->m);
        Q_->eof = true;
    });

    // drain queued child output to the channel; false = channel write failed
    auto drain = [&]() -> bool {
        std::vector<std::string> popped;
        {
            std::lock_guard<std::mutex> lk(Q_->m);
            popped.reserve(Q_->q.size());
            while (!Q_->q.empty()) { popped.emplace_back(std::move(Q_->q.front())); Q_->q.pop_front(); }
        }
        for (const auto& s : popped)   // write outside the lock
            if (!ch_write_all(ch, s.data(), s.size())) return false;
        return true;
    };

    char buf[4096];
    std::string u2oCarry;
    bool stdinClosed = false, childDone = false;
    while (true) {
        if (abort->load()) break;
        if (!drain()) break;

        if (!stdinClosed && ssh_channel_is_eof(ch)) {
            CloseHandle(cInW); cInW = INVALID_HANDLE_VALUE; stdinClosed = true;
        }

        int avail = ssh_channel_poll_timeout(ch, 50, 0);
        if (avail > 0) {
            int rd = (avail < (int)sizeof buf) ? avail : (int)sizeof buf;
            int r = ssh_channel_read(ch, buf, (uint32_t)rd, 0);
            if (r > 0) {
                if (exec) {
                    std::string oem = cp_utf82oem(buf, r, u2oCarry);   // transcode stdin too (text scripts)
                    if (cInW != INVALID_HANDLE_VALUE && !oem.empty() && !write_all_ov(cInW, oem.data(), oem.size(), abort)) {
                        LOG("child stdin write failed (pipe full / broken) - closing stdin");
                        CloseHandle(cInW); cInW = INVALID_HANDLE_VALUE; stdinClosed = true;
                    }
                } else {
                    if (!ch_write_all(ch, buf, (size_t)r)) break;   // local echo
                    std::string exp; exp.reserve(r + 8);
                    for (int i = 0; i < r; ++i) exp += (buf[i] == '\r') ? std::string("\r\n") : std::string(1, buf[i]);
                    std::string oem = cp_utf82oem(exp.data(), exp.size(), u2oCarry);
                    if (!oem.empty() && cInW != INVALID_HANDLE_VALUE && !write_all_ov(cInW, oem.data(), oem.size(), abort)) {
                        LOG("child stdin write failed (pipe full / broken) - closing stdin");
                        CloseHandle(cInW); cInW = INVALID_HANDLE_VALUE; stdinClosed = true;
                    }
                }
            }
        }

        { std::lock_guard<std::mutex> lk(Q_->m); childDone = Q_->eof; }
        if (childDone) { drain(); break; }
        if (ssh_channel_is_closed(ch)) break;
    }

    if (cInW != INVALID_HANDLE_VALUE) { CloseHandle(cInW); cInW = INVALID_HANDLE_VALUE; }
    if (abort->load() || !childDone) kill_tree();
    // if the process survives the wait (e.g. it ignored nothing but is stuck),
    // don't let it leak: kill and reap once more
    if (WaitForSingleObject(pi.hProcess, 3000) == WAIT_TIMEOUT) {
        LOG("child still alive after 3s wait - killing");
        kill_tree();
        WaitForSingleObject(pi.hProcess, 1000);
    }
    if (exec) {   // only exec has a meaningful exit code (interactive shells don't)
        DWORD code = 1;
        GetExitCodeProcess(pi.hProcess, &code);
        if (code == STILL_ACTIVE) code = 1;
        ssh_channel_request_send_exit_status(ch, (int)code);
    }
    CancelIoEx(cOutR, nullptr);   // cancel any in-flight overlapped read on cOutR
    SetEvent(stopEv);              // also wakes a read that pended AFTER the cancel
    reader.join();
    CloseHandle(readEv);
    CloseHandle(stopEv);
    CloseHandle(cOutR);
    if (job) CloseHandle(job);   // KILL_ON_JOB_CLOSE sweeps up any surviving grandchildren
    CloseHandle(pi.hProcess);
}

void shell_session(ssh_session s, App* app) {
    auto keys = load_auth_keys(app->authorized_keys_path());
    auto abort = reg_abort();   // early: covers the pre-auth phase too (disconnect-all)
    Auth a = authenticate(s, keys, abort);
    free_keys(keys);
    if (!a.ok) { unreg_abort(abort); notify_unknown_key(app, a.fp); return; }
    std::string who = display_name(app, a);
    LOG("shell session auth ok: %s (%s)", who.c_str(), a.fp.c_str());
    int tok = app->session_start("shell", who);
    Guard g([&]() { unreg_abort(abort); app->session_end(tok); });

    ssh_channel ch = accept_channel(s);
    if (!ch) return;
    ChanReq rq = wait_channel_requests(s, !a.opts.no_pty);

    if (!rq.shell && !rq.exec) {   // client asked for neither (or stalled past the budget)
        ch_write_str(ch, "remoted: no shell or exec requested\r\n");
        ssh_channel_send_eof(ch); ssh_channel_close(ch); ssh_channel_free(ch);
        return;   // guard releases occupancy
    }

    // a forced command replaces whatever the client asked for
    bool exec = rq.exec;
    std::string cmd = rq.exec_cmd;
    if (!a.opts.forced_command.empty()) { exec = true; cmd = a.opts.forced_command; }

    if (!exec) send_motd(ch, *app);
    run_shell(ch, app->shell_dir(), exec, cmd, abort);
    ssh_channel_send_eof(ch); ssh_channel_close(ch); ssh_channel_free(ch);
}
