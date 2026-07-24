#include "ssh_internal.h"

#include <ioapiset.h>
#include <cstring>

ssh_channel accept_channel(ssh_session s) {
    while (true) {
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
}

ChanReq wait_channel_requests(ssh_session s) {
    ChanReq r;
    for (int i = 0; i < 64 && !(r.shell || r.exec); ++i) {
        ssh_message msg = ssh_message_get(s);
        if (!msg) break;
        if (ssh_message_type(msg) == SSH_REQUEST_CHANNEL) {
            int st = ssh_message_subtype(msg);
            if (st == SSH_CHANNEL_REQUEST_PTY)               { ssh_message_channel_request_reply_success(msg); }
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
    ssh_channel_write(ch, m.data(), (uint32_t)m.size());
}

// anonymous pipe whose READ end is overlapped, so CancelIoEx can cancel a
// blocked read on teardown (closing a handle does NOT cancel in-flight sync I/O,
// and a synchronous pipe read can't otherwise be interrupted).
static std::atomic<unsigned> g_pipe_seq{0};
static bool make_overlapped_pipe(HANDLE& rd, HANDLE& wr) {
    std::wstring name = L"\\\\.\\pipe\\remoted_anon_" + std::to_wstring(GetCurrentProcessId())
                        + L"_" + std::to_wstring(g_pipe_seq.fetch_add(1));
    rd = CreateNamedPipeW(name.c_str(), PIPE_ACCESS_INBOUND | FILE_FLAG_OVERLAPPED,
                          PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT, 1, 8192, 8192, 0, nullptr);
    if (rd == INVALID_HANDLE_VALUE) return false;
    SECURITY_ATTRIBUTES sa{ sizeof(sa), nullptr, TRUE };
    wr = CreateFileW(name.c_str(), GENERIC_WRITE, 0, &sa, OPEN_EXISTING, 0, nullptr);
    if (wr == INVALID_HANDLE_VALUE) { CloseHandle(rd); rd = INVALID_HANDLE_VALUE; return false; }
    return true;
}

// ---- child process pump (pipes + OEM<->UTF-8 transcoding) ----
// exec: cmd /C <cmd>. interactive shell: cmd /K with local echo + \r->\r\n.
// All ssh_channel_* calls are on this thread only; the reader pushes child
// output (already converted to UTF-8) into a queue. The stdout read end is an
// overlapped pipe so we can CancelIoEx it on teardown -> the reader always
// unblocks and join() never deadlocks (even if a grandchild holds the pipe).
void run_shell(ssh_channel ch, const AppConfig& cfg, bool exec, const std::string& exec_cmd,
               const std::shared_ptr<std::atomic<bool>>& abort) {
    std::wstring cmdline = exec ? (L"cmd.exe /C " + utf8_to_wide(exec_cmd)) : L"cmd.exe /K";
    std::wstring cwd = utf8_to_wide(cfg.shell_dir);

    SECURITY_ATTRIBUTES sa{ sizeof(sa), nullptr, TRUE };
    HANDLE cInR, cInW;
    if (!CreatePipe(&cInR, &cInW, &sa, 0)) return;
    SetHandleInformation(cInW, HANDLE_FLAG_INHERIT, 0);
    HANDLE cOutR, cOutW;
    if (!make_overlapped_pipe(cOutR, cOutW)) { CloseHandle(cInR); CloseHandle(cInW); return; }

    STARTUPINFOW si{}; si.cb = sizeof(si);
    si.dwFlags = STARTF_USESTDHANDLES;
    si.hStdInput = cInR; si.hStdOutput = cOutW; si.hStdError = cOutW;
    PROCESS_INFORMATION pi{};
    std::vector<wchar_t> cl(cmdline.begin(), cmdline.end()); cl.push_back(0);
    BOOL ok = CreateProcessW(nullptr, cl.data(), nullptr, nullptr, TRUE,
                             CREATE_NO_WINDOW, nullptr,
                             cwd.empty() ? nullptr : cwd.c_str(), &si, &pi);
    CloseHandle(cInR); CloseHandle(cOutW);
    if (!ok) {
        const char* e = "remoted: CreateProcess failed\r\n";
        ssh_channel_write(ch, e, (uint32_t)strlen(e));
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

    // reader: child stdout (OEM) -> UTF-8 -> queue (never touches the channel)
    struct Q { std::mutex m; std::deque<std::string> q; bool eof = false; unsigned dropped = 0; };
    auto Q_ = std::make_shared<Q>();
    auto oemCarry = std::make_shared<std::string>();
    HANDLE readEv = CreateEvent(nullptr, TRUE, FALSE, nullptr);
    HANDLE stopEv = CreateEvent(nullptr, TRUE, FALSE, nullptr);
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

    auto drain = [&]() {
        std::vector<std::string> popped;
        {
            std::lock_guard<std::mutex> lk(Q_->m);
            popped.reserve(Q_->q.size());
            while (!Q_->q.empty()) { popped.emplace_back(std::move(Q_->q.front())); Q_->q.pop_front(); }
        }
        for (const auto& s : popped) ssh_channel_write(ch, s.data(), (uint32_t)s.size());   // write outside the lock
    };

    char buf[4096];
    std::string u2oCarry;
    bool stdinClosed = false, childDone = false;
    while (true) {
        if (abort->load()) break;
        drain();

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
                    DWORD w = 0; if (cInW != INVALID_HANDLE_VALUE && !oem.empty()) WriteFile(cInW, oem.data(), (DWORD)oem.size(), &w, nullptr);
                } else {
                    ssh_channel_write(ch, buf, (uint32_t)r);
                    std::string exp; exp.reserve(r + 8);
                    for (int i = 0; i < r; ++i) exp += (buf[i] == '\r') ? std::string("\r\n") : std::string(1, buf[i]);
                    std::string oem = cp_utf82oem(exp.data(), exp.size(), u2oCarry);
                    if (!oem.empty() && cInW != INVALID_HANDLE_VALUE) {
                        DWORD w = 0; WriteFile(cInW, oem.data(), (DWORD)oem.size(), &w, nullptr);
                    }
                }
            }
        }

        { std::lock_guard<std::mutex> lk(Q_->m); childDone = Q_->eof; }
        if (childDone) { drain(); break; }
        if (ssh_channel_is_closed(ch)) break;
    }

    if (cInW != INVALID_HANDLE_VALUE) { CloseHandle(cInW); cInW = INVALID_HANDLE_VALUE; }
    if (abort->load() || !childDone) {
        if (job) TerminateJobObject(job, 1);      // kills the whole tree
        else TerminateProcess(pi.hProcess, 1);    // fallback if job setup failed
    }
    WaitForSingleObject(pi.hProcess, 3000);
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
    auto keys = load_auth_keys(app->cfg.authorized_keys);
    Auth a = authenticate(s, keys);
    free_keys(keys);
    if (!a.ok) { notify_unknown_key(app, a.fp); return; }
    std::string who = display_name(app, a);
    LOG("shell session auth ok: %s (%s)", who.c_str(), a.fp.c_str());
    int tok = app->session_start("shell", who);
    auto abort = reg_abort();
    Guard g([&]() { unreg_abort(abort); app->session_end(tok); });

    ssh_channel ch = accept_channel(s);
    if (!ch) return;
    ChanReq rq = wait_channel_requests(s);
    if (!rq.exec) send_motd(ch, *app);
    run_shell(ch, app->cfg, rq.exec, rq.exec_cmd, abort);
    ssh_channel_send_eof(ch); ssh_channel_close(ch); ssh_channel_free(ch);
}
