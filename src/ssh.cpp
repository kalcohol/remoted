#include "ssh.h"
#include "app.h"
#include "serial.h"
#include "pnp.h"
#include "util.h"
#include "log.h"

#include <libssh/libssh.h>
#include <libssh/server.h>

#include <windows.h>
#include <thread>
#include <atomic>
#include <vector>
#include <string>
#include <functional>
#include <fstream>
#include <sstream>
#include <algorithm>

// ---- session registry (for disconnect-all) ----
static std::mutex g_sess_m;
static std::vector<ssh_session> g_sessions;
static std::atomic<bool> g_stop{ false };

static void sess_add(ssh_session s) {
    std::lock_guard<std::mutex> lk(g_sess_m);
    g_sessions.push_back(s);
}
static void sess_remove(ssh_session s) {
    std::lock_guard<std::mutex> lk(g_sess_m);
    g_sessions.erase(std::remove(g_sessions.begin(), g_sessions.end(), s), g_sessions.end());
}

void ssh_disconnect_all() {
    std::vector<ssh_session> copy;
    { std::lock_guard<std::mutex> lk(g_sess_m); copy = g_sessions; }
    LOG("disconnect-all: %d sessions", (int)copy.size());
    for (auto s : copy) ssh_disconnect(s);
}

// ---- host key ----
static void ensure_host_key(const std::string& path) {
    ssh_key k = nullptr;
    if (ssh_pki_import_privkey_file(path.c_str(), nullptr, nullptr, nullptr, &k) == SSH_OK) {
        ssh_key_free(k); LOG("host key present: %s", path.c_str()); return;
    }
    auto pos = path.find_last_of("/\\");
    if (pos != std::string::npos) CreateDirectoryW(utf8_to_wide(path.substr(0, pos)).c_str(), nullptr);
    if (ssh_pki_generate(SSH_KEYTYPE_ED25519, 0, &k) == SSH_OK) {
        ssh_pki_export_privkey_file(k, nullptr, nullptr, nullptr, path.c_str());
        ssh_pki_export_pubkey_file(k, (path + ".pub").c_str());
        ssh_key_free(k);
        LOG("generated host key: %s", path.c_str());
    }
}

// ---- authorized_keys ----
static std::vector<ssh_key> load_auth_keys(const std::string& path) {
    std::vector<ssh_key> keys;
    std::ifstream f(path);
    if (!f) { LOG("authorized_keys not found: %s", path.c_str()); return keys; }
    std::string line;
    while (std::getline(f, line)) {
        if (line.empty() || line[0] == '#') continue;
        std::istringstream is(line);
        std::string type, b64; is >> type >> b64;
        if (type.empty() || b64.empty()) continue;
        ssh_keytypes_e t = ssh_key_type_from_name(type.c_str());
        ssh_key k = nullptr;
        if (ssh_pki_import_pubkey_base64(b64.c_str(), t, &k) == SSH_OK) keys.push_back(k);
    }
    LOG("loaded %d authorized keys", (int)keys.size());
    return keys;
}
static void free_keys(std::vector<ssh_key>& keys) {
    for (auto k : keys) ssh_key_free(k);
    keys.clear();
}

static std::string key_fp(ssh_key k) {
    unsigned char* h = nullptr; size_t hl = 0;
    if (ssh_get_publickey_hash(k, SSH_PUBLICKEY_HASH_SHA256, &h, &hl) != SSH_OK) return "";
    char* s = ssh_get_fingerprint_hash(SSH_PUBLICKEY_HASH_SHA256, h, hl);
    std::string r = s ? s : "";
    ssh_string_free_char(s);
    ssh_clean_pubkey_hash(&h);
    return r;
}

struct Auth { bool ok = false; std::string fp; };

static Auth authenticate(ssh_session s, const std::vector<ssh_key>& keys) {
    ssh_message msg;
    while (true) {
        msg = ssh_message_get(s);
        if (!msg) return {};
        int t = ssh_message_type(msg), st = ssh_message_subtype(msg);
        if (t == SSH_REQUEST_AUTH && st == SSH_AUTH_METHOD_PUBLICKEY) {
            ssh_key off = ssh_message_auth_pubkey(msg);
            if (off) {
                for (ssh_key ak : keys) {
                    if (ssh_key_cmp(off, ak, SSH_KEY_CMP_PUBLIC) == 0) {
                        std::string fp = key_fp(off);
                        ssh_message_auth_reply_success(msg, 0);
                        ssh_message_free(msg);
                        return { true, fp };
                    }
                }
            }
            ssh_message_reply_default(msg);
        } else if (t == SSH_REQUEST_AUTH) {
            ssh_message_auth_set_methods(msg, SSH_AUTH_METHOD_PUBLICKEY);
            ssh_message_reply_default(msg);
        } else {
            ssh_message_reply_default(msg);
        }
        ssh_message_free(msg);
    }
}

static ssh_channel accept_channel(ssh_session s) {
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

struct ChanReq { bool shell = false, exec = false; std::string exec_cmd; };

static ChanReq wait_channel_requests(ssh_session s) {
    ChanReq r;
    for (int i = 0; i < 64 && !(r.shell || r.exec); ++i) {
        ssh_message msg = ssh_message_get(s);
        if (!msg) break;
        if (ssh_message_type(msg) == SSH_REQUEST_CHANNEL) {
            int st = ssh_message_subtype(msg);
            if (st == SSH_CHANNEL_REQUEST_PTY)          { ssh_message_channel_request_reply_success(msg); }
            else if (st == SSH_CHANNEL_REQUEST_WINDOW_CHANGE) { ssh_message_channel_request_reply_success(msg); }
            else if (st == SSH_CHANNEL_REQUEST_ENV)     { ssh_message_channel_request_reply_success(msg); }
            else if (st == SSH_CHANNEL_REQUEST_SHELL)   { ssh_message_channel_request_reply_success(msg); r.shell = true; }
            else if (st == SSH_CHANNEL_REQUEST_EXEC)    {
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

static void send_motd(ssh_channel ch, App& app) {
    std::string m = "\r\n=== remoted ===\r\nSerial consoles (ssh alias / ssh -p <port>):\r\n";
    for (auto& st : app.snapshot()) {
        const char* state = st.busy ? "[in-use]" : (st.present ? "[ready]" : "[absent]");
        m += "  " + st.name + "  " + st.com + "  :" + std::to_string(st.listen_port) + "  " + state + "\r\n";
    }
    m += "================\r\n\r\n";
    ssh_channel_write(ch, m.data(), (uint32_t)m.size());
}

// ---- shell / exec via cmd.exe ----
static void run_shell(ssh_channel ch, const AppConfig& cfg, bool exec, const std::string& exec_cmd) {
    std::wstring cmdline = exec ? (L"cmd.exe /C " + utf8_to_wide(exec_cmd)) : L"cmd.exe /Q";
    std::wstring cwd = utf8_to_wide(cfg.shell_dir);

    SECURITY_ATTRIBUTES sa{ sizeof(sa), nullptr, TRUE };
    HANDLE cInR, cInW, cOutR, cOutW;
    if (!CreatePipe(&cInR, &cInW, &sa, 0)) return;
    SetHandleInformation(cInW, HANDLE_FLAG_INHERIT, 0);
    if (!CreatePipe(&cOutR, &cOutW, &sa, 0)) { CloseHandle(cInR); CloseHandle(cInW); return; }
    SetHandleInformation(cOutR, HANDLE_FLAG_INHERIT, 0);

    STARTUPINFOW si{}; si.cb = sizeof(si);
    si.dwFlags = STARTF_USESTDHANDLES;
    si.hStdInput = cInR; si.hStdOutput = cOutW; si.hStdError = cOutW;
    PROCESS_INFORMATION pi{};

    std::vector<wchar_t> clbuf(cmdline.begin(), cmdline.end()); clbuf.push_back(0);
    BOOL ok = CreateProcessW(nullptr, clbuf.data(), nullptr, nullptr, TRUE,
                             CREATE_NO_WINDOW, nullptr,
                             cwd.empty() ? nullptr : cwd.c_str(), &si, &pi);
    CloseHandle(cInR); CloseHandle(cOutW);
    if (!ok) {
        const char* e = "remoted: failed to spawn shell\r\n";
        ssh_channel_write(ch, e, (uint32_t)strlen(e));
        CloseHandle(cInW); CloseHandle(cOutR);
        return;
    }

    // pipe(stdout) -> channel
    std::thread reader([cOutR, ch]() {
        char buf[4096]; DWORD n;
        while (ReadFile(cOutR, buf, sizeof buf, &n, nullptr) && n > 0)
            ssh_channel_write(ch, buf, (uint32_t)n);
        ssh_channel_send_eof(ch);
        CloseHandle(cOutR);
    });

    // channel -> pipe(stdin)
    char buf[4096];
    while (true) {
        int r = ssh_channel_read(ch, buf, sizeof buf, 0);
        if (r <= 0) break;
        DWORD w = 0; WriteFile(cInW, buf, (DWORD)r, &w, nullptr);
    }
    CloseHandle(cInW);
    WaitForSingleObject(pi.hProcess, 3000);
    reader.join();
    CloseHandle(pi.hThread); CloseHandle(pi.hProcess);
}

// ---- session handlers ----
static void shell_session(ssh_session s, App* app) {
    auto keys = load_auth_keys(app->cfg.authorized_keys);
    Auth a = authenticate(s, keys);
    free_keys(keys);
    if (!a.ok) return;
    LOG("shell session auth ok: %s", a.fp.c_str());
    int tok = app->session_start(a.fp);
    ssh_channel ch = accept_channel(s);
    if (!ch) { app->session_end(tok); return; }
    ChanReq rq = wait_channel_requests(s);
    send_motd(ch, *app);
    run_shell(ch, app->cfg, rq.exec, rq.exec_cmd);
    ssh_channel_send_eof(ch); ssh_channel_close(ch); ssh_channel_free(ch);
    app->session_end(tok);
}

static void serial_session(ssh_session s, const SerialCfg sc, App* app) {
    auto keys = load_auth_keys(app->cfg.authorized_keys);
    Auth a = authenticate(s, keys);
    free_keys(keys);
    if (!a.ok) return;
    LOG("serial session %s auth ok: %s", sc.name.c_str(), a.fp.c_str());
    int tok = app->session_start(a.fp);

    ssh_channel ch = accept_channel(s);
    if (!ch) { app->session_end(tok); return; }
    wait_channel_requests(s);   // accept pty/shell (client uses `ssh -t`)

    const Identity* id = app->identity_for(a.fp);
    std::string who = id ? id->name : a.fp;
    std::string com = app->find_com_for(sc.name);

    if (com.empty()) {
        const char* m = "remoted: serial port not present\r\n";
        ssh_channel_write(ch, m, (uint32_t)strlen(m));
    } else if (!app->mark_busy(sc.name, sc.name + " - " + who)) {
        const char* m = "remoted: serial in use, try later\r\n";
        ssh_channel_write(ch, m, (uint32_t)strlen(m));
    } else {
        SerialPort sp;
        if (!sp.open(com, sc.baud)) {
            const char* m = "remoted: cannot open serial port\r\n";
            ssh_channel_write(ch, m, (uint32_t)strlen(m));
            app->clear_busy(sc.name);
        } else {
            std::atomic<bool> stop{ false };
            std::thread reader([&sp, ch, &stop]() {
                char b[4096]; int n;
                while (!stop && sp.ok()) {
                    n = sp.read(b, sizeof b, 100);
                    if (n > 0) ssh_channel_write(ch, b, (uint32_t)n);
                    else if (n < 0) break;
                }
            });
            char b[4096];
            while (sp.ok()) {
                int r = ssh_channel_read(ch, b, sizeof b, 0);
                if (r < 0) break;
                if (r > 0 && sp.write(b, r) < 0) break;
                if (ssh_channel_is_eof(ch)) break;
            }
            stop = true; reader.join();
            sp.close();
            app->clear_busy(sc.name);
        }
    }

    ssh_channel_send_eof(ch); ssh_channel_close(ch); ssh_channel_free(ch);
    app->session_end(tok);
}

// ---- bind / accept loop ----
static ssh_bind make_bind(const std::string& host, uint16_t port, const std::string& hostkey) {
    ssh_bind b = ssh_bind_new();
    if (!host.empty()) ssh_bind_options_set(b, SSH_BIND_OPTIONS_BINDADDR, host.c_str());
    unsigned int p = port; ssh_bind_options_set(b, SSH_BIND_OPTIONS_BINDPORT, &p);
    ssh_bind_options_set(b, SSH_BIND_OPTIONS_HOSTKEY, hostkey.c_str());
    int v = SSH_LOG_WARNING; ssh_bind_options_set(b, SSH_BIND_OPTIONS_LOG_VERBOSITY, &v);
    if (ssh_bind_listen(b) != SSH_OK) {
        LOG("ssh bind listen failed port %u: %s", port, ssh_get_error(b));
        ssh_bind_free(b); return nullptr;
    }
    LOG("ssh listening on %s:%u", host.c_str(), port);
    return b;
}

static void accept_loop(ssh_bind b, App* app, std::function<void(ssh_session, App*)> fn) {
    while (!g_stop) {
        ssh_session s = ssh_new();
        if (!s) continue;
        if (ssh_bind_accept(b, s) != SSH_OK) {
            ssh_free(s);
            if (g_stop) break;
            Sleep(50); continue;
        }
        std::thread([s, app, fn]() {
            sess_add(s);
            if (ssh_handle_key_exchange(s) == SSH_OK) fn(s, app);
            else LOG("kex failed: %s", ssh_get_error(s));
            sess_remove(s);
            ssh_disconnect(s); ssh_free(s);
        }).detach();
    }
    ssh_bind_free(b);
}

static void bind_main(App* app, std::string host, uint16_t port, std::string hostkey) {
    ssh_bind b = make_bind(host, port, hostkey);
    if (!b) return;
    accept_loop(b, app, shell_session);
}

static void bind_serial(App* app, std::string host, SerialCfg sc, std::string hostkey) {
    ssh_bind b = make_bind(host, sc.listen_port, hostkey);
    if (!b) return;
    accept_loop(b, app, [sc](ssh_session s, App* a) { serial_session(s, sc, a); });
}

void ssh_start(App* app) {
    ensure_host_key(app->cfg.host_key);
    std::string host = app->cfg.listen_host;
    std::string hk = app->cfg.host_key;
    std::thread(bind_main, app, host, app->cfg.listen_port, hk).detach();
    for (const auto& sc : app->cfg.serials)
        std::thread(bind_serial, app, host, sc, hk).detach();
}
