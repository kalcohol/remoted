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
#include <map>
#include <deque>
#include <memory>

// ---- session abort registry (for disconnect-all) ----
// disconnect-all only sets flags; each worker polls its own flag and tears down
// on its own thread -> no cross-thread ssh_* calls (which used to AV).
static std::atomic<bool> g_stop{ false };
static std::mutex g_ab_m;
static std::vector<std::shared_ptr<std::atomic<bool>>> g_aborts;

static std::shared_ptr<std::atomic<bool>> reg_abort() {
    auto a = std::make_shared<std::atomic<bool>>(false);
    std::lock_guard<std::mutex> lk(g_ab_m);
    g_aborts.push_back(a);
    return a;
}
static void unreg_abort(const std::shared_ptr<std::atomic<bool>>& a) {
    std::lock_guard<std::mutex> lk(g_ab_m);
    g_aborts.erase(std::remove(g_aborts.begin(), g_aborts.end(), a), g_aborts.end());
}

void ssh_disconnect_all() {
    std::vector<std::shared_ptr<std::atomic<bool>>> copy;
    { std::lock_guard<std::mutex> lk(g_ab_m); copy = g_aborts; }
    LOG("disconnect-all: flagging %d session(s)", (int)copy.size());
    for (auto& a : copy) a->store(true);
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
struct AuthKey { ssh_key key; std::string comment; };

static std::vector<AuthKey> load_auth_keys(const std::string& path) {
    std::vector<AuthKey> keys;
    std::ifstream f(path);
    if (!f) { LOG("authorized_keys not found: %s", path.c_str()); return keys; }
    std::string line;
    while (std::getline(f, line)) {
        if (line.empty() || line[0] == '#') continue;
        std::istringstream is(line);
        std::string type, b64, comment;
        is >> type >> b64;
        std::getline(is, comment);
        auto p = comment.find_first_not_of(" \t");
        comment = (p != std::string::npos) ? comment.substr(p) : "";
        if (type.empty() || b64.empty()) continue;
        ssh_keytypes_e t = ssh_key_type_from_name(type.c_str());
        ssh_key k = nullptr;
        if (ssh_pki_import_pubkey_base64(b64.c_str(), t, &k) == SSH_OK)
            keys.push_back({ k, comment });
    }
    LOG("loaded %d authorized keys", (int)keys.size());
    return keys;
}
static void free_keys(std::vector<AuthKey>& keys) {
    for (auto& ak : keys) ssh_key_free(ak.key);
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

struct Auth { bool ok = false; std::string fp; std::string comment; };

static Auth authenticate(ssh_session s, const std::vector<AuthKey>& keys) {
    ssh_message msg;
    while (true) {
        msg = ssh_message_get(s);
        if (!msg) return {};
        int t = ssh_message_type(msg), st = ssh_message_subtype(msg);
        if (t == SSH_REQUEST_AUTH && st == SSH_AUTH_METHOD_PUBLICKEY) {
            ssh_key off = ssh_message_auth_pubkey(msg);
            if (off) {
                for (const auto& ak : keys) {
                    if (ssh_key_cmp(off, ak.key, SSH_KEY_CMP_PUBLIC) == 0) {
                        Auth r; r.ok = true; r.fp = key_fp(off); r.comment = ak.comment;
                        ssh_message_auth_reply_success(msg, 0);
                        ssh_message_free(msg);
                        return r;
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

// fingerprint -> identities map; else the key's comment; else a short key id (never "unknown").
static std::string display_name(App* app, const Auth& a) {
    const Identity* id = app->identity_for(a.fp);
    if (id) return id->name + (id->contact.empty() ? "" : " / " + id->contact);
    if (!a.comment.empty()) return a.comment;
    auto p = a.fp.find(':');
    return "key:" + (p != std::string::npos ? a.fp.substr(p + 1, 12) : a.fp.substr(0, 12));
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

static void send_motd(ssh_channel ch, App& app) {
    std::string m = "\r\n=== remoted ===\r\nSerial consoles (ssh alias / ssh -p <port>):\r\n";
    for (auto& st : app.snapshot()) {
        std::string state;
        if (!st.present) state = "[absent]";
        else if (st.holders.empty()) state = "[ready]";
        else { state = "[in-use: "; for (size_t i=0;i<st.holders.size();++i){ if(i) state+=", "; state+=st.holders[i]; } state+="]"; }
        m += "  " + st.name + "  " + st.com + "  :" + std::to_string(st.listen_port) + "  " + state + "\r\n";
    }
    m += "================\r\n\r\n";
    ssh_channel_write(ch, m.data(), (uint32_t)m.size());
}

// ---- child process pump (pipes) ----
// exec: cmd /C <cmd>. interactive shell: cmd.exe, where we provide local echo and
// translate \r -> \r\n (cmd over a pipe does not echo and needs CRLF line endings).
// Uses ssh_channel_read_timeout so the abort flag and channel close are both honored.
static void run_shell(ssh_channel ch, const AppConfig& cfg, bool exec, const std::string& exec_cmd,
                      const std::shared_ptr<std::atomic<bool>>& abort) {
    std::wstring cmdline = exec ? (L"cmd.exe /C " + utf8_to_wide(exec_cmd)) : L"cmd.exe";
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

    // channel writes are serialized (reader + echo both write)
    auto cw = std::make_shared<std::mutex>();
    std::thread reader([cOutR, ch, cw]() {
        char b[4096]; DWORD n;
        while (ReadFile(cOutR, b, sizeof b, &n, nullptr) && n > 0) {
            std::lock_guard<std::mutex> lk(*cw);
            ssh_channel_write(ch, b, (uint32_t)n);
        }
        { std::lock_guard<std::mutex> lk(*cw); ssh_channel_send_eof(ch); }
        CloseHandle(cOutR);
    });

    char buf[4096];
    while (true) {
        if (abort->load()) break;
        int r = ssh_channel_read_timeout(ch, buf, sizeof buf, 0, 200);
        if (r > 0) {
            if (exec) {
                DWORD w = 0; WriteFile(cInW, buf, (DWORD)r, &w, nullptr);
            } else {
                { std::lock_guard<std::mutex> lk(*cw); ssh_channel_write(ch, buf, (uint32_t)r); } // local echo
                std::string out; out.reserve(r + 8);
                for (int i = 0; i < r; ++i) out += (buf[i] == '\r') ? std::string("\r\n") : std::string(1, buf[i]);
                DWORD w = 0; WriteFile(cInW, out.data(), (DWORD)out.size(), &w, nullptr);
            }
        } else if (r < 0) {
            break;
        } else if (ssh_channel_is_closed(ch) || ssh_channel_is_eof(ch)) {
            break;
        }
    }

    CloseHandle(cInW);
    if (abort->load()) TerminateProcess(pi.hProcess, 1);
    WaitForSingleObject(pi.hProcess, 3000);
    reader.join();
    CloseHandle(pi.hThread); CloseHandle(pi.hProcess);
}

// ---- shared serial bridge ----
struct Attach {
    ssh_channel ch;
    std::mutex qm;
    std::deque<std::string> outq;
};

struct SerialBridge : std::enable_shared_from_this<SerialBridge> {
    std::string name, com; uint32_t baud = 0;
    SerialPort sp;
    std::atomic<bool> stop{ false };
    std::thread reader;
    std::mutex att_m;
    std::vector<std::shared_ptr<Attach>> attaches;
    std::mutex write_m;
    std::atomic<int> ref{ 0 };

    void start_reader() {
        auto self = shared_from_this();
        reader = std::thread([self]() {
            char b[4096]; int n;
            while (!self->stop) {
                n = self->sp.read(b, sizeof b, 100);
                if (n > 0) {
                    std::lock_guard<std::mutex> lk(self->att_m);
                    std::string chunk(b, n);
                    for (auto& a : self->attaches) { std::lock_guard<std::mutex> ql(a->qm); a->outq.push_back(chunk); }
                } else if (n < 0) break;
            }
        });
    }
    std::shared_ptr<Attach> attach(ssh_channel ch) {
        auto a = std::make_shared<Attach>(); a->ch = ch;
        std::lock_guard<std::mutex> lk(att_m); attaches.push_back(a);
        return a;
    }
    void detach(const std::shared_ptr<Attach>& a) {
        std::lock_guard<std::mutex> lk(att_m);
        attaches.erase(std::remove(attaches.begin(), attaches.end(), a), attaches.end());
    }
    void write_com(const void* buf, int len) {
        std::lock_guard<std::mutex> lk(write_m);
        sp.write(buf, len);
    }
};

static std::mutex g_bm;
static std::map<std::string, std::shared_ptr<SerialBridge>> g_bridges;

static std::shared_ptr<SerialBridge> bridge_attach(const SerialCfg& sc, const std::string& com) {
    std::lock_guard<std::mutex> lk(g_bm);
    auto it = g_bridges.find(sc.name);
    if (it != g_bridges.end()) { it->second->ref++; return it->second; }
    auto b = std::make_shared<SerialBridge>();
    b->name = sc.name; b->com = com; b->baud = sc.baud;
    if (!b->sp.open(com, sc.baud)) { LOG("bridge open failed %s (%s)", sc.name.c_str(), com.c_str()); return nullptr; }
    LOG("bridge opened %s (%s) @%u", sc.name.c_str(), com.c_str(), sc.baud);
    g_bridges[sc.name] = b;
    b->ref++;
    b->start_reader();
    return b;
}

static void bridge_release(const std::string& name, const std::shared_ptr<Attach>& a) {
    std::shared_ptr<SerialBridge> b; bool last = false;
    {
        std::lock_guard<std::mutex> lk(g_bm);
        auto it = g_bridges.find(name);
        if (it == g_bridges.end()) return;
        b = it->second;
        if (--b->ref == 0) { g_bridges.erase(it); last = true; }
    }
    if (b) b->detach(a);
    if (last) {
        b->stop = true;
        if (b->reader.joinable()) b->reader.join();
        b->sp.close();
        LOG("bridge closed %s", name.c_str());
    }
}

// ---- session handlers ----
static void shell_session(ssh_session s, App* app) {
    auto keys = load_auth_keys(app->cfg.authorized_keys);
    Auth a = authenticate(s, keys);
    free_keys(keys);
    if (!a.ok) return;
    std::string who = display_name(app, a);
    LOG("shell session auth ok: %s", who.c_str());
    int tok = app->session_start("shell", who);
    auto abort = reg_abort();
    ssh_channel ch = accept_channel(s);
    if (!ch) { unreg_abort(abort); app->session_end(tok); return; }
    ChanReq rq = wait_channel_requests(s);
    send_motd(ch, *app);
    run_shell(ch, app->cfg, rq.exec, rq.exec_cmd, abort);
    ssh_channel_send_eof(ch); ssh_channel_close(ch); ssh_channel_free(ch);
    unreg_abort(abort);
    app->session_end(tok);
}

static void serial_session(ssh_session s, const SerialCfg sc, App* app) {
    auto keys = load_auth_keys(app->cfg.authorized_keys);
    Auth a = authenticate(s, keys);
    free_keys(keys);
    if (!a.ok) return;
    std::string who = display_name(app, a);
    LOG("serial session %s auth ok: %s", sc.name.c_str(), who.c_str());
    int tok = app->session_start(sc.name, who);
    auto abort = reg_abort();
    app->mark_busy(sc.name, who);

    ssh_channel ch = accept_channel(s);
    if (!ch) { app->clear_busy(sc.name, who); unreg_abort(abort); app->session_end(tok); return; }
    wait_channel_requests(s);

    std::string com = app->find_com_for(sc.name);
    if (com.empty()) {
        const char* m = "remoted: serial port not present on this host\r\n";
        ssh_channel_write(ch, m, (uint32_t)strlen(m));
    } else {
        auto b = bridge_attach(sc, com);
        if (!b) {
            const char* m = "remoted: cannot open serial port\r\n";
            ssh_channel_write(ch, m, (uint32_t)strlen(m));
        } else {
            auto at = b->attach(ch);
            char buf[4096];
            while (true) {
                if (abort->load()) break;
                int avail = ssh_channel_poll(ch, 0);
                if (avail < 0) break;
                if (avail > 0) {
                    int rd = (avail < (int)sizeof buf) ? avail : (int)sizeof buf;
                    int r = ssh_channel_read(ch, buf, (uint32_t)rd, 0);
                    if (r > 0) b->write_com(buf, r);
                    else if (r < 0) break;
                }
                {
                    std::lock_guard<std::mutex> ql(at->qm);
                    while (!at->outq.empty()) {
                        const auto& ss = at->outq.front();
                        ssh_channel_write(ch, ss.data(), (uint32_t)ss.size());
                        at->outq.pop_front();
                    }
                }
                if (ssh_channel_is_eof(ch) || ssh_channel_is_closed(ch)) break;
                if (avail == 0) Sleep(5);
            }
            bridge_release(sc.name, at);
        }
    }

    ssh_channel_send_eof(ch); ssh_channel_close(ch); ssh_channel_free(ch);
    app->clear_busy(sc.name, who);
    unreg_abort(abort);
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
            if (ssh_handle_key_exchange(s) == SSH_OK) fn(s, app);
            else LOG("kex failed: %s", ssh_get_error(s));
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
    ssh_init();
    ensure_host_key(app->cfg.host_key);
    std::string host = app->cfg.listen_host;
    std::string hk = app->cfg.host_key;
    std::thread(bind_main, app, host, app->cfg.listen_port, hk).detach();
    for (const auto& sc : app->cfg.serials)
        std::thread(bind_serial, app, host, sc, hk).detach();
}
