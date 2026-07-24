#pragma once
// Internal plumbing shared by ssh.cpp / ssh_auth.cpp / ssh_shell.cpp /
// ssh_serial.cpp. Not a public API -- the public surface is ssh.h.

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>

#include "app.h"
#include "serial.h"
#include "codepage.h"
#include "util.h"
#include "log.h"

#include <libssh/libssh.h>
#include <libssh/server.h>

#include <algorithm>
#include <atomic>
#include <deque>
#include <functional>
#include <map>
#include <memory>
#include <mutex>
#include <set>
#include <string>
#include <thread>
#include <vector>

// set by ssh_request_shutdown(); accept loops and workers poll it to exit
extern std::atomic<bool> g_stop;

// ---- session abort registry (for disconnect-all) ----
// disconnect-all only sets flags; each worker polls its own flag and tears down
// on its own thread -> no cross-thread ssh_* calls (which used to AV).
std::shared_ptr<std::atomic<bool>> reg_abort();
void unreg_abort(const std::shared_ptr<std::atomic<bool>>& a);

// ---- worker thread tracking (clean shutdown) ----
// every accept/session thread runs via spawn_tracked so ssh_request_shutdown()
// can join them instead of exiting the process under their feet.
void spawn_tracked(std::function<void()> fn);
void join_tracked(DWORD budget_ms);

// ---- auth (ssh_auth.cpp) ----
// authorized_keys options we actually enforce. Anything else in the options
// field is logged as ignored at load time (except the no-*-forwarding family,
// which is inherently satisfied: remoted implements no forwarding at all).
struct KeyOpts {
    std::string forced_command;   // command="..."   -> replaces whatever the client asks to run
    bool        no_pty = false;   // no-pty          -> pty requests are refused
    std::string from;             // from="patterns" -> peer IP must match (wildcards * ?)
};
struct AuthKey { ssh_key key; std::string comment; KeyOpts opts; };
struct Auth { bool ok = false; std::string fp; std::string comment; KeyOpts opts; };

void ensure_host_key(const std::string& path);
std::vector<AuthKey> load_auth_keys(const std::string& path);
void free_keys(std::vector<AuthKey>& keys);
std::string key_fp(ssh_key k);
Auth authenticate(ssh_session s, const std::vector<AuthKey>& keys);
void notify_unknown_key(App* app, const std::string& fp);
// fingerprint -> identities map; else the key's comment; else a short key id (never "unknown").
std::string display_name(App* app, const Auth& a);
// peer IPv4/IPv6 address of the session, "" if unavailable
std::string peer_ip(ssh_session s);

// one-shot channel write where failure only matters as a log line
// (the channel is being closed right after anyway)
inline void ch_write_str(ssh_channel ch, const std::string& s) {
    if (ssh_channel_write(ch, s.data(), (uint32_t)s.size()) < 0)
        LOG("channel write failed (%zu bytes)", s.size());
}

// channel write that loops over short writes; false = channel is broken
inline bool ch_write_all(ssh_channel ch, const char* d, size_t n) {
    size_t off = 0;
    while (off < n) {
        int w = ssh_channel_write(ch, d + off, (uint32_t)(n - off));
        if (w <= 0) return false;
        off += (size_t)w;
    }
    return true;
}

// ---- channel/session helpers (ssh_shell.cpp) ----
ssh_channel accept_channel(ssh_session s);

struct ChanReq { bool shell = false, exec = false; std::string exec_cmd; };
ChanReq wait_channel_requests(ssh_session s, bool allow_pty);

void send_motd(ssh_channel ch, App& app);

void run_shell(ssh_channel ch, const std::string& shell_dir, bool exec, const std::string& exec_cmd,
               const std::shared_ptr<std::atomic<bool>>& abort);

void shell_session(ssh_session s, App* app);

// ---- shared serial bridge (ssh_serial.cpp) ----
struct Attach {
    ssh_channel ch;
    std::mutex qm;
    std::deque<std::string> outq;
    unsigned dropped = 0;            // chunks dropped because outq was full (rate-limited logging)
    std::atomic<bool> dead{ false }; // bridge's reader died (device gone) -> session should bail
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
            char b[4096]; int n; long total = 0; bool logged = false;
            while (!self->stop) {
                n = self->sp.read(b, sizeof b, 100);
                if (n > 0) {
                    total += n;
                    if (!logged) { LOG("serial %s: first data %d bytes", self->name.c_str(), n); logged = true; }
                    std::lock_guard<std::mutex> lk(self->att_m);
                    std::string chunk(b, n);
                    for (auto& a : self->attaches) {
                        std::lock_guard<std::mutex> ql(a->qm);
                        if (a->outq.size() >= 256) {
                            a->outq.pop_front();   // drop oldest (keep newest for a live console)
                            // rate-limited: first drop + every 100th, not per chunk
                            if (++a->dropped == 1 || a->dropped % 100 == 0)
                                LOG("serial %s: output queue full, %u chunk(s) dropped", self->name.c_str(), a->dropped);
                        }
                        a->outq.push_back(chunk);
                    }
                } else if (n < 0) { LOG("serial %s: read error", self->name.c_str()); break; }
            }
            // reader is gone (device error or stop): mark the bridge dead and tell
            // every attached session, so nobody sits on a silent console and no
            // new session gets attached to a dead bridge (see bridge_attach)
            self->stop = true;
            { std::lock_guard<std::mutex> lk(self->att_m);
              for (auto& a : self->attaches) a->dead = true; }
            LOG("serial %s: reader stopped, total %ld bytes", self->name.c_str(), total);
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
        int w = sp.write(buf, len);
        if (w != len) LOG("serial %s: short/failed write (%d/%d bytes)", name.c_str(), w, len);
    }
};

std::shared_ptr<SerialBridge> bridge_attach(const SerialCfg& sc, const std::string& com);
// identity-checked: a stale release from a dead bridge can't touch the current one
void bridge_release(const std::shared_ptr<SerialBridge>& b, const std::shared_ptr<Attach>& a);

void serial_session(ssh_session s, const SerialCfg sc, App* app);

// RAII: ensures occupancy (session token / abort flag / serial busy slot) is
// released even if the handler throws or returns early.
struct Guard { std::function<void()> d; Guard(std::function<void()> f) : d(std::move(f)) {} ~Guard() { if (d) d(); } };
