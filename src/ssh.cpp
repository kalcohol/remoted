#include <winsock2.h>
#include <ws2tcpip.h>

#include "ssh.h"
#include "ssh_internal.h"

#include <exception>

std::atomic<bool> g_stop{ false };

// ---- session abort registry (for disconnect-all) ----
// disconnect-all only sets flags; each worker polls its own flag and tears down
// on its own thread -> no cross-thread ssh_* calls (which used to AV).
static std::mutex g_ab_m;
static std::vector<std::shared_ptr<std::atomic<bool>>> g_aborts;

std::shared_ptr<std::atomic<bool>> reg_abort() {
    auto a = std::make_shared<std::atomic<bool>>(false);
    std::lock_guard<std::mutex> lk(g_ab_m);
    g_aborts.push_back(a);
    return a;
}
void unreg_abort(const std::shared_ptr<std::atomic<bool>>& a) {
    std::lock_guard<std::mutex> lk(g_ab_m);
    g_aborts.erase(std::remove(g_aborts.begin(), g_aborts.end(), a), g_aborts.end());
}

// ---- worker thread tracking (clean shutdown) ----
// Workers used to be fully detached; on process exit a detached thread could
// still be inside a libssh call and crash. Tracked threads flag themselves done
// so they can be reaped, and ssh_request_shutdown() joins what is still running.
namespace {
struct Tracked {
    std::thread th;
    std::shared_ptr<std::atomic<bool>> done;
};
}
static std::mutex g_th_m;
static std::vector<std::shared_ptr<Tracked>> g_tracked;

void spawn_tracked(std::function<void()> fn) {
    auto t = std::make_shared<Tracked>();
    t->done = std::make_shared<std::atomic<bool>>(false);
    std::weak_ptr<Tracked> weak = t;
    t->th = std::thread([weak, fn]() {
        fn();
        if (auto p = weak.lock()) p->done->store(true);
    });
    std::lock_guard<std::mutex> lk(g_th_m);
    if (g_stop.load()) {   // shutdown join may already be done: never track
        t->th.detach();    // (a joinable std::thread left in a static would terminate)
        return;
    }
    // reap finished workers so the list doesn't grow unbounded
    for (auto it = g_tracked.begin(); it != g_tracked.end();) {
        if ((*it)->done->load() && (*it)->th.joinable()) (*it)->th.join();   // already done -> instant
        if (!(*it)->th.joinable()) it = g_tracked.erase(it);
        else ++it;
    }
    g_tracked.push_back(std::move(t));
}

// Join all tracked workers within an overall time budget. Called from the UI
// thread via ssh_request_shutdown(), so it must never block indefinitely: on
// timeout we detach stragglers and let the process exit dirty -- a dirty exit
// beats a hung tray.
void join_tracked(DWORD budget_ms) {
    ULONGLONG deadline = GetTickCount64() + budget_ms;
    for (;;) {
        {
            std::lock_guard<std::mutex> lk(g_th_m);
            bool pending = false;
            for (auto& p : g_tracked)
                if (p->th.joinable() && !p->done->load()) { pending = true; break; }
            if (!pending) {
                for (auto& p : g_tracked) if (p->th.joinable()) p->th.join();
                g_tracked.clear();
                return;
            }
            if (GetTickCount64() >= deadline) {
                // out of budget: detach so static destruction won't std::terminate
                for (auto& p : g_tracked) if (p->th.joinable()) p->th.detach();
                g_tracked.clear();
                return;
            }
        }
        Sleep(10);
    }
}

// ports we listen on, so shutdown can wake a blocked ssh_bind_accept via a
// throwaway localhost connect.
static std::mutex g_ports_m;
static std::vector<uint16_t> g_ports;

static void poke_port(uint16_t port) {
    SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (s == INVALID_SOCKET) return;
    struct sockaddr_in a{};
    a.sin_family = AF_INET;
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    a.sin_port = htons(port);
    // non-blocking connect + a bounded wait: never hang the UI thread even if
    // the stack is being weird (loopback normally completes instantly)
    u_long nb = 1;
    ioctlsocket(s, FIONBIO, &nb);
    connect(s, (struct sockaddr*)&a, sizeof(a));
    fd_set w; FD_ZERO(&w); FD_SET(s, &w);
    timeval tv{ 0, 200 * 1000 };
    select(0, nullptr, &w, nullptr, &tv);   // let the handshake complete -> wakes accept
    closesocket(s);
}

void ssh_disconnect_all() {
    std::vector<std::shared_ptr<std::atomic<bool>>> copy;
    { std::lock_guard<std::mutex> lk(g_ab_m); copy = g_aborts; }
    LOG("disconnect-all: flagging %d session(s)", (int)copy.size());
    for (auto& a : copy) a->store(true);
}

void ssh_request_shutdown() {
    g_stop = true;
    ssh_disconnect_all();
    std::vector<uint16_t> ports;
    { std::lock_guard<std::mutex> lk(g_ports_m); ports = g_ports; }
    for (uint16_t p : ports) poke_port(p);   // wake any accept blocked in ssh_bind_accept
    // wait for accept loops + session workers to unwind (they poll their abort
    // flag every 5-50ms). Hard budget: this runs on the UI thread, so a stuck
    // worker must not hang the tray -- give up and exit dirty instead.
    join_tracked(2000);
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
    { std::lock_guard<std::mutex> lk(g_ports_m); g_ports.push_back(port); }
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
        if (g_stop) { ssh_free(s); break; }   // accept woken by a shutdown poke
        spawn_tracked([s, app, fn]() {
            try {
                // a silent/half-open connection will time out instead of
                // pinning a thread forever.
                long timeout = 60;
                ssh_options_set(s, SSH_OPTIONS_TIMEOUT, &timeout);
                if (ssh_handle_key_exchange(s) == SSH_OK) fn(s, app);
                else LOG("kex failed: %s", ssh_get_error(s));
            } catch (const std::exception& e) {
                LOG("session exception: %s", e.what());
            } catch (...) {
                LOG("session unknown exception");
            }
            ssh_disconnect(s); ssh_free(s);
        });
    }
    ssh_bind_free(b);
}

static void bind_main(App* app, std::string host, uint16_t port, std::string hostkey) {
    ssh_bind b = make_bind(host, port, hostkey);
    if (!b) { app->request_notify(L"remoted", L"failed to listen on :" + std::to_wstring(port)); return; }
    accept_loop(b, app, shell_session);
}

static void bind_serial(App* app, std::string host, SerialCfg sc, std::string hostkey) {
    ssh_bind b = make_bind(host, sc.listen_port, hostkey);
    if (!b) { app->request_notify(L"remoted", L"failed to listen on :" + std::to_wstring(sc.listen_port) + L" (" + utf8_to_wide(sc.name) + L")"); return; }
    accept_loop(b, app, [sc](ssh_session s, App* a) { serial_session(s, sc, a); });
}

void ssh_start(App* app) {
    ssh_init();
    ensure_host_key(app->host_key_path());
    std::string host = app->listen_host();
    std::string hk = app->host_key_path();
    spawn_tracked([app, host, port = app->listen_port(), hk]() { bind_main(app, host, port, hk); });
    for (const auto& sc : app->serial_cfgs())
        spawn_tracked([app, host, sc, hk]() { bind_serial(app, host, sc, hk); });
}
