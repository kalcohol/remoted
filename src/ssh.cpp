#include <winsock2.h>
#include <ws2tcpip.h>

#include "ssh.h"
#include "ssh_internal.h"

#include <exception>

std::atomic<bool> g_stop{ false };

// mutable statics live in a leaked struct: shutdown stragglers (detached after
// the join budget) may still touch them while the CRT destroys statics.
namespace {
struct SshStatics {
    // ---- session abort registry (for disconnect-all) ----
    // disconnect-all only sets flags; each worker polls its own flag and tears
    // down on its own thread -> no cross-thread ssh_* calls (which used to AV).
    std::mutex ab_m;
    std::vector<std::shared_ptr<std::atomic<bool>>> aborts;

    // ---- worker thread tracking (clean shutdown) ----
    struct Tracked {
        std::thread th;
        std::shared_ptr<std::atomic<bool>> done;
    };
    std::mutex th_m;
    std::vector<std::shared_ptr<Tracked>> tracked;

    // active session workers, for the concurrency cap
    std::atomic<int> sessions{ 0 };

    // ports + bind host, so shutdown can wake a blocked ssh_bind_accept via a
    // throwaway connect to the address we actually bound
    std::mutex ports_m;
    std::vector<uint16_t> ports;
    std::string bind_host;
    std::map<std::string, uint16_t> serial_binds;   // serial name -> live listen port
};
}
static SshStatics& S() { static auto* p = new SshStatics(); return *p; }

// hard cap on concurrent session workers: thread-per-connection needs a ceiling
static const int kMaxSessions = 64;

std::shared_ptr<std::atomic<bool>> reg_abort() {
    auto a = std::make_shared<std::atomic<bool>>(false);
    std::lock_guard<std::mutex> lk(S().ab_m);
    S().aborts.push_back(a);
    return a;
}
void unreg_abort(const std::shared_ptr<std::atomic<bool>>& a) {
    std::lock_guard<std::mutex> lk(S().ab_m);
    auto& v = S().aborts;
    v.erase(std::remove(v.begin(), v.end(), a), v.end());
}

void spawn_tracked(std::function<void()> fn) {
    auto t = std::make_shared<SshStatics::Tracked>();
    t->done = std::make_shared<std::atomic<bool>>(false);
    std::weak_ptr<SshStatics::Tracked> weak = t;
    t->th = std::thread([weak, fn]() {
        // a worker that escapes via exception would std::terminate the whole
        // process - catch everything, and always flag done
        try { fn(); }
        catch (const std::exception& e) { LOG("worker exception: %s", e.what()); }
        catch (...) { LOG("worker unknown exception"); }
        if (auto p = weak.lock()) p->done->store(true);
    });
    std::lock_guard<std::mutex> lk(S().th_m);
    if (g_stop.load()) {   // shutdown join may already be done: never track
        t->th.detach();    // (a joinable std::thread left in a static would terminate)
        return;
    }
    // reap finished workers so the list doesn't grow unbounded
    auto& v = S().tracked;
    for (auto it = v.begin(); it != v.end();) {
        if ((*it)->done->load() && (*it)->th.joinable()) (*it)->th.join();   // already done -> instant
        if (!(*it)->th.joinable()) it = v.erase(it);
        else ++it;
    }
    v.push_back(std::move(t));
}

// Join all tracked workers within an overall time budget. Called from the UI
// thread via ssh_request_shutdown(), so it must never block indefinitely: on
// timeout we detach stragglers and let the process exit dirty -- a dirty exit
// beats a hung tray.
void join_tracked(DWORD budget_ms) {
    ULONGLONG deadline = GetTickCount64() + budget_ms;
    for (;;) {
        {
            std::lock_guard<std::mutex> lk(S().th_m);
            auto& v = S().tracked;
            bool pending = false;
            for (auto& p : v)
                if (p->th.joinable() && !p->done->load()) { pending = true; break; }
            if (!pending) {
                for (auto& p : v) if (p->th.joinable()) p->th.join();
                v.clear();
                return;
            }
            if (GetTickCount64() >= deadline) {
                // out of budget: detach so static destruction won't std::terminate
                for (auto& p : v) if (p->th.joinable()) p->th.detach();
                v.clear();
                return;
            }
        }
        Sleep(10);
    }
}

static void poke_port(uint16_t port) {
    std::string host;
    { std::lock_guard<std::mutex> lk(S().ports_m); host = S().bind_host; }
    std::string h = host;
    if (h.empty() || h == "0.0.0.0") h = "127.0.0.1";
    if (h == "::") h = "::1";

    sockaddr_storage a{}; int alen = 0; int fam = AF_INET;
    if (h.find(':') != std::string::npos) {   // IPv6 literal
        auto* a6 = (sockaddr_in6*)&a;
        a6->sin6_family = AF_INET6;
        a6->sin6_port = htons(port);
        if (inet_pton(AF_INET6, h.c_str(), &a6->sin6_addr) != 1) return;
        fam = AF_INET6; alen = sizeof(sockaddr_in6);
    } else {
        auto* a4 = (sockaddr_in*)&a;
        a4->sin_family = AF_INET;
        a4->sin_port = htons(port);
        if (inet_pton(AF_INET, h.c_str(), &a4->sin_addr) != 1)
            inet_pton(AF_INET, "127.0.0.1", &a4->sin_addr);   // hostname: best-effort loopback
        alen = sizeof(sockaddr_in);
    }
    SOCKET s = socket(fam, SOCK_STREAM, IPPROTO_TCP);
    if (s == INVALID_SOCKET) return;
    // non-blocking connect + a bounded wait: never hang the UI thread even if
    // the stack is being weird (loopback normally completes instantly)
    u_long nb = 1;
    ioctlsocket(s, FIONBIO, &nb);
    connect(s, (sockaddr*)&a, alen);
    fd_set w; FD_ZERO(&w); FD_SET(s, &w);
    timeval tv{ 0, 200 * 1000 };
    select(0, nullptr, &w, nullptr, &tv);   // let the handshake complete -> wakes accept
    closesocket(s);
}

void ssh_disconnect_all() {
    std::vector<std::shared_ptr<std::atomic<bool>>> copy;
    { std::lock_guard<std::mutex> lk(S().ab_m); copy = S().aborts; }
    LOG("disconnect-all: flagging %d session(s)", (int)copy.size());
    for (auto& a : copy) a->store(true);
}

void ssh_request_shutdown() {
    g_stop = true;
    ssh_disconnect_all();
    std::vector<uint16_t> ports;
    { std::lock_guard<std::mutex> lk(S().ports_m); ports = S().ports; }
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
    { std::lock_guard<std::mutex> lk(S().ports_m);
      S().ports.push_back(port);
      S().bind_host = host; }
    return b;
}

static void accept_loop(ssh_bind b, App* app, std::function<void(ssh_session, App*)> fn) {
    int accept_fails = 0;
    while (!g_stop) {
        ssh_session s = ssh_new();
        if (!s) { Sleep(50); continue; }   // resource pressure: back off, don't spin
        if (ssh_bind_accept(b, s) != SSH_OK) {
            ssh_free(s);
            if (g_stop) break;
            if (++accept_fails == 1 || accept_fails % 100 == 0)   // don't spin silently
                LOG("accept failed (%d in a row): %s", accept_fails, ssh_get_error(b));
            Sleep(50); continue;
        }
        accept_fails = 0;
        if (g_stop) { ssh_free(s); break; }   // accept woken by a shutdown poke
        // reserve a slot atomically: a plain check-then-increment lets a burst
        // of accepts all pass before any worker increments
        if (S().sessions.fetch_add(1) >= kMaxSessions) {
            S().sessions--;
            LOG("session cap (%d) reached - dropping new connection", kMaxSessions);
            ssh_disconnect(s); ssh_free(s);
            continue;
        }
        try {
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
            S().sessions--;   // spawn_tracked guarantees we always get here
        });
        } catch (...) {
            // std::thread construction failed (resource pressure): release the
            // reserved slot and the session, keep this listener alive
            LOG("worker spawn failed - dropping connection");
            S().sessions--;
            ssh_disconnect(s); ssh_free(s);
        }
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
    { std::lock_guard<std::mutex> lk(S().ports_m); S().serial_binds[sc.name] = sc.listen_port; }
    accept_loop(b, app, [sc](ssh_session s, App* a) { serial_session(s, sc, a); });
}

uint16_t ssh_serial_bound_port(const std::string& name) {
    std::lock_guard<std::mutex> lk(S().ports_m);
    auto it = S().serial_binds.find(name);
    return it == S().serial_binds.end() ? 0 : it->second;
}

void ssh_start(App* app) {
    WSADATA wsa{};   // libssh's ssh_init does this too, but poke_port is ours
    WSAStartup(MAKEWORD(2, 2), &wsa);
    ssh_init();
    ensure_host_key(app->host_key_path());
    std::string host = app->listen_host();
    std::string hk = app->host_key_path();
    spawn_tracked([app, host, port = app->listen_port(), hk]() { bind_main(app, host, port, hk); });
    for (const auto& sc : app->serial_cfgs())
        spawn_tracked([app, host, sc, hk]() { bind_serial(app, host, sc, hk); });
}
