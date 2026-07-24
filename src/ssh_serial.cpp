#include "ssh_internal.h"

#include <cstring>

// ---- shared serial bridge registry ----
// leaked like every other mutable static: a detached shutdown straggler may
// still run bridge_release while the CRT destroys statics.
namespace {
struct BridgeStatics {
    std::mutex m;
    std::map<std::string, std::shared_ptr<SerialBridge>> bridges;
};
}
static BridgeStatics& B() { static auto* p = new BridgeStatics(); return *p; }

std::shared_ptr<SerialBridge> bridge_attach(const SerialCfg& sc, const std::string& com) {
    std::lock_guard<std::mutex> lk(B().m);
    auto it = B().bridges.find(sc.name);
    if (it != B().bridges.end()) {
        auto b = it->second;
        if (b->stop.load()) {
            // dead bridge (reader died with the device): tear it down and fall
            // through to build a fresh one. Old attaches were flagged dead by the
            // reader's exit broadcast (and attach() re-checks stop), their
            // sessions unwind via bridge_release, which is identity-checked and
            // won't touch the new bridge.
            LOG("bridge %s: previous bridge died - rebuilding", sc.name.c_str());
            if (b->reader.joinable()) b->reader.join();
            { std::lock_guard<std::mutex> wl(b->write_m); b->sp.close(); }   // don't close under an in-flight write
            B().bridges.erase(it);
        } else {
            if (b->com != com || b->baud != sc.baud) {
                // config changed under a live bridge: refuse rather than silently
                // land the user on the OLD device / baud
                LOG("bridge %s: config changed (%s@%u -> %s@%u) while in use - refusing attach",
                    sc.name.c_str(), b->com.c_str(), b->baud, com.c_str(), sc.baud);
                return nullptr;
            }
            b->ref++;
            return b;
        }
    }
    auto b = std::make_shared<SerialBridge>();
    b->name = sc.name; b->com = com; b->baud = sc.baud;
    if (!b->sp.open(com, sc.baud)) { LOG("bridge open failed %s (%s)", sc.name.c_str(), com.c_str()); return nullptr; }
    LOG("bridge opened %s (%s) @%u", sc.name.c_str(), com.c_str(), sc.baud);
    B().bridges[sc.name] = b;
    b->ref++;
    b->start_reader();
    return b;
}

void bridge_release(const std::shared_ptr<SerialBridge>& b, const std::shared_ptr<Attach>& a) {
    // stop/join/close under the lock so a concurrent attach cannot create a
    // second bridge and fail the exclusive COM open. Identity-checked: a stale
    // release from a previous (dead) bridge must not touch the current one.
    std::lock_guard<std::mutex> lk(B().m);
    b->detach(a);
    if (--b->ref == 0) {
        auto it = B().bridges.find(b->name);
        if (it != B().bridges.end() && it->second == b) B().bridges.erase(it);
        b->stop = true;
        if (b->reader.joinable()) b->reader.join();
        { std::lock_guard<std::mutex> wl(b->write_m); b->sp.close(); }   // don't close under an in-flight write
        LOG("bridge closed %s", b->name.c_str());
    }
}

void serial_session(ssh_session s, const SerialCfg sc, App* app) {
    auto keys = load_auth_keys(app->authorized_keys_path());
    auto abort = reg_abort();   // early: covers the pre-auth phase too (disconnect-all)
    Auth a = authenticate(s, keys, abort);
    free_keys(keys);
    if (!a.ok) { unreg_abort(abort); notify_unknown_key(app, a.fp); return; }
    std::string who = display_name(app, a);
    LOG("serial session %s auth ok: %s (%s)", sc.name.c_str(), who.c_str(), a.fp.c_str());

    ssh_channel ch = accept_channel(s);
    if (!ch) { unreg_abort(abort); return; }
    ChanReq rq = wait_channel_requests(s, !a.opts.no_pty);

    // refusals come FIRST: a rejected connection never registers occupancy
    // (it must not flash the overlay for a few seconds)
    auto refuse = [&](const char* m) {
        ch_write_str(ch, m);
        ssh_channel_send_eof(ch); ssh_channel_close(ch); ssh_channel_free(ch);
        unreg_abort(abort);
    };
    if (!a.opts.forced_command.empty())    // a forced-command key has no business on a console
        return refuse("remoted: this key is restricted to a forced command.\r\n");
    if (rq.exec)                           // serial ports are interactive consoles
        return refuse("remoted: serial ports are interactive-only.\r\n"
                      "Connect without a command:  ssh -p <port> <host>\r\n");
    if (!rq.shell)                         // client asked for nothing (or stalled past the budget)
        return refuse("remoted: no shell request received\r\n");

    // use the CURRENT config entry for this serial (reload may have changed
    // com/usb_id/baud since this listener was bound)
    SerialCfg cur;
    if (!app->serial_cfg_for(sc.name, cur))
        return refuse("remoted: this serial was removed from the config\r\n");

    int tok = app->session_start(sc.name, who);
    app->mark_busy(sc.name, tok, who);
    Guard g([&]() { app->clear_busy(sc.name, tok); unreg_abort(abort); app->session_end(tok); });

    std::string com = app->find_com_for(sc.name);
    if (com.empty()) {
        ch_write_str(ch, "remoted: serial port not present on this host\r\n");
    } else {
        auto b = bridge_attach(cur, com);
        if (!b) {
            ch_write_str(ch, "remoted: cannot open serial port (absent, busy, or config changed while in use)\r\n");
        } else {
            auto at = b->attach(ch);
            Guard bg([&]() { bridge_release(b, at); });   // exceptions must not leak the ref
            char buf[4096];
            while (true) {
                if (abort->load()) break;
                if (at->dead.load()) {   // device lost / reader died
                    ch_write_str(ch, "\r\nremoted: serial device lost - closing console\r\n");
                    break;
                }
                int avail = ssh_channel_poll(ch, 0);
                if (avail < 0) break;
                if (avail > 0) {
                    int rd = (avail < (int)sizeof buf) ? avail : (int)sizeof buf;
                    int r = ssh_channel_read(ch, buf, (uint32_t)rd, 0);
                    if (r > 0) b->write_com(buf, r);
                    else if (r < 0) break;
                }
                std::vector<std::string> popped;
                {
                    std::lock_guard<std::mutex> ql(at->qm);
                    popped.reserve(at->outq.size());
                    while (!at->outq.empty()) { popped.emplace_back(std::move(at->outq.front())); at->outq.pop_front(); }
                }
                bool dead = false;
                for (const auto& ss : popped)
                    if (!ch_write_all(ch, ss.data(), ss.size())) { dead = true; break; }
                if (dead) break;
                if (ssh_channel_is_eof(ch) || ssh_channel_is_closed(ch)) break;
                if (avail == 0) Sleep(5);
            }
        }
    }

    ssh_channel_send_eof(ch); ssh_channel_close(ch); ssh_channel_free(ch);
}
