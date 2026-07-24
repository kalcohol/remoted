#include "ssh_internal.h"

#include <cstring>

// ---- shared serial bridge registry ----
static std::mutex g_bm;
static std::map<std::string, std::shared_ptr<SerialBridge>> g_bridges;

std::shared_ptr<SerialBridge> bridge_attach(const SerialCfg& sc, const std::string& com) {
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

void bridge_release(const std::string& name, const std::shared_ptr<Attach>& a) {
    // stop/join/close the bridge under the lock so a concurrent attach cannot
    // create a second bridge and fail the exclusive COM open.
    std::lock_guard<std::mutex> lk(g_bm);
    auto it = g_bridges.find(name);
    if (it == g_bridges.end()) return;
    auto b = it->second;
    b->detach(a);
    if (--b->ref == 0) {
        b->stop = true;
        if (b->reader.joinable()) b->reader.join();
        b->sp.close();
        g_bridges.erase(it);
        LOG("bridge closed %s", name.c_str());
    }
}

void serial_session(ssh_session s, const SerialCfg sc, App* app) {
    auto keys = load_auth_keys(app->authorized_keys_path());
    Auth a = authenticate(s, keys);
    free_keys(keys);
    if (!a.ok) { notify_unknown_key(app, a.fp); return; }
    std::string who = display_name(app, a);
    LOG("serial session %s auth ok: %s (%s)", sc.name.c_str(), who.c_str(), a.fp.c_str());
    int tok = app->session_start(sc.name, who);
    auto abort = reg_abort();
    app->mark_busy(sc.name, tok, who);
    Guard g([&]() { app->clear_busy(sc.name, tok); unreg_abort(abort); app->session_end(tok); });

    ssh_channel ch = accept_channel(s);
    if (!ch) return;
    ChanReq rq = wait_channel_requests(s, !a.opts.no_pty);

    if (!a.opts.forced_command.empty()) {   // a forced-command key has no business on a console
        ch_write_str(ch, "remoted: this key is restricted to a forced command.\r\n");
        ssh_channel_send_eof(ch); ssh_channel_close(ch); ssh_channel_free(ch);
        return;   // guard releases occupancy
    }

    if (rq.exec) {   // serial ports are interactive consoles; exec makes no sense
        ch_write_str(ch, "remoted: serial ports are interactive-only.\r\n"
                         "Connect without a command:  ssh -p <port> <host>\r\n");
        ssh_channel_send_eof(ch); ssh_channel_close(ch); ssh_channel_free(ch);
        return;   // guard releases occupancy
    }

    std::string com = app->find_com_for(sc.name);
    if (com.empty()) {
        ch_write_str(ch, "remoted: serial port not present on this host\r\n");
    } else {
        auto b = bridge_attach(sc, com);
        if (!b) {
            ch_write_str(ch, "remoted: cannot open serial port\r\n");
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
                std::vector<std::string> popped;
                {
                    std::lock_guard<std::mutex> ql(at->qm);
                    popped.reserve(at->outq.size());
                    while (!at->outq.empty()) { popped.emplace_back(std::move(at->outq.front())); at->outq.pop_front(); }
                }
                bool dead = false;
                for (const auto& ss : popped)
                    if (ssh_channel_write(ch, ss.data(), (uint32_t)ss.size()) < 0) { dead = true; break; }
                if (dead) break;
                if (ssh_channel_is_eof(ch) || ssh_channel_is_closed(ch)) break;
                if (avail == 0) Sleep(5);
            }
            bridge_release(sc.name, at);
        }
    }

    ssh_channel_send_eof(ch); ssh_channel_close(ch); ssh_channel_free(ch);
}
