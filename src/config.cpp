#include "config.h"
#include "log.h"
#include <fstream>
#include <cstdlib>
#include <stdexcept>

using json = nlohmann::json;

// parse a port string; must be 1..65535, otherwise warn and use the fallback
static uint16_t parse_port(const std::string& s, const char* what, uint16_t fallback) {
    char* end = nullptr;
    long v = std::strtol(s.c_str(), &end, 10);
    if (s.empty() || !end || *end != '\0' || v < 1 || v > 65535) {
        LOG("config: invalid %s port '%s' - using %u", what, s.c_str(), (unsigned)fallback);
        return fallback;
    }
    return (uint16_t)v;
}

AppConfig load_config(const std::string& path, bool* ok) {
    AppConfig c;
    if (ok) *ok = true;
    std::ifstream f(path);
    if (!f) { LOG("config not found: %s - using defaults", path.c_str()); return c; }
    json j;
    try { f >> j; }
    catch (std::exception& e) {
        LOG("config parse error: %s", e.what());
        if (ok) *ok = false;
        return c;
    }

    // any type/range error below (e.g. "baud": "115200", "serial": {...}) -> defaults
    try {

    const auto& ssh = j.value("ssh", json::object());
    std::string listen = ssh.value("listen", "0.0.0.0:9721");
    if (!listen.empty() && listen[0] == '[') {            // [ipv6]:port
        auto rb = listen.find(']');
        if (rb != std::string::npos && rb + 2 < listen.size() && listen[rb + 1] == ':') {
            c.listen_host = listen.substr(1, rb - 1);
            c.listen_port = parse_port(listen.substr(rb + 2), "ssh listen", c.listen_port);
        }
    } else {
        auto pos = listen.rfind(':');
        if (pos != std::string::npos) {
            c.listen_host = listen.substr(0, pos);
            c.listen_port = parse_port(listen.substr(pos + 1), "ssh listen", c.listen_port);
        }
    }
    c.host_key        = ssh.value("host_key", c.host_key);
    c.authorized_keys = ssh.value("authorized_keys", c.authorized_keys);
    c.shell_dir       = ssh.value("shell_dir", c.shell_dir);

    for (auto& s : j.value("serial", json::array())) {
        try {   // one bad entry must not nuke the whole config
            SerialCfg sc;
            sc.name        = s.value("name", "");
            sc.com         = s.value("com", "");
            sc.usb_id      = s.value("usb_id", "");
            sc.baud        = s.value("baud", 115200);
            int lp         = s.value("listen_port", 0);
            if (lp < 0 || lp > 65535) {
                LOG("config: serial '%s' listen_port %d out of range", sc.name.c_str(), lp);
                lp = 0;   // entry is skipped below
            }
            sc.listen_port = (uint16_t)lp;
            if (!sc.name.empty() && sc.listen_port) c.serials.push_back(sc);
            else LOG("config: serial '%s' skipped (no name or no listen_port)", sc.name.c_str());
        } catch (std::exception& e) {
            LOG("config: bad serial entry skipped: %s", e.what());
        }
    }

    const auto& ov = j.value("overlay", json::object());
    c.overlay.enabled          = ov.value("enabled", true);
    c.overlay.retract_delay_sec = ov.value("retract_delay_sec", 3);
    c.overlay.message          = ov.value("message", std::string(""));
    if (c.overlay.retract_delay_sec < 1 || c.overlay.retract_delay_sec > 3600) {
        LOG("config: retract_delay_sec %d out of range - clamped to [1,3600]",
            c.overlay.retract_delay_sec);
        c.overlay.retract_delay_sec = c.overlay.retract_delay_sec < 1 ? 3 : 3600;
    }

    if (j.contains("identities") && j["identities"].is_object()) {
        const auto& ids = j["identities"];   // one object, same container for begin()/end()
        for (auto it = ids.begin(); it != ids.end(); ++it) {
            try {   // skip a bad identity, keep the rest of the config
                if (!it.value().is_object()) throw std::runtime_error("not an object");
                Identity id;
                id.name    = it.value().value("name", "");
                id.contact = it.value().value("contact", "");
                c.identities[it.key()] = id;
            } catch (std::exception& e) {
                LOG("config: bad identity '%s' skipped: %s", it.key().c_str(), e.what());
            }
        }
    }

    } catch (std::exception& e) {
        LOG("config value error: %s - using defaults", e.what());
        if (ok) *ok = false;
        return AppConfig{};
    }

    LOG("config loaded: %d serials, %d identities",
        (int)c.serials.size(), (int)c.identities.size());
    return c;
}
