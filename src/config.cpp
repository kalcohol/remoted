#include "config.h"
#include "log.h"
#include <fstream>
#include <cstdlib>

using json = nlohmann::json;

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

    const auto& ssh = j.value("ssh", json::object());
    std::string listen = ssh.value("listen", "0.0.0.0:9721");
    if (!listen.empty() && listen[0] == '[') {            // [ipv6]:port
        auto rb = listen.find(']');
        if (rb != std::string::npos && rb + 2 < listen.size() && listen[rb + 1] == ':') {
            c.listen_host = listen.substr(1, rb - 1);
            c.listen_port = (uint16_t)std::atoi(listen.substr(rb + 2).c_str());
        }
    } else {
        auto pos = listen.rfind(':');
        if (pos != std::string::npos) {
            c.listen_host = listen.substr(0, pos);
            c.listen_port = (uint16_t)std::atoi(listen.substr(pos + 1).c_str());
        }
    }
    c.host_key        = ssh.value("host_key", c.host_key);
    c.authorized_keys = ssh.value("authorized_keys", c.authorized_keys);
    c.shell_dir       = ssh.value("shell_dir", c.shell_dir);

    for (auto& s : j.value("serial", json::array())) {
        SerialCfg sc;
        sc.name        = s.value("name", "");
        sc.com         = s.value("com", "");
        sc.usb_id      = s.value("usb_id", "");
        sc.baud        = s.value("baud", 115200);
        sc.listen_port = s.value("listen_port", (uint16_t)0);
        if (!sc.name.empty() && sc.listen_port) c.serials.push_back(sc);
    }

    const auto& ov = j.value("overlay", json::object());
    c.overlay.enabled          = ov.value("enabled", true);
    c.overlay.retract_delay_sec = ov.value("retract_delay_sec", 3);
    c.overlay.message          = ov.value("message", std::string(""));

    if (j.contains("identities") && j["identities"].is_object()) {
        const auto& ids = j["identities"];   // one object, same container for begin()/end()
        for (auto it = ids.begin(); it != ids.end(); ++it) {
            Identity id;
            id.name    = it.value().value("name", "");
            id.contact = it.value().value("contact", "");
            c.identities[it.key()] = id;
        }
    }

    LOG("config loaded: %d serials, %d identities",
        (int)c.serials.size(), (int)c.identities.size());
    return c;
}
