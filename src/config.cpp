#include "config.h"
#include "log.h"
#include <fstream>
#include <cstdlib>

using json = nlohmann::json;

AppConfig load_config(const std::string& path) {
    AppConfig c;
    std::ifstream f(path);
    if (!f) { LOG("config not found: %s - using defaults", path.c_str()); return c; }
    json j;
    try { f >> j; }
    catch (std::exception& e) { LOG("config parse error: %s", e.what()); return c; }

    const auto& ssh = j.value("ssh", json::object());
    std::string listen = ssh.value("listen", "0.0.0.0:9721");
    auto pos = listen.rfind(':');
    if (pos != std::string::npos) {
        c.listen_host = listen.substr(0, pos);
        c.listen_port = (uint16_t)std::atoi(listen.substr(pos + 1).c_str());
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

    for (auto it = j.value("identities", json::object()).begin();
         it != j.value("identities", json::object()).end(); ++it) {
        Identity id; id.name = it->value("name", ""); id.contact = it->value("contact", "");
        c.identities[it.key()] = id;
    }

    LOG("config loaded: %d serials, %d identities",
        (int)c.serials.size(), (int)c.identities.size());
    return c;
}
