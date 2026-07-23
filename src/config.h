#pragma once
#include <string>
#include <vector>
#include <cstdint>
#include <unordered_map>
#include <nlohmann/json.hpp>

struct SerialCfg {
    std::string name;
    std::string com;          // e.g. "COM44"  (fallback / current)
    std::string usb_id;       // stable substring matched against device parent
    uint32_t    baud = 115200;
    uint16_t    listen_port = 0;
};

struct Identity {
    std::string name;
    std::string contact;
};

struct OverlayCfg {
    bool        enabled = true;
    int         retract_delay_sec = 3;
    std::string message;
};

struct AppConfig {
    std::string listen_host = "0.0.0.0";
    uint16_t    listen_port = 9721;
    std::string host_key        = "keys/ed25519_key";
    std::string authorized_keys = "keys/authorized_keys";
    std::string shell_dir       = ".";
    std::vector<SerialCfg>  serials;
    OverlayCfg  overlay;
    std::unordered_map<std::string, Identity> identities;   // fingerprint -> identity
};

// Returns false (and a default config) on a parse error; true on success / file-missing.
AppConfig load_config(const std::string& path, bool* ok = nullptr);
