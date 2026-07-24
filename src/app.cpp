#include "app.h"
#include "ssh.h"
#include "util.h"
#include "log.h"
#include <algorithm>
#include <map>

static std::string abs_path(const std::wstring& exe_dir, const std::string& p) {
    if (p.empty()) return p;
    if (p.size() >= 2 && p[1] == ':') return p;      // X:\...
    if (p[0] == '\\' || p[0] == '/') return p;        // root / UNC
    std::string d = wide_to_utf8(exe_dir);
    if (p == ".") return d;
    if (p.rfind("./", 0) == 0 || p.rfind(".\\", 0) == 0) return d + "\\" + p.substr(2);
    return d + "\\" + p;
}

void resolve_config_paths(AppConfig& c, const std::wstring& exe_dir) {
    // authorized_keys: prefer the standard %USERPROFILE%\.ssh\authorized_keys
    // if it exists and the user did not point the config elsewhere.
    if (c.authorized_keys == "keys/authorized_keys") {
        wchar_t profile[MAX_PATH];
        DWORD nn = GetEnvironmentVariableW(L"USERPROFILE", profile, MAX_PATH);
        if (nn > 0 && nn < MAX_PATH) {
            std::wstring u = std::wstring(profile) + L"\\.ssh\\authorized_keys";
            if (GetFileAttributesW(u.c_str()) != INVALID_FILE_ATTRIBUTES) {
                c.authorized_keys = wide_to_utf8(u);
                LOG("authorized_keys: using %USERPROFILE%\\.ssh\\authorized_keys");
            }
        }
    }
    c.host_key        = abs_path(exe_dir, c.host_key);
    c.authorized_keys = abs_path(exe_dir, c.authorized_keys);
    c.shell_dir       = abs_path(exe_dir, c.shell_dir);
    LOG("authorized_keys resolved: %s", c.authorized_keys.c_str());
}

bool App::init() {
    bool ok = true;
    AppConfig c = load_config(config_path, &ok);
    resolve_config_paths(c, exe_dir);
    {
        std::lock_guard<std::mutex> lk(m_);
        cfg_ = std::move(c);
    }
    // make sure the host key's parent directory exists (first run)
    std::string hk = host_key_path();
    auto kp = hk.find_last_of("/\\");
    if (kp != std::string::npos) ensure_dir(hk.substr(0, kp));
    return ok;
}

void App::start() {
    refresh();
}

void App::refresh() const {
    // serialize refreshers against each other on refresh_m_, but do the slow
    // setupapi enumeration OUTSIDE m_ (holding the config lock across an I/O-
    // style syscall stalls every config reader). Serialization order doubles as
    // freshness order, so an older enumeration can't overwrite a newer rebuild.
    std::lock_guard<std::mutex> rl(refresh_m_);
    auto devs = enumerate_com_ports();
    std::lock_guard<std::mutex> lk(m_);
    devs_ = std::move(devs);
    std::vector<SerialStatus> rebuilt;
    for (const auto& s : cfg_.serials) {
        SerialStatus st;
        st.name        = s.name;
        st.listen_port = s.listen_port;
        st.com         = resolve_com(s, devs_);
        // present only if the resolved COM actually exists on THIS machine
        for (const auto& e : devs_) {
            if (e.com == st.com) { st.present = true; break; }
        }
        // keep occupancy info across rebuilds
        const SerialStatus* old = nullptr;
        for (const auto& o : status_) if (o.name == st.name) { old = &o; break; }
        if (old) st.holders = old->holders;
        if (!old || old->com != st.com || old->present != st.present)
            LOG("serial[%s] -> %s (%s)", s.name.c_str(), st.com.c_str(),
                st.present ? "present" : "absent");
        rebuilt.push_back(std::move(st));
    }
    status_.swap(rebuilt);
}

std::vector<SerialStatus> App::snapshot() const {
    refresh();   // pick up hot-plugged devices
    std::lock_guard<std::mutex> lk(m_);
    return status_;
}

std::string App::find_com_for(const std::string& name) const {
    refresh();   // pick up hot-plugged devices
    std::lock_guard<std::mutex> lk(m_);
    for (const auto& s : cfg_.serials)
        if (s.name == name) return resolve_com(s, devs_);
    return "";
}

bool App::reload() {
    bool ok = true;
    AppConfig c = load_config(config_path, &ok);
    if (!ok) {
        // keep the known-good config: swapping in defaults would silently
        // change the auth surface (authorized_keys path, identities, serials)
        LOG("reload: %s failed to parse - keeping the previous config", config_path.c_str());
        return false;
    }
    resolve_config_paths(c, exe_dir);
    {
        std::lock_guard<std::mutex> lk(m_);
        // listeners are bound once at startup; port changes cannot apply at runtime
        if (c.listen_host != cfg_.listen_host || c.listen_port != cfg_.listen_port) {
            LOG("reload: listen port changes require restart - keeping %s:%u",
                cfg_.listen_host.c_str(), (unsigned)cfg_.listen_port);
            c.listen_host = cfg_.listen_host;
            c.listen_port = cfg_.listen_port;
        }
        for (auto& ns : c.serials) {
            const SerialCfg* old = nullptr;
            for (const auto& os : cfg_.serials)
                if (os.name == ns.name) { old = &os; break; }
            if (!old) {
                uint16_t bound = ssh_serial_bound_port(ns.name);
                if (bound) {
                    // deleted-then-re-added: the OLD listener is still alive -
                    // advertise the port that actually works
                    LOG("reload: serial '%s' re-added - keeping live listener :%u",
                        ns.name.c_str(), (unsigned)bound);
                    ns.listen_port = bound;
                } else {
                    LOG("reload: serial '%s' is new - its listener needs a restart", ns.name.c_str());
                    // don't advertise a port nobody listens on (MOTD/Status show :0)
                    ns.listen_port = 0;
                }
            } else if (old->listen_port != ns.listen_port) {
                LOG("reload: serial '%s' listen port changes require restart - keeping :%u",
                    ns.name.c_str(), (unsigned)old->listen_port);
                // keep the port that is actually bound, or the MOTD/Status would
                // advertise a listener that does not exist
                ns.listen_port = old->listen_port;
            }
        }
        for (const auto& os : cfg_.serials) {
            bool gone = true;
            for (const auto& ns : c.serials)
                if (ns.name == os.name) { gone = false; break; }
            if (gone)
                LOG("reload: serial '%s' removed - its listener stays until restart",
                    os.name.c_str());
        }
        cfg_ = std::move(c);
        LOG("reload: config reloaded (%d serials, %d identities)",
            (int)cfg_.serials.size(), (int)cfg_.identities.size());
    }
    refresh();   // rebuild the status table for the new serial list
    return true;
}

// ---- thread-safe config accessors (copies taken under m_) ----

std::string App::authorized_keys_path() const {
    std::lock_guard<std::mutex> lk(m_);
    return cfg_.authorized_keys;
}
std::string App::host_key_path() const {
    std::lock_guard<std::mutex> lk(m_);
    return cfg_.host_key;
}
std::string App::listen_host() const {
    std::lock_guard<std::mutex> lk(m_);
    return cfg_.listen_host;
}
uint16_t App::listen_port() const {
    std::lock_guard<std::mutex> lk(m_);
    return cfg_.listen_port;
}
std::string App::shell_dir() const {
    std::lock_guard<std::mutex> lk(m_);
    return cfg_.shell_dir;
}
OverlayCfg App::overlay_cfg() const {
    std::lock_guard<std::mutex> lk(m_);
    return cfg_.overlay;
}
std::vector<SerialCfg> App::serial_cfgs() const {
    std::lock_guard<std::mutex> lk(m_);
    return cfg_.serials;
}
bool App::serial_cfg_for(const std::string& name, SerialCfg& out) const {
    std::lock_guard<std::mutex> lk(m_);
    for (const auto& s : cfg_.serials)
        if (s.name == name) { out = s; return true; }
    return false;
}
bool App::identity_for(const std::string& fp, Identity& out) const {
    std::lock_guard<std::mutex> lk(m_);
    auto it = cfg_.identities.find(fp);
    if (it == cfg_.identities.end()) return false;
    out = it->second;
    return true;
}

int App::session_start(const std::string& scope, const std::string& display_name) {
    std::lock_guard<std::mutex> lk(m_);
    int t = next_token_++;
    holders_[t] = { scope, display_name };
    active_++;
    if (hwnd_main) PostMessage(hwnd_main, WM_APP_STATE, 1, 0);
    return t;
}

void App::session_end(int token) {
    bool zero = false;
    {
        std::lock_guard<std::mutex> lk(m_);
        if (holders_.erase(token) == 0) return;   // unknown token: nothing to end
        if (active_ > 0) active_--;
        zero = (active_ == 0);
    }
    if (hwnd_main) PostMessage(hwnd_main, WM_APP_STATE, zero ? 0 : 1, 0);
}

int App::active_count() const {
    std::lock_guard<std::mutex> lk(m_);
    return active_;
}

bool App::mark_busy(const std::string& name, int token, const std::string& holder) {
    bool found = false;
    {
        std::lock_guard<std::mutex> lk(m_);
        for (auto& st : status_) {
            if (st.name == name) { st.holders[token] = holder; found = true; break; }
        }
    }
    if (hwnd_main) PostMessage(hwnd_main, WM_APP_REFRESH, 0, 0);   // text-only refresh
    return found;   // false: serial vanished from the config while a session lives
}

void App::clear_busy(const std::string& name, int token) {
    {
        std::lock_guard<std::mutex> lk(m_);
        for (auto& st : status_) {
            if (st.name == name) { st.holders.erase(token); break; }
        }
    }
    if (hwnd_main) PostMessage(hwnd_main, WM_APP_REFRESH, 0, 0);
}

void App::request_notify(const std::wstring& title, const std::wstring& body) {
    {
        std::lock_guard<std::mutex> lk(nm_);
        pending_notify_.emplace_back(title, body);
    }
    if (hwnd_main) PostMessage(hwnd_main, WM_APP_NOTIFY, 0, 0);
}

std::wstring App::overlay_text() const {
    std::string s = overlay_cfg().message;   // copy under lock (reload may swap cfg_)
    if (s.empty()) s = "Remote session active - please do not operate";
    s += "\r\n\r\n";

    // group holders by scope ("shell" first, then each serial by config name)
    std::map<std::string, std::vector<std::string>> byScope;
    {
        std::lock_guard<std::mutex> lk(m_);
        for (const auto& kv : holders_) byScope[kv.second.first].push_back(kv.second.second);
    }
    auto join = [](const std::vector<std::string>& v) {
        std::string r;
        for (size_t i = 0; i < v.size(); ++i) { if (i) r += ", "; r += v[i]; }
        return r;
    };
    auto it = byScope.find("shell");
    if (it != byScope.end() && !it->second.empty())
        s += "Shell  : " + join(it->second) + "\r\n";
    for (const auto& kv : byScope) {
        if (kv.first == "shell" || kv.second.empty()) continue;
        s += kv.first + " : " + join(kv.second) + "\r\n";
    }

    s += "\r\nPlease Love & Peace :)    [Disconnect / Minimize below]";
    return utf8_to_wide(s);
}
