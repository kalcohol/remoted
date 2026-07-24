#include "app.h"
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

void App::start() {
    refresh();
}

void App::refresh() const {
    auto devs = enumerate_com_ports();
    std::lock_guard<std::mutex> lk(m_);
    devs_ = std::move(devs);
    std::vector<SerialStatus> rebuilt;
    for (const auto& s : cfg.serials) {
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
    for (const auto& s : cfg.serials)
        if (s.name == name) return resolve_com(s, devs_);
    return "";
}

void App::reload() {
    bool ok = true;
    AppConfig c = load_config(config_path, &ok);
    if (!ok) LOG("reload: %s failed to parse - using defaults", config_path.c_str());
    resolve_config_paths(c, exe_dir);
    {
        std::lock_guard<std::mutex> lk(m_);
        // listeners are bound once at startup; port changes cannot apply at runtime
        if (c.listen_host != cfg.listen_host || c.listen_port != cfg.listen_port) {
            LOG("reload: listen port changes require restart - keeping %s:%u",
                cfg.listen_host.c_str(), (unsigned)cfg.listen_port);
            c.listen_host = cfg.listen_host;
            c.listen_port = cfg.listen_port;
        }
        for (const auto& ns : c.serials) {
            const SerialCfg* old = nullptr;
            for (const auto& os : cfg.serials)
                if (os.name == ns.name) { old = &os; break; }
            if (!old)
                LOG("reload: serial '%s' is new - listen port changes require restart",
                    ns.name.c_str());
            else if (old->listen_port != ns.listen_port)
                LOG("reload: serial '%s' listen port changes require restart",
                    ns.name.c_str());
        }
        for (const auto& os : cfg.serials) {
            bool gone = true;
            for (const auto& ns : c.serials)
                if (ns.name == os.name) { gone = false; break; }
            if (gone)
                LOG("reload: serial '%s' removed - its listener stays until restart",
                    os.name.c_str());
        }
        cfg = std::move(c);
        LOG("reload: config reloaded (%d serials, %d identities)",
            (int)cfg.serials.size(), (int)cfg.identities.size());
    }
    refresh();   // rebuild the status table for the new serial list
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
        holders_.erase(token);
        if (active_ > 0) active_--;
        zero = (active_ == 0);
    }
    if (hwnd_main) PostMessage(hwnd_main, WM_APP_STATE, zero ? 0 : 1, 0);
}

bool App::mark_busy(const std::string& name, int token, const std::string& holder) {
    {
        std::lock_guard<std::mutex> lk(m_);
        for (auto& st : status_) {
            if (st.name == name) { st.holders[token] = holder; break; }
        }
    }
    if (hwnd_main) PostMessage(hwnd_main, WM_APP_REFRESH, 0, 0);   // text-only refresh
    return true;
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

const Identity* App::identity_for(const std::string& fp) const {
    auto it = cfg.identities.find(fp);
    return it == cfg.identities.end() ? nullptr : &it->second;
}

std::vector<std::string> App::shell_holders() const {
    std::lock_guard<std::mutex> lk(m_);
    std::vector<std::string> r;
    for (const auto& kv : holders_) if (kv.second.first == "shell") r.push_back(kv.second.second);
    return r;
}

std::wstring App::overlay_text() const {
    std::string s = cfg.overlay.message;
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
