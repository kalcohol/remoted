#include "app.h"
#include "util.h"
#include "log.h"
#include <algorithm>
#include <map>

void App::start() {
    devs_ = enumerate_com_ports();
    std::lock_guard<std::mutex> lk(m_);
    status_.clear();
    for (const auto& s : cfg.serials) {
        SerialStatus st;
        st.name        = s.name;
        st.listen_port = s.listen_port;
        st.com         = resolve_com(s, devs_);
        // present only if the resolved COM actually exists on THIS machine
        st.present = false;
        for (const auto& e : devs_) {
            if (e.com == st.com) { st.present = true; break; }
        }
        status_.push_back(st);
        LOG("serial[%s] -> %s (%s)", s.name.c_str(), st.com.c_str(),
            st.present ? "present" : "absent");
    }
}

std::vector<SerialStatus> App::snapshot() const {
    std::lock_guard<std::mutex> lk(m_);
    return status_;
}

std::string App::find_com_for(const std::string& name) const {
    for (const auto& s : cfg.serials)
        if (s.name == name) return resolve_com(s, devs_);
    return "";
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
    std::lock_guard<std::mutex> lk(m_);
    for (auto& st : status_) {
        if (st.name == name) { st.holders[token] = holder; break; }
    }
    if (hwnd_main) PostMessage(hwnd_main, WM_APP_STATE, 1, 0);
    return true;
}

void App::clear_busy(const std::string& name, int token) {
    std::lock_guard<std::mutex> lk(m_);
    for (auto& st : status_) {
        if (st.name == name) { st.holders.erase(token); break; }
    }
    if (hwnd_main) PostMessage(hwnd_main, WM_APP_STATE, 1, 0);
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
