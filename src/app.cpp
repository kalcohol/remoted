#include "app.h"
#include "util.h"
#include "log.h"
#include <algorithm>

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

int App::session_start(const std::string& fp) {
    const Identity* id = identity_for(fp);
    std::string who = id ? id->name : (fp.empty() ? std::string("(unknown)") : fp);
    std::lock_guard<std::mutex> lk(m_);
    int t = next_token_++;
    holders_[t] = who;
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

bool App::mark_busy(const std::string& name, const std::string& holder) {
    std::lock_guard<std::mutex> lk(m_);
    for (auto& st : status_) {
        if (st.name == name) {
            if (st.busy) return false;
            st.busy = true; st.holder = holder;
            return true;
        }
    }
    return false;
}

void App::clear_busy(const std::string& name) {
    std::lock_guard<std::mutex> lk(m_);
    for (auto& st : status_) {
        if (st.name == name) { st.busy = false; st.holder.clear(); break; }
    }
}

const Identity* App::identity_for(const std::string& fp) const {
    auto it = cfg.identities.find(fp);
    return it == cfg.identities.end() ? nullptr : &it->second;
}

std::wstring App::overlay_text() const {
    std::string s = cfg.overlay.message;
    if (s.empty()) s = "Remote session active - please do not operate";
    s += "\r\n\r\nOccupied by: ";
    std::string names;
    {
        std::lock_guard<std::mutex> lk(m_);
        for (const auto& kv : holders_) {
            if (!names.empty()) names += ", ";
            names += kv.second;
        }
    }
    if (names.empty()) names = "(unknown)";
    s += names;
    s += "\r\n\r\nPlease Love & Peace :)    [Disconnect / Minimize below]";
    return utf8_to_wide(s);
}
