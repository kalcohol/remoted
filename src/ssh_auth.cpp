#include "ssh_internal.h"

#include <cctype>
#include <fstream>
#include <sstream>

// ---- host key ----
void ensure_host_key(const std::string& path) {
    ssh_key k = nullptr;
    if (ssh_pki_import_privkey_file(path.c_str(), nullptr, nullptr, nullptr, &k) == SSH_OK) {
        ssh_key_free(k); LOG("host key present: %s", path.c_str()); return;
    }
    auto pos = path.find_last_of("/\\");
    if (pos != std::string::npos) ensure_dir(path.substr(0, pos));
    if (ssh_pki_generate(SSH_KEYTYPE_ED25519, 0, &k) == SSH_OK) {
        if (ssh_pki_export_privkey_file(k, nullptr, nullptr, nullptr, path.c_str()) != SSH_OK)
            LOG("host key export FAILED: %s", path.c_str());
        else if (ssh_pki_export_pubkey_file(k, (path + ".pub").c_str()) != SSH_OK)
            LOG("host pubkey export FAILED: %s.pub", path.c_str());
        else
            LOG("generated host key: %s", path.c_str());
        ssh_key_free(k);
    } else {
        LOG("host key generation FAILED (ssh_pki_generate)");
    }
}

// ---- peer address ----
std::string peer_ip(ssh_session s) {
    SOCKET fd = (SOCKET)ssh_get_fd(s);
    if (fd == INVALID_SOCKET) return "";
    sockaddr_storage ss{}; int len = sizeof(ss);
    if (getpeername(fd, (sockaddr*)&ss, &len) != 0) return "";
    char buf[INET6_ADDRSTRLEN] = {};
    if (ss.ss_family == AF_INET) {
        inet_ntop(AF_INET, &((sockaddr_in*)&ss)->sin_addr, buf, sizeof(buf));
    } else if (ss.ss_family == AF_INET6) {
        inet_ntop(AF_INET6, &((sockaddr_in6*)&ss)->sin6_addr, buf, sizeof(buf));
        // dual-stack listeners hand us IPv4-mapped addresses; normalize so
        // from="10.0.*" matches as an operator would expect
        if (strncmp(buf, "::ffff:", 7) == 0) memmove(buf, buf + 7, strlen(buf + 7) + 1);
    }
    return buf;
}

// ---- authorized_keys line / options parsing ----
namespace {

struct Tok { std::string text; size_t off; };

// whitespace tokenizer that keeps quoted sections (e.g. command="a b") together;
// backslash escapes the next char inside quotes (\" doesn't flip quote state)
std::vector<Tok> tokenize_quoted(const std::string& line) {
    std::vector<Tok> out;
    size_t i = 0, n = line.size();
    while (i < n) {
        while (i < n && (line[i] == ' ' || line[i] == '\t')) i++;
        if (i >= n) break;
        size_t start = i;
        bool inq = false;
        std::string t;
        while (i < n && (inq || (line[i] != ' ' && line[i] != '\t'))) {
            if (inq && line[i] == '\\' && i + 1 < n) { t += line[i]; t += line[i + 1]; i += 2; continue; }
            if (line[i] == '"') inq = !inq;
            t += line[i];
            i++;
        }
        out.push_back({ t, start });
    }
    return out;
}

bool is_keytype(const std::string& s) {
    return s.rfind("ssh-", 0) == 0 || s.rfind("ecdsa-", 0) == 0 ||
           s.rfind("sk-", 0) == 0;
}

std::string unquote(const std::string& v) {
    if (v.size() >= 2 && v.front() == '"' && v.back() == '"') {
        std::string r;
        const size_t last = v.size() - 1;   // index of the closing quote
        for (size_t i = 1; i < last; ++i) {
            if (v[i] == '\\' && i + 1 < last && (v[i + 1] == '"' || v[i + 1] == '\\')) { r += v[i + 1]; ++i; }
            else r += v[i];
        }
        return r;
    }
    return v;
}

KeyOpts parse_key_options(const std::string& s, const std::string& keydesc) {
    KeyOpts o;
    size_t i = 0, n = s.size();
    while (i < n) {
        // split on commas outside quotes (\" stays inside via the escape)
        bool inq = false;
        size_t start = i;
        while (i < n && (inq || s[i] != ',')) {
            if (inq && s[i] == '\\' && i + 1 < n) { i += 2; continue; }
            if (s[i] == '"') inq = !inq;
            i++;
        }
        std::string item = s.substr(start, i - start);
        if (i < n) i++;   // skip the comma
        auto b = item.find_first_not_of(" \t");
        if (b == std::string::npos) continue;
        item = item.substr(b, item.find_last_not_of(" \t") - b + 1);

        std::string name = item, value;
        auto eq = item.find('=');
        if (eq != std::string::npos) { name = item.substr(0, eq); value = unquote(item.substr(eq + 1)); }
        for (auto& c : name) c = (char)std::tolower((unsigned char)c);

        if (name == "command") o.forced_command = value;
        else if (name == "no-pty") o.no_pty = true;
        else if (name == "from") o.from = value;
        else if (name == "no-agent-forwarding" || name == "no-x11-forwarding" ||
                 name == "no-port-forwarding" || name == "restrict" ||
                 name == "permitopen" || name == "permitlisten") {
            // inherently satisfied: remoted implements no forwarding/tunneling at all
        } else {
            LOG("authorized_keys: option '%s' not supported - ignoring (key %s)",
                name.c_str(), keydesc.c_str());
        }
    }
    return o;
}

// case-insensitive * ? wildcard match
bool wild_match(const std::string& pat, const std::string& str) {
    size_t p = 0, s = 0, star = std::string::npos, ss = 0;
    auto eq = [](char a, char b) { return std::tolower((unsigned char)a) == std::tolower((unsigned char)b); };
    while (s < str.size()) {
        if (p < pat.size() && (pat[p] == '?' || eq(pat[p], str[s]))) { p++; s++; }
        else if (p < pat.size() && pat[p] == '*') { star = p++; ss = s; }
        else if (star != std::string::npos) { p = star + 1; s = ++ss; }
        else return false;
    }
    while (p < pat.size() && pat[p] == '*') p++;
    return p == pat.size();
}

// from="pattern[,pattern]": first matching entry decides, '!' negates;
// no match -> deny (OpenSSH semantics). CIDR (a/b) is not implemented and
// never matches (fail closed).
bool from_allows(const std::string& from, const std::string& ip) {
    if (from.empty()) return true;
    if (ip.empty()) { LOG("from= set but peer address unknown - denying"); return false; }
    size_t i = 0, n = from.size();
    while (i <= n) {
        size_t j = from.find(',', i);
        std::string p = from.substr(i, j == std::string::npos ? n : j - i);
        i = (j == std::string::npos) ? n + 1 : j + 1;
        if (p.empty()) continue;
        bool neg = p[0] == '!';
        std::string pat = neg ? p.substr(1) : p;
        if (pat.find('/') != std::string::npos) {
            LOG("from= pattern '%s': CIDR not supported - treating as no-match", pat.c_str());
            continue;
        }
        if (wild_match(pat, ip)) return !neg;
    }
    return false;
}

} // namespace

// ---- authorized_keys ----
std::vector<AuthKey> load_auth_keys(const std::string& path) {
    std::vector<AuthKey> keys;
    std::ifstream f(path);
    if (!f) { LOG("authorized_keys not found: %s", path.c_str()); return keys; }
    std::string line;
    int lineno = 0;
    while (std::getline(f, line)) {
        lineno++;
        // getline keeps the \r of CRLF files; a trailing \r on the base64 token
        // makes libssh reject the key (silently, if the line has no comment)
        while (!line.empty() && (line.back() == '\r' || line.back() == '\n')) line.pop_back();
        if (line.empty() || line[0] == '#') continue;
        auto t = tokenize_quoted(line);
        size_t ki = t.size();
        for (size_t i = 0; i < t.size(); ++i) if (is_keytype(t[i].text)) { ki = i; break; }
        if (ki == t.size() || ki + 1 >= t.size()) continue;   // no type + base64
        const std::string& type = t[ki].text;
        const std::string& b64 = t[ki + 1].text;
        std::string comment;
        for (size_t i = ki + 2; i < t.size(); ++i) { if (!comment.empty()) comment += " "; comment += t[i].text; }
        while (!comment.empty() && (comment.back() == '\r' || comment.back() == '\n')) comment.pop_back();

        // everything before the keytype token is the options field
        KeyOpts opts;
        if (ki > 0) {
            std::string desc = comment.empty() ? ("line " + std::to_string(lineno)) : comment;
            opts = parse_key_options(line.substr(0, t[ki].off), desc);
        }

        ssh_keytypes_e ty = ssh_key_type_from_name(type.c_str());
        ssh_key k = nullptr;
        if (ssh_pki_import_pubkey_base64(b64.c_str(), ty, &k) == SSH_OK)
            keys.push_back({ k, comment, opts });
        else
            LOG("authorized_keys:%d: key import failed - line skipped", lineno);
    }
    LOG("loaded %d authorized keys", (int)keys.size());
    return keys;
}
void free_keys(std::vector<AuthKey>& keys) {
    for (auto& ak : keys) ssh_key_free(ak.key);
    keys.clear();
}

std::string key_fp(ssh_key k) {
    unsigned char* h = nullptr; size_t hl = 0;
    if (ssh_get_publickey_hash(k, SSH_PUBLICKEY_HASH_SHA256, &h, &hl) != SSH_OK) return "";
    char* s = ssh_get_fingerprint_hash(SSH_PUBLICKEY_HASH_SHA256, h, hl);
    std::string r = s ? s : "";
    ssh_string_free_char(s);
    ssh_clean_pubkey_hash(&h);
    return r;
}

// mutable statics are intentionally leaked: shutdown stragglers (detached
// after the join budget) may still touch them while the CRT destroys statics.
struct AuthStatics {
    std::mutex nf_m;
    std::set<std::string> notified_fp;                          // fps we already ballooned about
    std::mutex ip_m;
    std::map<std::string, std::pair<int, ULONGLONG>> ip_fails;  // ip -> {fails, window start}
};
static AuthStatics& A() { static auto* p = new AuthStatics(); return *p; }

// Notify once per fingerprint when a session ultimately fails to authenticate.
void notify_unknown_key(App* app, const std::string& fp) {
    if (!app || fp.empty()) return;
    bool do_notify = false;
    { std::lock_guard<std::mutex> lk(A().nf_m);
      auto& seen = A().notified_fp;
      if (seen.size() >= 64) seen.clear();      // cap: evict all rather than going silent forever
      if (seen.insert(fp).second) do_notify = true; }
    if (do_notify) {
        LOG("auth failed; last offered key: %s", fp.c_str());
        app->request_notify(L"unknown key rejected", utf8_to_wide(fp));
    }
}

// ---- per-IP throttle: 10 failed sessions within 60s -> drop early ----
static bool ip_throttled(const std::string& ip) {
    if (ip.empty()) return false;
    std::lock_guard<std::mutex> lk(A().ip_m);
    auto now = GetTickCount64();
    auto it = A().ip_fails.find(ip);
    if (it == A().ip_fails.end()) return false;
    if (now - it->second.second > 60000) { A().ip_fails.erase(it); return false; }
    return it->second.first >= 10;
}
static void ip_record_fail(const std::string& ip) {
    if (ip.empty()) return;
    std::lock_guard<std::mutex> lk(A().ip_m);
    ULONGLONG now = GetTickCount64();
    auto& e = A().ip_fails[ip];
    if (now - e.second > 60000) e = { 0, now };
    e.first++;
    if (A().ip_fails.size() > 1024) {   // bound: drop expired windows; clear if still huge
        for (auto it = A().ip_fails.begin(); it != A().ip_fails.end();)
            if (now - it->second.second > 60000) it = A().ip_fails.erase(it); else ++it;
        if (A().ip_fails.size() > 4096) A().ip_fails.clear();
    }
}
static void ip_record_success(const std::string& ip) {
    if (ip.empty()) return;
    std::lock_guard<std::mutex> lk(A().ip_m);
    A().ip_fails.erase(ip);   // a working login resets the failure window
}

Auth authenticate(ssh_session s, const std::vector<AuthKey>& keys,
                  const std::shared_ptr<std::atomic<bool>>& abort) {
    ssh_message msg;
    std::string lastFp;        // last offered key that is NOT in authorized_keys (for reporting)
    bool fail_counted = false; // count a failed session at most once
    const std::string ip = peer_ip(s);
    if (ip_throttled(ip)) {
        LOG("auth: %s throttled (too many recent failures) - dropping", ip.c_str());
        return { false, "", "" };
    }
    int budget = 32;      // hard cap on processed auth messages (brute-force protection)
    while (budget-- > 0) {
        if (abort && abort->load()) break;   // disconnect-all / shutdown
        msg = ssh_message_get(s);
        if (!msg) break;
        int t = ssh_message_type(msg), st = ssh_message_subtype(msg);
        if (t == SSH_REQUEST_AUTH && st == SSH_AUTH_METHOD_PUBLICKEY) {
            ssh_key off = ssh_message_auth_pubkey(msg);
            if (off) {
                bool in_authorized = false, matched = false;
                for (const auto& ak : keys) {
                    if (ssh_key_cmp(off, ak.key, SSH_KEY_CMP_PUBLIC) != 0) continue;
                    in_authorized = true;
                    // from= is part of authorization: a matching key from a
                    // disallowed address counts as no match at all (and is NOT
                    // reported as an "unknown key" - the log line below suffices)
                    if (!ak.opts.from.empty() && !from_allows(ak.opts.from, ip)) {
                        LOG("auth: key '%s' not allowed from %s", ak.comment.c_str(), ip.c_str());
                        continue;
                    }
                    matched = true;
                    // The key alone proves nothing: the first request carries no
                    // signature (state NONE) -> ask the client to sign; only accept
                    // once libssh has verified the signature (state VALID).
                    switch (ssh_message_auth_publickey_state(msg)) {
                    case SSH_PUBLICKEY_STATE_NONE:
                        ssh_message_auth_reply_pk_ok_simple(msg);
                        break;
                    case SSH_PUBLICKEY_STATE_VALID: {
                        Auth r; r.ok = true; r.fp = key_fp(off);
                        r.comment = ak.comment; r.opts = ak.opts;
                        ip_record_success(ip);
                        ssh_message_auth_reply_success(msg, 0);
                        ssh_message_free(msg);
                        return r;
                    }
                    default:   // WRONG / ERROR: bad signature -> slow down online guessing
                        Sleep(1000);
                        ip_record_fail(ip);
                        fail_counted = true;
                        ssh_message_reply_default(msg);
                        break;
                    }
                    break;
                }
                if (!matched) {
                    if (!in_authorized) lastFp = key_fp(off);   // genuinely unknown key
                    ssh_message_reply_default(msg);
                }
                ssh_message_free(msg);
                continue;
            }
            ssh_message_reply_default(msg);
        } else if (t == SSH_REQUEST_AUTH) {
            ssh_message_auth_set_methods(msg, SSH_AUTH_METHOD_PUBLICKEY);
            ssh_message_reply_default(msg);
        } else {
            ssh_message_reply_default(msg);
        }
        ssh_message_free(msg);
    }
    if (budget <= 0) LOG("auth attempt limit reached; dropping connection");
    if (!fail_counted) ip_record_fail(ip);   // every exit here is a failed session
    return { false, lastFp, "" };
}

// fingerprint -> identities map; else the key's comment; else a short key id (never "unknown").
std::string display_name(App* app, const Auth& a) {
    Identity id;
    if (app->identity_for(a.fp, id))
        return id.name + (id.contact.empty() ? "" : " / " + id.contact);
    if (!a.comment.empty()) return a.comment;
    auto p = a.fp.find(':');
    return "key:" + (p != std::string::npos ? a.fp.substr(p + 1, 12) : a.fp.substr(0, 12));
}
