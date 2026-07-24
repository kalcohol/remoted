#include "ssh_internal.h"

#include <fstream>
#include <sstream>

// ---- host key ----
void ensure_host_key(const std::string& path) {
    ssh_key k = nullptr;
    if (ssh_pki_import_privkey_file(path.c_str(), nullptr, nullptr, nullptr, &k) == SSH_OK) {
        ssh_key_free(k); LOG("host key present: %s", path.c_str()); return;
    }
    auto pos = path.find_last_of("/\\");
    if (pos != std::string::npos) CreateDirectoryW(utf8_to_wide(path.substr(0, pos)).c_str(), nullptr);
    if (ssh_pki_generate(SSH_KEYTYPE_ED25519, 0, &k) == SSH_OK) {
        ssh_pki_export_privkey_file(k, nullptr, nullptr, nullptr, path.c_str());
        ssh_pki_export_pubkey_file(k, (path + ".pub").c_str());
        ssh_key_free(k);
        LOG("generated host key: %s", path.c_str());
    }
}

// ---- authorized_keys ----
std::vector<AuthKey> load_auth_keys(const std::string& path) {
    std::vector<AuthKey> keys;
    std::ifstream f(path);
    if (!f) { LOG("authorized_keys not found: %s", path.c_str()); return keys; }
    auto is_keytype = [](const std::string& s) {
        return s.rfind("ssh-", 0) == 0 || s.rfind("ecdsa-", 0) == 0 ||
               s.rfind("sk-", 0) == 0;
    };
    std::string line;
    while (std::getline(f, line)) {
        if (line.empty() || line[0] == '#') continue;
        // tokenize, skipping a leading options field (e.g. "no-pty ssh-ed25519 ...")
        std::vector<std::string> t;
        { std::istringstream is(line); std::string w; while (is >> w) t.push_back(w); }
        size_t ki = t.size();
        for (size_t i = 0; i < t.size(); ++i) if (is_keytype(t[i])) { ki = i; break; }
        if (ki == t.size() || ki + 1 >= t.size()) continue;   // no type + base64
        const std::string& type = t[ki];
        const std::string& b64 = t[ki + 1];
        std::string comment;
        for (size_t i = ki + 2; i < t.size(); ++i) { if (!comment.empty()) comment += " "; comment += t[i]; }
        while (!comment.empty() && (comment.back() == '\r' || comment.back() == '\n')) comment.pop_back();

        ssh_keytypes_e ty = ssh_key_type_from_name(type.c_str());
        ssh_key k = nullptr;
        if (ssh_pki_import_pubkey_base64(b64.c_str(), ty, &k) == SSH_OK)
            keys.push_back({ k, comment });
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

static std::mutex g_nf_m;
static std::set<std::string> g_notified_fp;   // unknown fingerprints we already ballooned about

// Notify once per fingerprint when a session ultimately fails to authenticate.
void notify_unknown_key(App* app, const std::string& fp) {
    if (!app || fp.empty()) return;
    bool do_notify = false;
    { std::lock_guard<std::mutex> lk(g_nf_m);
      if (g_notified_fp.size() < 64 && g_notified_fp.insert(fp).second) do_notify = true; }
    if (do_notify) {
        LOG("auth failed; last offered key: %s", fp.c_str());
        app->request_notify(L"unknown key rejected", utf8_to_wide(fp));
    }
}

Auth authenticate(ssh_session s, const std::vector<AuthKey>& keys) {
    ssh_message msg;
    std::string lastFp;   // last offered (rejected) pubkey, for failure reporting
    int budget = 32;      // hard cap on processed auth messages (brute-force protection)
    while (budget-- > 0) {
        msg = ssh_message_get(s);
        if (!msg) return { false, lastFp, "" };
        int t = ssh_message_type(msg), st = ssh_message_subtype(msg);
        if (t == SSH_REQUEST_AUTH && st == SSH_AUTH_METHOD_PUBLICKEY) {
            ssh_key off = ssh_message_auth_pubkey(msg);
            if (off) {
                bool matched = false;
                for (const auto& ak : keys) {
                    if (ssh_key_cmp(off, ak.key, SSH_KEY_CMP_PUBLIC) == 0) {
                        matched = true;
                        // The key alone proves nothing: the first request carries no
                        // signature (state NONE) -> ask the client to sign; only accept
                        // once libssh has verified the signature (state VALID).
                        switch (ssh_message_auth_publickey_state(msg)) {
                        case SSH_PUBLICKEY_STATE_NONE:
                            ssh_message_auth_reply_pk_ok_simple(msg);
                            break;
                        case SSH_PUBLICKEY_STATE_VALID: {
                            Auth r; r.ok = true; r.fp = key_fp(off); r.comment = ak.comment;
                            ssh_message_auth_reply_success(msg, 0);
                            ssh_message_free(msg);
                            return r;
                        }
                        default:   // WRONG / ERROR: bad signature
                            ssh_message_reply_default(msg);
                            break;
                        }
                        break;
                    }
                }
                if (!matched) {
                    lastFp = key_fp(off);   // remember; don't balloon per-attempt (clients try several)
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
    LOG("auth attempt limit reached; dropping connection");
    return { false, lastFp, "" };
}

std::string display_name(App* app, const Auth& a) {
    const Identity* id = app->identity_for(a.fp);
    if (id) return id->name + (id->contact.empty() ? "" : " / " + id->contact);
    if (!a.comment.empty()) return a.comment;
    auto p = a.fp.find(':');
    return "key:" + (p != std::string::npos ? a.fp.substr(p + 1, 12) : a.fp.substr(0, 12));
}
