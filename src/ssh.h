#pragma once
#include "app.h"

// Start all ssh binds (main shell + per-serial). Spawns tracked accept threads
// (see spawn_tracked); returns immediately.
void ssh_start(App* app);

// Force-close every active ssh session (used by tray "disconnect all").
void ssh_disconnect_all();

// Signal accept loops to stop + disconnect sessions, then join workers within
// a bounded budget (clean process exit). Idempotent.
void ssh_request_shutdown();

// The port a serial listener is ACTUALLY bound to right now (0 = not bound).
// App::reload uses this to tell "new config entry" apart from "re-added entry
// whose old listener is still alive".
uint16_t ssh_serial_bound_port(const std::string& name);
