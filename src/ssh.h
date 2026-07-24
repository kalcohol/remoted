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
