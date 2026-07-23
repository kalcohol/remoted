#pragma once
#include "app.h"

// Start all ssh binds (main shell + per-serial). Spawns accept threads.
// Returns immediately; threads are detached and self-managing.
void ssh_start(App* app);

// Force-close every active ssh session (used by tray "disconnect all").
void ssh_disconnect_all();

// Signal accept loops to stop + disconnect sessions (clean process exit).
void ssh_request_shutdown();
