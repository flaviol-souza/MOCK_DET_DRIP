#pragma once
#include <Arduino.h>          // required for millis()
#include "f3411_messages.h"   // for DRIP_EPOCH_UNIX_S / SIM_DRIP_TIME_BASE

// ---------------------------------------------------------------------------
// DRIP clock (ADR 0002 — real clock via PC serial, constant fallback)
//
// All DRIP/ASTM timestamps use the DRIP epoch: seconds since 2019-01-01
// 00:00:00 UTC (RFC 9575 §3.2.4.3). This module returns "now" in that epoch.
//
// TIME SOURCE, in priority order:
//   1. REAL clock seeded from the PC over the serial console. The operator (or
//      a helper) sends `time <unix_seconds_UTC>` once per session; the firmware
//      converts it to the DRIP epoch and tracks it with millis() from then on.
//   2. FALLBACK constant SIM_DRIP_TIME_BASE (f3411_messages.h), used only until
//      a seed arrives — so a session with no PC still transmits (though the
//      constant may be stale; that is the documented consequence of running
//      without the PC / without an RTC/GPS).
//
// State is header-owned via C++17 `inline` variables (single shared instance
// across translation units). GPS/RTC can later replace source #1 by calling
// drip_time_set_unix() from their driver — the rest of the firmware is unchanged.
// ---------------------------------------------------------------------------

inline uint32_t g_drip_base_epoch = SIM_DRIP_TIME_BASE;  // DRIP-epoch secs at ref
inline uint32_t g_drip_ref_millis = 0;                   // millis() when base set
inline bool     g_drip_seeded     = false;               // has a real seed arrived?

// Seed the clock from a real Unix time (seconds since 1970 UTC), e.g. the PC
// clock delivered over serial. Rejects obviously bogus values (pre-2019).
inline void drip_time_set_unix(uint32_t unix_secs) {
    if (unix_secs < DRIP_EPOCH_UNIX_S) return;           // ignore pre-epoch garbage
    g_drip_base_epoch = unix_secs - DRIP_EPOCH_UNIX_S;   // -> DRIP epoch
    g_drip_ref_millis = millis();
    g_drip_seeded     = true;
}

// True once a real time source has seeded the clock this session.
inline bool drip_time_is_seeded() { return g_drip_seeded; }

// Current DRIP-epoch base in effect (seeded value, or the fallback constant).
inline uint32_t drip_time_base_epoch() { return g_drip_base_epoch; }

// Current time in the DRIP epoch. Uses the seeded real clock if available, else
// the SIM_DRIP_TIME_BASE fallback. Before any seed, g_drip_ref_millis == 0, so
// this reduces exactly to the previous behaviour (SIM_DRIP_TIME_BASE + uptime).
inline uint32_t drip_timestamp() {
    return g_drip_base_epoch + (uint32_t)((millis() - g_drip_ref_millis) / 1000UL);
}
