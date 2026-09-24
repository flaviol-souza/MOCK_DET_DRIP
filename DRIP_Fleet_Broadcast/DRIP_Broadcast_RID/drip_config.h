#pragma once

// ===========================================================================
// Scenario board — the ONE place to choose a build (ADR 0004).
//
// Pick exactly ONE DRIP_SCENARIO_* below. It expands into the individual
// switches (transport, test BE chain, fleet size, which UA identity to emit).
//
// STYLE B (single override point): this file is the ONE place you OVERRIDE the
// switches. Each switch still has an OWNER header that keeps its DEFAULT behind
// an #ifndef, so nothing here MOVES a constant's ownership — it only overrides:
//
//     FLEET_MAX        owner drone_fleet.h        (#ifndef default = 1)
//     DRIP_UA_SLOT     fallback at the bottom here (default = 0)
//     DRIP_TEST_BE     compiled in only when defined (drip_registration.*)
//     transport        DRIP_TX_SOFTAP / DRIP_TX_BLE / (none = raw injection)
//
// The active scenario is printed at boot as "[CFG] scenario=..." (fleet_init),
// so any capture/log is self-explaining.
//
// NOTE: two session-tuning switches still live in their owner headers and are
// NOT folded in yet (documented follow-up): SIM_DRIP_TIME_BASE
// (f3411_messages.h) and DRONE_REPLAY_RECORDED_TIME (drone_playback.h).
// ===========================================================================

// ---- 1) choose exactly ONE scenario ---------------------------------------
// #define DRIP_SCENARIO_BENCH_BLE
// #define DRIP_SCENARIO_BENCH_WIFI_SOFTAP
// #define DRIP_SCENARIO_BENCH_WIFI_FLEET
#define DRIP_SCENARIO_ROGUE_BLE          // R1 negative test: untrusted UA
                                            //   (no endorsement, key not enrolled,
                                            //   absent from DNS). The observer
                                            //   MUST reject it (E-KEY-01 / NXDOMAIN).

// ---- 2) expand the chosen scenario ----------------------------------------
#if defined(DRIP_SCENARIO_BENCH_BLE)
  #define DRIP_TX_BLE
  #define DRIP_TEST_BE
  #define DRIP_UA_SLOT         0            // trusted slot-0 identity (d952)
  #define FLEET_MAX            1
  #define DRIP_SCENARIO_NAME   "BENCH_BLE"

#elif defined(DRIP_SCENARIO_BENCH_WIFI_SOFTAP)
  #define DRIP_TX_SOFTAP
  #define DRIP_TEST_BE
  #define DRIP_UA_SLOT         0
  #define FLEET_MAX            1
  #define DRIP_SCENARIO_NAME   "BENCH_WIFI_SOFTAP"

#elif defined(DRIP_SCENARIO_BENCH_WIFI_FLEET)
  // no transport macro -> default raw 802.11 injection (multi-drone)
  #define DRIP_TEST_BE
  #define FLEET_MAX            3
  #define DRIP_SCENARIO_NAME   "BENCH_WIFI_FLEET"

#elif defined(DRIP_SCENARIO_ROGUE_BLE)
  #define DRIP_TX_BLE
  // NO DRIP_TEST_BE on purpose -> no Broadcast Endorsement on the air.
  #define DRIP_UA_SLOT         3            // = DRIP_SLOT_ROGUE (det_generator.h):
                                            //   unenrolled key, not in DNS.
  #define FLEET_MAX            1
  #define DRIP_SCENARIO_NAME   "ROGUE_BLE"

#else
  #error "drip_config.h: select exactly ONE DRIP_SCENARIO_* above."
#endif

// ---- 3) guards -------------------------------------------------------------
// One transmit transport at a time. BLE is BLE-only: Wi-Fi + BLE coexistence on
// the shared 2.4 GHz radio is out of scope (README). (A scenario never sets both;
// this catches a hand-edit that does.)
#if defined(DRIP_TX_BLE) && defined(DRIP_TX_SOFTAP)
#error "DRIP_TX_BLE e single-transport (BLE-only). Nao habilite DRIP_TX_SOFTAP junto (coexistencia Wi-Fi+BLE fora de escopo)."
#endif

// ---- 4) fallback defaults (always defined for the code that reads them) ----
#ifndef DRIP_UA_SLOT
#define DRIP_UA_SLOT         0
#endif
#ifndef DRIP_SCENARIO_NAME
#define DRIP_SCENARIO_NAME   "custom"
#endif
