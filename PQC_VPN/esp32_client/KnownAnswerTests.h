#ifndef KNOWN_ANSWER_TESTS_H
#define KNOWN_ANSWER_TESTS_H

// ============================================================================
// Known-answer tests (KATs) for EVERY algorithm this VPN uses, run on the ESP32.
// Each test feeds fixed inputs from an official test vector (or from an
// independent reference implementation) and compares the output byte for byte.
// Prints one PASS/FAIL line and one "BENCH,B0,..." line per test.
// Returns true only if every test passed. Used by SystemBenchmark (test B0).
// ============================================================================
bool runKnownAnswerTests();

#endif // KNOWN_ANSWER_TESTS_H
