package brokercore

// RefusalReasonField is the ErrorResponse field carrying the broker's fixed refusal code; PostgreSQL never sends it, so a relay can tell a broker refusal from a server error.
const RefusalReasonField byte = 'G'

// RefusalHeader carries the broker's fixed refusal code on its own HTTP refusals; it is stripped from upstream responses so a destination's answer never reads as a broker refusal.
const RefusalHeader = "X-Gatehouse-Refusal"
