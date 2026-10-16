package brokercore

// RefusalReasonField is the ErrorResponse field in which the PostgreSQL broker
// names why it refused, as a fixed reason code (the audit outcome). PostgreSQL
// never sends this field type and clients ignore unknown fields, so a relay can
// tell a broker refusal from a database server error and replace the broker's
// text with its own fixed words.
const RefusalReasonField byte = 'G'

// RefusalHeader names, on an HTTP refusal the broker makes itself, why it
// refused, as a fixed reason code. The broker owns it: it is stripped from
// every upstream response (ShouldStripResponseHeader), so a destination's
// answer, which may already have been applied, never reads as a refusal the
// request never left the broker for.
const RefusalHeader = "X-Gatehouse-Refusal"
