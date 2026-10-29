# Security guidance

OneControl is authorised endpoint management software. Review administrator/agent identity boundaries, credential disclosure, PostgreSQL transaction and lease races, command schema enforcement, update trust, IPC permissions and downgrade/replay resistance.

Required properties:

- No management credential enters the GUI or user-session broker.
- The long-running service requires LocalSystem and outbound HTTPS. Ordinary users cannot write its code, configuration or state.
- Remote tasks are typed allowlisted operations, never shell text or caller-chosen executable paths.
- Installation batches require another authenticated approver and a successful previous rollout ring.
- Unknown installation outcomes block subsequent work until explicit, evidenced IT reconciliation.
- Custom installer trust includes signed metadata, exact length/hash, allowed origin/package, expiry, increasing sequence and Windows publisher verification.
- No security-product evasion, process hiding, credential harvesting or automatically created security exclusions.
- Production never uses development authentication or PGlite; secrets and private keys are absent from Git and logs.

Report suspected issues privately to the repository owner. Include an affected revision, trust boundary, reproducible conditions and impact. Never test destructive actions on a production endpoint. Endpoint-local administrators, database administrators and the offline release signing authority are trusted principals; document that trust rather than claiming invisibility or tamper immunity.
