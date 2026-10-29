import { record, text } from "../../../apps/console/src/view-model.js";

export function SessionResult({ result }: { result: Record<string, unknown> }) {
  const sessions = Array.isArray(result.sessions)
    ? result.sessions.map(record).filter((value) => value !== null)
    : [];
  return (
    <section aria-label="Signed-in sessions">
      <h3>Signed-in sessions</h3>
      {result.partial === true && (
        <p role="status">The session list is partial. Refresh before choosing a user.</p>
      )}
      {sessions.length ? (
        <div className="table-wrap">
          <table>
            <thead>
              <tr>
                <th>User</th>
                <th>Session</th>
                <th>State</th>
                <th>Selection</th>
              </tr>
            </thead>
            <tbody>
              {sessions.map((session) => (
                <tr key={`${session.sessionId}:${session.logonId}`}>
                  <td>
                    {text(session.domain)}\{text(session.user)}
                  </td>
                  <td>
                    {text(session.station)} · {String(session.sessionId)}
                  </td>
                  <td>{text(session.state)}</td>
                  <td>
                    {session.selectable === true
                      ? "Identity verified"
                      : text(session.reason).replaceAll("_", " ")}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ) : (
        <p>No signed-in user sessions were reported.</p>
      )}
      <p>
        Session identity is checked again when a user operation starts. A disconnected or replaced logon
        cannot be substituted automatically.
      </p>
    </section>
  );
}
