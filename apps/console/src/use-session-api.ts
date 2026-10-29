import { useCallback, useRef, useState } from "react";
import { apiError, HttpError } from "./api-errors.js";

type Session = { token: string; controller: AbortController };
const ended = () => new DOMException("Authenticated session ended", "AbortError");

export function useSessionApi(clearData: (reason?: string) => void) {
  const [session, setSession] = useState<Session>(() => ({ token: "", controller: new AbortController() }));
  const current = useRef(session);
  const replaceToken = useCallback(
    (token: string, reason?: string) => {
      current.current.controller.abort();
      const next = { token, controller: new AbortController() };
      current.current = next;
      clearData(reason);
      setSession(next);
    },
    [clearData],
  );
  const isCurrent = useCallback(
    () => current.current === session && !session.controller.signal.aborted,
    [session],
  );
  const api = useCallback(
    async <T>(
      path: string,
      body?: unknown,
      method = body ? "POST" : "GET",
      idempotencyKey?: string,
    ): Promise<T> => {
      if (!session.token || !isCurrent()) throw ended();
      const response = await fetch(path, {
        method,
        signal: AbortSignal.any([session.controller.signal, AbortSignal.timeout(30_000)]),
        headers: {
          Authorization: `Bearer ${session.token}`,
          "Content-Type": "application/json",
          ...(idempotencyKey ? { "Idempotency-Key": idempotencyKey } : {}),
        },
        ...(body ? { body: JSON.stringify(body) } : {}),
      });
      if (!isCurrent()) throw ended();
      if (response.status === 401) {
        replaceToken("", "Your access could not be authenticated. Sign in again.");
        throw ended();
      }
      let result: unknown;
      try {
        result = await response.json();
      } catch {
        if (!isCurrent()) throw ended();
        const message =
          "The control plane returned an unexpected response. Refresh the current state before retrying a change.";
        throw response.ok ? new Error(message) : new HttpError(response.status, message);
      }
      if (!isCurrent()) throw ended();
      if (!response.ok)
        throw new HttpError(
          response.status,
          apiError(result && typeof result === "object" && "error" in result ? result.error : undefined),
        );
      return result as T;
    },
    [session, isCurrent, replaceToken],
  );
  return { token: session.token, replaceToken, api, isCurrent };
}
