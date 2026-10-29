import { HttpError } from "./api-errors.js";
import { date } from "./view-model.js";

type Snapshot<T> = { data: T; updatedAt: string };
export type Section<T> =
  | { status: "idle" }
  | { status: "loading"; previous?: Snapshot<T> }
  | { status: "loaded"; snapshot: Snapshot<T> }
  | { status: "unsupported"; httpStatus: number }
  | { status: "failed"; message: string; httpStatus?: number; previous?: Snapshot<T> };

export function snapshot<T>(section: Section<T>): Snapshot<T> | undefined {
  return section.status === "loaded"
    ? section.snapshot
    : section.status === "loading" || section.status === "failed"
      ? section.previous
      : undefined;
}

export function pending<T>(section: Section<T>): Section<T> {
  const previous = snapshot(section);
  return { status: "loading", ...(previous ? { previous } : {}) };
}

export function failed<T>(section: Section<T>, error: unknown): Section<T> {
  const httpStatus = error instanceof HttpError ? error.status : undefined;
  if (httpStatus === 404 || httpStatus === 405 || httpStatus === 501)
    return { status: "unsupported", httpStatus };
  const previous = httpStatus === 403 ? undefined : snapshot(section);
  return {
    status: "failed",
    message: error instanceof Error ? error.message : "Connection failed",
    ...(httpStatus === undefined ? {} : { httpStatus }),
    ...(previous ? { previous } : {}),
  };
}

export function SectionNotice<T>({ name, section }: { name: string; section: Section<T> }) {
  const saved = snapshot(section);
  let message: string;
  switch (section.status) {
    case "idle":
      message = "Not requested.";
      break;
    case "loading":
      message = "Loading.";
      break;
    case "loaded":
      message = `Updated ${date(section.snapshot.updatedAt)}.`;
      break;
    case "unsupported":
      message = `Request unsupported (HTTP ${section.httpStatus}). Module availability is unknown.`;
      break;
    case "failed":
      message = `${section.httpStatus === 403 ? "Access denied" : "Unavailable"}${section.httpStatus ? ` (HTTP ${section.httpStatus})` : ""}. ${section.message}`;
  }
  return (
    <p className="section-status" data-section={name} data-state={section.status}>
      <strong>{name}</strong> · {message}
      {saved && section.status !== "loaded" && ` Showing stale data from ${date(saved.updatedAt)}.`}
    </p>
  );
}
