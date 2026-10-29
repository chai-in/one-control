import { X } from "lucide-react";
import { type ReactNode, useEffect, useId, useRef } from "react";

export function Dialog({
  title,
  children,
  close,
  wide = false,
  closeLabel = "Close dialog",
  busy = false,
  error,
}: {
  title: string;
  children: ReactNode;
  close: () => void;
  wide?: boolean;
  closeLabel?: string;
  busy?: boolean;
  error?: string;
}) {
  const element = useRef<HTMLDialogElement>(null);
  const titleId = useId();
  useEffect(() => {
    const dialog = element.current;
    const opener = document.activeElement;
    dialog?.showModal();
    return () => {
      dialog?.close();
      if (opener instanceof HTMLElement && opener.isConnected) opener.focus({ preventScroll: true });
    };
  }, []);
  return (
    <dialog
      ref={element}
      className={`modal native-dialog${wide ? " wide" : ""}`}
      aria-labelledby={titleId}
      onCancel={(event) => {
        event.preventDefault();
        if (!busy) close();
      }}
    >
      <button type="button" className="close" aria-label={closeLabel} disabled={busy} onClick={close}>
        <X size={18} />
      </button>
      <h2 id={titleId}>{title}</h2>
      {error && (
        <p className="error" role="alert">
          {error}
        </p>
      )}
      {children}
    </dialog>
  );
}
