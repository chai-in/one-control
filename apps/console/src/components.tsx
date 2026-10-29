import type { Monitor } from "lucide-react";
export function Stat({
  label,
  value,
  icon: Icon,
  note,
}: {
  label: string;
  value: number | null;
  icon: typeof Monitor;
  note: string;
}) {
  return (
    <div className="stat">
      <div>
        <span>{label}</span>
        <Icon size={18} />
      </div>
      <strong className={value === null ? "stat-unavailable" : undefined}>
        {value === null ? "Unavailable" : value.toString().padStart(2, "0")}
      </strong>
      <small>{note}</small>
    </div>
  );
}
export function Empty({ icon: Icon, title, text }: { icon: typeof Monitor; title: string; text: string }) {
  return (
    <div className="empty">
      <div className="empty-icon">
        <Icon size={25} />
      </div>
      <h3>{title}</h3>
      <p>{text}</p>
    </div>
  );
}
