export function EmptyState({ title, children }: { title: string; children: string }) {
  return (
    <div className="empty">
      <strong>{title}</strong>
      {children}
    </div>
  );
}

export function StatusMessage({
  message,
  error = false,
}: {
  message: string;
  error?: boolean;
}) {
  return <div className={`status${error ? " is-error" : ""}`}>{message}</div>;
}
