import type { ReactNode } from "react";

export type Cell = ReactNode | { value: ReactNode; num?: boolean; cls?: string };

export function DataTable({ headers, rows }: { headers: string[]; rows: Cell[][] }) {
  return (
    <table>
      <thead>
        <tr>
          {headers.map((header) => (
            <th key={header}>{header}</th>
          ))}
        </tr>
      </thead>
      <tbody>
        {rows.map((cells, i) => (
          <tr key={i}>
            {cells.map((cell, j) => {
              const isObject = cell !== null && typeof cell === "object" && "value" in cell;
              const className = isObject
                ? [cell.num ? "num" : "", cell.cls ?? ""].filter(Boolean).join(" ")
                : undefined;
              return (
                <td key={j} className={className || undefined}>
                  {isObject ? cell.value : cell}
                </td>
              );
            })}
          </tr>
        ))}
      </tbody>
    </table>
  );
}
