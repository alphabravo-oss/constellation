import { createContext, useContext, type ReactNode } from "react";

type TableIdentity = { org_id: string; user_id: string } | null;
const TablePreferencesContext = createContext<TableIdentity>(null);

export function TablePreferencesProvider({ identity, children }: { identity: TableIdentity; children: ReactNode }) {
  return <TablePreferencesContext.Provider value={identity}>{children}</TablePreferencesContext.Provider>;
}

// eslint-disable-next-line react-refresh/only-export-components
export function useTablePreferencesIdentity() {
  return useContext(TablePreferencesContext);
}
