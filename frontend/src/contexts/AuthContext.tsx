import { createContext, useContext, useEffect, useState, type ReactNode } from "react";
import { auth, getToken, setToken } from "@/api/client";

interface Me {
  user_id: string;
  org_id: string;
  email: string;
  roles: string[];
}

interface AuthState {
  me: Me | null;
  loading: boolean;
  login: (email: string, password: string) => Promise<void>;
  logout: () => Promise<void>;
}

const AuthCtx = createContext<AuthState | undefined>(undefined);

export function AuthProvider({ children }: { children: ReactNode }) {
  const [me, setMe] = useState<Me | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    if (!getToken()) {
      setLoading(false);
      return;
    }
    auth.me()
      .then((m) => setMe(m))
      .catch(() => setToken(null))
      .finally(() => setLoading(false));
  }, []);

  async function login(email: string, password: string) {
    const r = await auth.login(email, password);
    setToken(r.token);
    const m = await auth.me();
    setMe(m);
  }

  async function logout() {
    try { await auth.logout(); } catch { /* ignore */ }
    setToken(null);
    setMe(null);
  }

  return <AuthCtx.Provider value={{ me, loading, login, logout }}>{children}</AuthCtx.Provider>;
}

// eslint-disable-next-line react-refresh/only-export-components
export function useAuth(): AuthState {
  const v = useContext(AuthCtx);
  if (!v) throw new Error("useAuth must be inside AuthProvider");
  return v;
}
