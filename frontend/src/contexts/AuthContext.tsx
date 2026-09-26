import { createContext, useContext, useEffect, useRef, useState, type ReactNode } from "react";
import { useQueryClient } from "@tanstack/react-query";
import { auth } from "@/api/client";

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
  const queryClient = useQueryClient();
  const identityChannel = useRef<BroadcastChannel | null>(null);
  const [me, setMe] = useState<Me | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    auth.me()
      .then((m) => setMe(m))
      .catch(() => setMe(null))
      .finally(() => setLoading(false));
  }, []);

  useEffect(() => {
    if (typeof BroadcastChannel === "undefined") return;
    const channel = new BroadcastChannel("constellation-identity");
    identityChannel.current = channel;
    channel.onmessage = () => {
      queryClient.clear();
      window.location.reload();
    };
    return () => {
      identityChannel.current = null;
      channel.close();
    };
  }, [queryClient]);

  function notifyIdentityChange() {
    identityChannel.current?.postMessage("changed");
  }

  async function login(email: string, password: string) {
    await auth.login(email, password);
    await queryClient.cancelQueries();
    queryClient.clear();
    const m = await auth.me();
    setMe(m);
    notifyIdentityChange();
  }

  async function logout() {
    await auth.logout();
    await queryClient.cancelQueries();
    queryClient.clear();
    setMe(null);
    notifyIdentityChange();
  }

  return <AuthCtx.Provider value={{ me, loading, login, logout }}>{children}</AuthCtx.Provider>;
}

// eslint-disable-next-line react-refresh/only-export-components
export function useAuth(): AuthState {
  const v = useContext(AuthCtx);
  if (!v) throw new Error("useAuth must be inside AuthProvider");
  return v;
}
