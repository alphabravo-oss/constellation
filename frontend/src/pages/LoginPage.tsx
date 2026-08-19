import { useState } from "react";
import { useNavigate, useSearchParams } from "react-router-dom";
import { toast } from "sonner";
import { ArrowRight, Database, Eye, EyeOff, Network, ShieldCheck } from "lucide-react";

import { useAuth } from "@/contexts/AuthContext";
import { auth as authApi } from "@/api/client";

function BrandMark({ compact = false }: { compact?: boolean }) {
  return (
    <div className="flex items-center gap-3">
      <img
        src="/constellation-mark.svg?v=2"
        alt=""
        aria-hidden="true"
        className={`${compact ? "h-10 w-10" : "h-11 w-11"} shrink-0`}
      />
      <div className="flex flex-col leading-tight">
        <span className={`${compact ? "text-xl" : "text-2xl"} font-semibold text-white`}>Constellation</span>
        <span className="text-[11px] text-zinc-500">by AlphaBravo</span>
      </div>
    </div>
  );
}

export function LoginPage() {
  const { login } = useAuth();
  const navigate = useNavigate();
  const [searchParams] = useSearchParams();
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [showPassword, setShowPassword] = useState(false);
  const [submitting, setSubmitting] = useState(false);

  async function onSubmit(e: React.FormEvent) {
    e.preventDefault();
    setSubmitting(true);
    try {
      await login(email, password);
      const returnTo = searchParams.get("returnTo");
      const nextPath = returnTo?.startsWith("/") && !returnTo.startsWith("//") ? returnTo : "/clusters";
      navigate(nextPath, { replace: true });
    } catch (err) {
      toast.error("Login failed");
      console.error(err);
    } finally {
      setSubmitting(false);
    }
  }

  async function onOIDC() {
    try {
      const r = await authApi.oidcStart();
      window.location.href = r.authorize_url;
    } catch {
      toast.error("OIDC not configured for this deployment");
    }
  }

  return (
    <div className="flex min-h-screen bg-background">
      <aside className="relative hidden w-1/2 overflow-hidden bg-zinc-950 p-12 text-white lg:flex lg:flex-col lg:justify-between">
        <div
          className="absolute inset-0 opacity-[0.06]"
          style={{
            backgroundImage:
              "linear-gradient(rgba(255,255,255,0.65) 1px, transparent 1px), linear-gradient(90deg, rgba(255,255,255,0.65) 1px, transparent 1px)",
            backgroundSize: "40px 40px",
          }}
        />
        <div className="absolute inset-y-0 right-0 w-px bg-white/10" />

        <div className="relative">
          <BrandMark />
        </div>

        <div className="relative max-w-xl space-y-5">
          <h1 className="text-4xl font-bold leading-tight text-white">
            Kubernetes Security
            <br />
            <span className="text-primary">Control Plane</span>
          </h1>
          <p className="max-w-md text-lg leading-relaxed text-zinc-400">
            Vulnerability intelligence, runtime defense, network policy automation, and compliance evidence from one operator workflow.
          </p>
        </div>

        <div className="relative space-y-5">
          <div className="grid max-w-2xl grid-cols-3 gap-4 text-sm text-zinc-400">
            <div className="flex items-center gap-2">
              <ShieldCheck className="h-4 w-4 text-status-success" />
              Runtime defense
            </div>
            <div className="flex items-center gap-2">
              <Database className="h-4 w-4 text-status-info" />
              VulnDB aligned
            </div>
            <div className="flex items-center gap-2">
              <Network className="h-4 w-4 text-primary" />
              Network controls
            </div>
          </div>
          <p className="text-xs text-zinc-600">
            Developed by{" "}
            <a href="https://alphabravo.io" target="_blank" rel="noopener noreferrer" className="text-zinc-500 transition-colors hover:text-zinc-300">
              AlphaBravo
            </a>
          </p>
        </div>
      </aside>

      <main className="flex flex-1 items-center justify-center p-6 sm:p-8">
        <div className="w-full max-w-sm space-y-8">
          <div className="flex justify-center lg:hidden">
            <BrandMark compact />
          </div>

          <div className="space-y-2 text-center lg:text-left">
            <h2 className="text-2xl font-semibold text-foreground">Sign in to Constellation</h2>
            <p className="text-sm text-muted-foreground">Enter your credentials or use SSO to continue.</p>
          </div>

          <button
            type="button"
            onClick={onOIDC}
            className="inline-flex h-10 w-full items-center justify-center gap-2 rounded-lg border border-border bg-background px-4 text-sm font-medium text-foreground transition-colors hover:bg-accent"
          >
            Continue with SSO
          </button>

          <div className="relative">
            <div className="absolute inset-0 flex items-center">
              <div className="w-full border-t border-border" />
            </div>
            <div className="relative flex justify-center text-xs">
              <span className="bg-background px-3 text-muted-foreground">continue with password</span>
            </div>
          </div>

          <form onSubmit={onSubmit} className="space-y-4">
            <div className="space-y-1.5">
              <label htmlFor="login-email" className="text-sm font-medium text-foreground">Email</label>
              <input
                id="login-email"
                type="email"
                className="h-10 w-full rounded-lg border border-input bg-background px-3 text-sm text-foreground transition-colors placeholder:text-muted-foreground focus:border-transparent focus:outline-none focus:ring-2 focus:ring-ring"
                required
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                autoFocus
                autoComplete="username"
                placeholder="you@example.com"
              />
            </div>

            <div className="space-y-1.5">
              <label htmlFor="login-password" className="text-sm font-medium text-foreground">Password</label>
              <div className="relative">
                <input
                  id="login-password"
                  type={showPassword ? "text" : "password"}
                  className="h-10 w-full rounded-lg border border-input bg-background px-3 pr-10 text-sm text-foreground transition-colors placeholder:text-muted-foreground focus:border-transparent focus:outline-none focus:ring-2 focus:ring-ring"
                  required
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  autoComplete="current-password"
                  placeholder="Enter your password"
                />
                <button
                  type="button"
                  onClick={() => setShowPassword((value) => !value)}
                  className="absolute right-3 top-1/2 -translate-y-1/2 text-muted-foreground transition-colors hover:text-foreground"
                  aria-label={showPassword ? "Hide password" : "Show password"}
                >
                  {showPassword ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
                </button>
              </div>
            </div>

            <button
              type="submit"
              disabled={submitting}
              className="inline-flex h-10 w-full items-center justify-center gap-2 rounded-lg bg-primary px-4 text-sm font-medium text-primary-foreground transition-opacity hover:opacity-90 disabled:opacity-50"
            >
              {submitting ? "Signing in..." : "Sign in"}
              <ArrowRight className="h-4 w-4" />
            </button>
          </form>

          <p className="text-center text-xs text-muted-foreground">
            By signing in, you agree to the Constellation terms of service and privacy policy.
          </p>
        </div>
      </main>
    </div>
  );
}
