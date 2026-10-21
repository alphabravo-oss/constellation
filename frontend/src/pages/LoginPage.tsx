import { useState } from "react";
import { useNavigate } from "@tanstack/react-router";
import { useQuery } from "@tanstack/react-query";
import { useRouteSearchParams } from "@/lib/route-search";
import { toast } from "sonner";
import { ArrowRight, Eye, EyeOff } from "lucide-react";
import { ConstellationMark } from "@/lib/product-config";
import { Button, Form } from "@/ui";

import { useAuth } from "@/contexts/AuthContext";
import { auth as authApi } from "@/api/client";
import { loginReturnPath } from "@/lib/login-return";

function BrandMark({ compact = false }: { compact?: boolean }) {
  return (
    <div className="flex items-center gap-3">
      <ConstellationMark size="lg" />
      <div className="flex flex-col leading-tight">
        <span className={`${compact ? "text-foreground" : "text-white"} text-xl font-semibold tracking-tight`}>Constellation</span>
        <span className={`${compact ? "text-muted-foreground" : "text-zinc-400"} text-micro`}>by AlphaBravo</span>
      </div>
    </div>
  );
}

export function LoginPage() {
  const { login } = useAuth();
  const navigate = useNavigate();
  const [searchParams] = useRouteSearchParams();
  const [email, setEmail] = useState("");
  const [totp, setTOTP] = useState("");
  const [password, setPassword] = useState("");
  const [showPassword, setShowPassword] = useState(false);
  const [submitting, setSubmitting] = useState(false);
  const { data: providers } = useQuery({
    queryKey: ["auth", "providers"],
    queryFn: authApi.providers,
    retry: false,
  });
  const [emergency, setEmergency] = useState(false);
  const hasSSO = providers?.oidc;

  async function onSubmit(e: React.FormEvent) {
    e.preventDefault();
    setSubmitting(true);
    try {
      await login(email, password, totp, emergency);
      const returnTo = searchParams.get("returnTo");
      const nextPath = loginReturnPath(returnTo);
      navigate({ href: nextPath, replace: true });
    } catch (err) {
      toast.error("Sign-in failed. Check your credentials or try again after the cooldown.");
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
      toast.error("Unable to start SSO. Please try again.");
    }
  }

  return (
    <div className="flex min-h-screen bg-background">
      <aside className="dark relative hidden w-1/2 overflow-hidden bg-[hsl(200_30%_4%)] p-12 text-white lg:flex lg:flex-col lg:justify-between" data-testid="login-hero">
        <div aria-hidden className="star-field absolute inset-0 opacity-60" />
        <div aria-hidden className="absolute left-1/2 top-1/3 h-96 w-96 -translate-x-1/2 rounded-full bg-brand/15 blur-[120px]" />
        <div aria-hidden className="absolute bottom-1/4 left-1/4 h-64 w-64 rounded-full bg-brand-to/10 blur-[100px]" />

        <div className="relative">
          <BrandMark />
        </div>

        <div className="relative max-w-xl space-y-4">
          <h1 className="text-4xl font-bold leading-tight text-white">
            Kubernetes security
            <br />
            <span className="text-gradient">control plane</span>
          </h1>
          <p className="max-w-md text-lg leading-relaxed text-zinc-400">
            Vulnerability intelligence, runtime defense, network policy and compliance evidence in one workflow.
          </p>
        </div>

        <div className="relative space-y-4">
          <div className="flex flex-wrap items-center gap-8 text-sm text-zinc-400">
            <span className="flex items-center gap-2"><span aria-hidden className="h-2 w-2 rounded-full bg-brand" />Runtime defense</span>
            <span className="flex items-center gap-2"><span aria-hidden className="h-2 w-2 rounded-full bg-brand-to" />Vulnerability intelligence</span>
            <span className="flex items-center gap-2"><span aria-hidden className="h-2 w-2 rounded-full bg-zinc-400" />Network controls</span>
          </div>
          <p className="text-xs text-zinc-500">
            Developed by{" "}
            <a href="https://alphabravo.io" target="_blank" rel="noopener noreferrer" className="text-zinc-400 transition-colors hover:text-zinc-200">
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
            <h2 className="text-2xl font-semibold tracking-tight text-foreground">Sign in to Constellation</h2>
            <p className="text-sm text-muted-foreground">Use your local account or your organization’s single sign-on.</p>
          </div>

          {hasSSO && <Button type="button" intent="primary" className="w-full" onClick={onOIDC}>Continue with SSO</Button>}
          {providers?.break_glass && <Button type="button" intent="ghost" className="w-full" onClick={() => setEmergency(!emergency)}>{emergency ? "Use normal sign-in" : "Emergency access"}</Button>}
          {(providers?.local || (emergency && providers?.break_glass)) && <>
          {emergency && <p className="text-sm text-muted-foreground">Recovery administrator. Every use is audited and alerts your operators.</p>}
          <form onSubmit={onSubmit} className="space-y-4">
            {!emergency && <Form.Field label="Email" id="login-email" required>{ids => <Form.Input {...ids} type="email" autoComplete="username" required value={email} onChange={e=>setEmail(e.target.value)} />}</Form.Field>}
            <div className="space-y-1.5">
              <label htmlFor="login-password" className="text-sm font-medium text-foreground">Password</label>
              <div className="relative">
                <Form.Input
                  id="login-password"
                  type={showPassword ? "text" : "password"}
                  className="h-10 pr-10"
                  required
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  autoComplete="current-password"
                  placeholder="Enter your password"
                />
                <button
                  type="button"
                  onClick={() => setShowPassword((value) => !value)}
                  className="absolute right-1 top-1/2 inline-flex h-8 w-8 -translate-y-1/2 items-center justify-center rounded-sm text-muted-foreground transition-colors hover:bg-accent hover:text-foreground focus-visible:outline-hidden focus-visible:ring-2 focus-visible:ring-ring"
                  aria-label={showPassword ? "Hide password" : "Show password"}
                >
                  {showPassword ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
                </button>
              </div>
            </div>

            <div className="space-y-1.5">
              <label htmlFor="login-totp" className="text-sm font-medium">Authenticator code</label>
              <Form.Input id="login-totp" value={totp} onChange={e=>setTOTP(e.target.value)} inputMode="numeric" autoComplete="one-time-code" pattern="[0-9]{6}" required={emergency || providers?.totp_policy === "everyone"} />
            </div>
            <Button type="submit" intent="primary" disabled={submitting} className="h-10 w-full">
              {submitting ? "Signing in…" : "Sign in"}
              <ArrowRight className="h-4 w-4" />
            </Button>
          </form></>}

          <p className="text-center text-xs text-muted-foreground">
            By signing in, you agree to the Constellation terms of service and privacy policy.
          </p>
        </div>
      </main>
    </div>
  );
}
