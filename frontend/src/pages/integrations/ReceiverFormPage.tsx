import { useEffect, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Link, useNavigate, useParams } from "react-router-dom";
import { toast } from "sonner";
import { ArrowLeft, Check, Copy } from "lucide-react";

import { receivers as receiversApi, type Receiver } from "@/api/client";
import { PageHeader } from "@/components/ui/page";
import { Card } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Field, TextInput, Textarea, Select } from "@/components/ui/form";

/**
 * ReceiverFormPage — /settings/integrations/receivers/new and /:id. A dedicated
 * form page (the Astronomer add/edit-as-a-page pattern, replacing the old create +
 * edit drawers). On CREATE it mints the receiver and reveals its HMAC secret once
 * on-page (like RegisterClusterPage's post-mint view); on EDIT it patches the
 * existing receiver.
 */

const RECEIVER_KINDS = ["slack", "pagerduty", "jira", "servicenow", "webhook", "email"];

export function ReceiverFormPage() {
  const { id } = useParams<{ id: string }>();
  const editing = !!id;
  const navigate = useNavigate();
  const qc = useQueryClient();

  const [name, setName] = useState("");
  const [kind, setKind] = useState("slack");
  const [endpoint, setEndpoint] = useState("");
  const [recipients, setRecipients] = useState("");
  const [rate, setRate] = useState(60);
  const [template, setTemplate] = useState("default");
  // On CREATE, the one-time HMAC secret returned by the API — revealed on-page.
  const [secret, setSecret] = useState<string | null>(null);

  // In edit mode, seed the form from the existing receiver (there is no single-GET;
  // the list endpoint returns them all, so find ours in there).
  const listQ = useQuery({
    queryKey: ["receivers"],
    queryFn: () => receiversApi.list(),
    enabled: editing,
  });
  const existing = editing ? (listQ.data?.receivers ?? []).find((r) => r.id === id) ?? null : null;

  useEffect(() => {
    if (!existing) return;
    setName(existing.name);
    setKind(existing.kind);
    setEndpoint(existing.endpoint ?? "");
    const to = (existing.config?.to as unknown) ?? [];
    setRecipients(Array.isArray(to) ? to.join(", ") : "");
    setRate(existing.rate_per_min);
    setTemplate(existing.template_id || "default");
  }, [existing]);

  const isEmail = kind === "email";
  const toList = recipients.split(",").map((s) => s.trim()).filter(Boolean);
  const canSubmit = name.trim() !== "" && (isEmail ? toList.length > 0 : endpoint.trim() !== "");

  const buildBody = (): Partial<Receiver> => {
    const body: Partial<Receiver> = { name: name.trim(), kind, supported_events: [], rate_per_min: rate };
    if (isEmail) {
      // Email delivery derives its endpoint from the recipients — send only config.to.
      body.config = { to: toList };
    } else {
      body.endpoint = endpoint.trim();
    }
    return body;
  };

  const create = useMutation({
    mutationFn: () => receiversApi.create(buildBody()),
    onSuccess: (data) => {
      setSecret(data.secret_key);
      void qc.invalidateQueries({ queryKey: ["receivers"] });
      toast.success("Receiver created");
    },
    onError: () => toast.error("Failed to create receiver"),
  });

  const update = useMutation({
    mutationFn: () => receiversApi.patch(id!, { ...buildBody(), template_id: template }),
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: ["receivers"] });
      toast.success("Receiver updated");
      navigate("/settings/integrations");
    },
    onError: () => toast.error("Failed to update receiver"),
  });

  const submit = () => {
    if (!canSubmit) return;
    if (editing) update.mutate();
    else create.mutate();
  };

  const backLink = (
    <Link to="/settings/integrations" className="inline-flex items-center gap-1 hover:text-foreground">
      <ArrowLeft className="h-3.5 w-3.5" /> Integrations
    </Link>
  );

  // Post-create result view: reveal the HMAC secret once, then return to the list.
  if (secret) {
    return (
      <div className="space-y-6">
        <PageHeader
          title="Receiver created"
          description="Save the HMAC secret below — Constellation cannot show it again."
          backLink={backLink}
        />
        <Card title="New HMAC secret (one-time reveal)">
          <div className="space-y-3 text-xs">
            <div className="break-all rounded-md border border-[color:var(--color-status-warning)]/50 bg-[color:var(--color-status-warning)]/10 p-3 font-mono" data-testid="receiver-secret-key">
              {secret}
            </div>
            <p className="text-[11px] text-muted-foreground">
              Save this somewhere safe — Constellation cannot show it again. Receivers must use this exact value to
              verify the X-Constellation-Signature header on outbound deliveries.
            </p>
            <div className="flex items-center gap-2">
              <CopyButton text={secret} />
              <Button variant="ghost" size="sm" onClick={() => navigate("/settings/integrations")}>Done</Button>
            </div>
          </div>
        </Card>
      </div>
    );
  }

  const pending = create.isPending || update.isPending;

  return (
    <div className="space-y-6">
      <PageHeader
        title={editing ? "Edit receiver" : "Add receiver"}
        description="A destination alerts are delivered to."
        backLink={backLink}
      />

      <Card title="Receiver details">
        <form
          className="space-y-5"
          data-testid="create-receiver-drawer"
          onSubmit={(e) => { e.preventDefault(); submit(); }}
        >
          <Field label="Name">
            <TextInput
              value={name}
              onChange={(e) => setName(e.target.value)}
              placeholder="e.g. platform-oncall"
              data-testid="create-receiver-name"
              className="max-w-md"
            />
          </Field>

          <Field label="Kind" hint="What sort of destination this is.">
            <Select value={kind} onChange={(e) => setKind(e.target.value)} data-testid="create-receiver-kind" className="max-w-md">
              {RECEIVER_KINDS.map((k) => (
                <option key={k} value={k}>{k}</option>
              ))}
            </Select>
          </Field>

          {isEmail ? (
            <Field
              label="Recipients"
              hint="Comma-separated email addresses. Email delivery requires the SMTP server on the Integrations page to be configured."
            >
              <Textarea
                value={recipients}
                onChange={(e) => setRecipients(e.target.value)}
                placeholder="alice@example.com, bob@example.com"
                data-testid="create-receiver-recipients"
              />
            </Field>
          ) : (
            <Field label="Endpoint URL" hint="The webhook / API URL alerts are POSTed to.">
              <TextInput
                value={endpoint}
                onChange={(e) => setEndpoint(e.target.value)}
                placeholder="https://hooks.example.com/…"
                data-testid="create-receiver-endpoint"
                className="max-w-md"
              />
            </Field>
          )}

          <Field label="Rate per minute" hint="Maximum deliveries per minute before this destination is throttled.">
            <TextInput
              type="number"
              min={1}
              value={rate}
              onChange={(e) => {
                const n = Number.parseInt(e.target.value, 10);
                if (!Number.isNaN(n)) setRate(n);
              }}
              className="w-32"
            />
          </Field>

          {editing && (
            <Field label="Template" hint="Which message layout this destination renders alerts with.">
              <Select value={template} onChange={(e) => setTemplate(e.target.value)} className="max-w-xs">
                <option value="default">default</option>
                <option value="compact">compact</option>
                <option value="verbose">verbose</option>
              </Select>
            </Field>
          )}

          <div className="flex items-center gap-3">
            <Button
              type="submit"
              variant="primary"
              size="lg"
              disabled={!canSubmit || pending}
              data-testid="create-receiver-save"
            >
              {pending ? (editing ? "Saving…" : "Creating…") : (editing ? "Save receiver" : "Create receiver")}
            </Button>
            <Button type="button" variant="ghost" size="lg" onClick={() => navigate("/settings/integrations")}>Cancel</Button>
          </div>
        </form>
      </Card>
    </div>
  );
}

function CopyButton({ text }: { text: string }) {
  const [copied, setCopied] = useState(false);
  return (
    <Button
      variant="outline"
      size="sm"
      onClick={() => {
        void navigator.clipboard.writeText(text);
        setCopied(true);
        setTimeout(() => setCopied(false), 1500);
      }}
    >
      {copied ? <Check className="h-3.5 w-3.5 text-status-success" /> : <Copy className="h-3.5 w-3.5" />}
      {copied ? "Copied" : "Copy"}
    </Button>
  );
}
