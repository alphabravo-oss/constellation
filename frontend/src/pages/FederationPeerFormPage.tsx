import { useState } from "react";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { Link, useNavigate } from "react-router-dom";

import { federation } from "@/api/client";
import { PageHeader } from "@/components/ui/page";
import { Card } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Field, TextInput } from "@/components/ui/form";
import { ArrowLeft } from "lucide-react";

/**
 * FederationPeerFormPage — /federation/new. A dedicated form page (the Astronomer
 * add/edit-as-a-page pattern, replacing the old "Join a federation" drawer). Joins
 * an existing federation as a joint cluster, which then receives policies and groups
 * from the named master. Navigates back to /federation on success.
 */
export function FederationPeerFormPage() {
  const navigate = useNavigate();
  const qc = useQueryClient();
  const [masterID, setMasterID] = useState("");
  const [clusterName, setClusterName] = useState("");

  const transit = useMutation({
    mutationFn: () => federation.transition("join", masterID, clusterName),
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: ["fed-state"] });
      navigate("/federation");
    },
  });

  return (
    <div className="space-y-6">
      <PageHeader
        title="Join a federation"
        description="Join an existing federation as a joint cluster. It will receive policies and groups from the named master."
        backLink={<Link to="/federation" className="inline-flex items-center gap-1 hover:text-foreground"><ArrowLeft className="h-3.5 w-3.5" /> Federation</Link>}
      />

      <Card title="Federation details" description="Point this cluster at the master to join as a joint member.">
        <form
          className="space-y-5"
          onSubmit={(e) => {
            e.preventDefault();
            transit.mutate();
          }}
        >
          <Field label="Master id" required>
            <TextInput
              autoFocus
              placeholder="master id"
              value={masterID}
              onChange={(e) => setMasterID(e.target.value)}
              required
              className="max-w-md"
            />
          </Field>
          <Field label="This cluster name">
            <TextInput
              placeholder="this cluster name"
              value={clusterName}
              onChange={(e) => setClusterName(e.target.value)}
              className="max-w-md"
            />
          </Field>
          <div className="flex items-center gap-3">
            <Button type="submit" variant="primary" size="lg" disabled={!masterID || transit.isPending}>
              {transit.isPending ? "Joining…" : "Join federation"}
            </Button>
            <Button type="button" variant="ghost" size="lg" onClick={() => navigate("/federation")}>Cancel</Button>
          </div>
        </form>
      </Card>
    </div>
  );
}
