// `constellationctl network-flows backfill` — re-runs the Wave M2 IP-to-workload
// resolver over a window of recent network_flows rows.
//
// The Wave M2 migration (036_pod_ips_and_services.sql) ships an empty
// `pod_ips` and `cluster_services` table; the discoverer populates them on
// its next pass. Existing rows in network_flows whose `src_workload` or
// `dst_workload` is "cluster/<ip>" stay raw until this command rewrites them.
// We intentionally avoid an automatic rewrite at migration time because the
// table is partitioned and a 24h window can be tens of millions of rows.
//
// The command reads DATABASE_URL from --database-url or $DATABASE_URL, the
// same env the API binary reads, and operates on rows where:
//
//   - `at >= NOW() - $hours hours`
//   - `src_workload LIKE 'cluster/%' OR dst_workload LIKE 'cluster/%'`
//
// Rows are batched (default 500) and resolved against well-known IPs first,
// then pod_ips, then cluster_services. Unresolved rows are left as-is.
package main

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/spf13/cobra"
)

// networkFlowsCmd is the parent for `constellationctl network-flows ...`.
func networkFlowsCmd() *cobra.Command {
	c := &cobra.Command{
		Use:   "network-flows",
		Short: "Network-flow maintenance commands (Wave M2)",
	}
	c.AddCommand(networkFlowsBackfillCmd())
	return c
}

func networkFlowsBackfillCmd() *cobra.Command {
	var (
		hours       int
		dbURL       string
		batchSize   int
		dryRun      bool
		clusterOnly string
	)
	cmd := &cobra.Command{
		Use:   "backfill",
		Short: "Re-resolve raw IPs (cluster/<ip>) on recent network_flows rows",
		Long: `Walks network_flows rows whose src_workload or dst_workload is still
"cluster/<ip>" within the given window and rewrites them to the named
workload using the same lookup chain the ingest path applies:

  1. Well-known IPs (loopback / cloud-metadata / CGNAT / multicast / link-local)
  2. pod_ips (-> "<ns>/<deployment>")
  3. cluster_services (-> "<ns>/<service-name>")

Rows with no match are left untouched. The pod_ips and cluster_services
tables must be populated first by the discoverer (one reconcile pass).`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if dbURL == "" {
				dbURL = os.Getenv("DATABASE_URL")
			}
			if dbURL == "" {
				return errors.New("--database-url or $DATABASE_URL required")
			}
			if hours <= 0 || hours > 24*30 {
				return fmt.Errorf("--hours must be 1..720, got %d", hours)
			}
			if batchSize <= 0 {
				batchSize = 500
			}
			ctx, cancel := context.WithTimeout(cmd.Context(), 30*time.Minute)
			defer cancel()
			pool, err := pgxpool.New(ctx, dbURL)
			if err != nil {
				return fmt.Errorf("connect: %w", err)
			}
			defer pool.Close()

			return backfillNetworkFlows(ctx, cmd.OutOrStdout(), pool, hours, batchSize, dryRun, clusterOnly)
		},
	}
	cmd.Flags().IntVar(&hours, "hours", 24, "Hours back to scan (1..720)")
	cmd.Flags().StringVar(&dbURL, "database-url", "", "Postgres URL (else $DATABASE_URL)")
	cmd.Flags().IntVar(&batchSize, "batch", 500, "Rows per batch")
	cmd.Flags().BoolVar(&dryRun, "dry-run", false, "Compute changes, do not write")
	cmd.Flags().StringVar(&clusterOnly, "cluster-id", "", "Restrict to one cluster (UUID)")
	return cmd
}

// backfillNetworkFlows scans network_flows for rows with "cluster/<ip>" labels
// within the window, batch-resolves the IPs against pod_ips / cluster_services
// (per org_id, the unique key on those tables), and UPDATEs the rows in
// place. Returns stats to stdout.
func backfillNetworkFlows(ctx context.Context, w stdoutWriter, pool *pgxpool.Pool, hours, batchSize int, dryRun bool, clusterOnly string) error {
	args := []any{fmt.Sprintf("%d", hours)}
	q := `
SELECT ctid::text, org_id::text, cluster_id::text, src_workload, dst_workload,
       COALESCE(src_addr, ''), COALESCE(dst_addr, ''), at
  FROM network_flows
 WHERE at >= NOW() - ($1::text || ' hours')::interval
   AND (src_workload LIKE 'cluster/%' OR dst_workload LIKE 'cluster/%')`
	if clusterOnly != "" {
		q += fmt.Sprintf(" AND cluster_id = $%d::uuid", len(args)+1)
		args = append(args, clusterOnly)
	}
	q += " ORDER BY at"

	rows, err := pool.Query(ctx, q, args...)
	if err != nil {
		return fmt.Errorf("scan flows: %w", err)
	}
	defer rows.Close()

	type pending struct {
		ctid, orgID, clusterID, src, dst, srcAddr, dstAddr string
		at                                                 time.Time
	}
	var all []pending
	for rows.Next() {
		var p pending
		if err := rows.Scan(&p.ctid, &p.orgID, &p.clusterID, &p.src, &p.dst, &p.srcAddr, &p.dstAddr, &p.at); err != nil {
			return err
		}
		all = append(all, p)
	}
	if err := rows.Err(); err != nil {
		return err
	}
	fmt.Fprintf(w, "scanned %d candidate rows over last %dh\n", len(all), hours)
	if len(all) == 0 {
		return nil
	}

	// Group by org_id so the batched IP lookup uses one pod_ips/cluster_services
	// query per org (typically just one org in single-tenant deployments).
	byOrg := map[string][]int{}
	for i, p := range all {
		byOrg[p.orgID] = append(byOrg[p.orgID], i)
	}

	rewritten := 0
	for orgID, idxs := range byOrg {
		// Collect distinct IPs for this org.
		ipset := map[string]struct{}{}
		for _, i := range idxs {
			p := all[i]
			for _, raw := range []string{
				p.srcAddr, p.dstAddr,
				extractClusterIPCLI(p.src), extractClusterIPCLI(p.dst),
			} {
				if a, ok := normalizeIPCLI(raw); ok {
					ipset[a] = struct{}{}
				}
			}
		}
		if len(ipset) == 0 {
			continue
		}
		ips := make([]string, 0, len(ipset))
		for ip := range ipset {
			ips = append(ips, ip)
		}
		pods, svcs, err := loadResolverMaps(ctx, pool, orgID, ips)
		if err != nil {
			return err
		}

		// For each row, derive the new src/dst workload labels.
		batchOps := make([]batchUpdate, 0, batchSize)
		for _, i := range idxs {
			p := all[i]
			newSrc := resolveLabel(p.src, p.srcAddr, p.src, pods, svcs)
			newDst := resolveLabel(p.dst, p.dstAddr, p.src, pods, svcs)
			if newSrc == p.src && newDst == p.dst {
				continue
			}
			batchOps = append(batchOps, batchUpdate{ctid: p.ctid, at: p.at, src: newSrc, dst: newDst})
			if len(batchOps) >= batchSize {
				if !dryRun {
					if err := applyUpdates(ctx, pool, batchOps); err != nil {
						return err
					}
				}
				rewritten += len(batchOps)
				batchOps = batchOps[:0]
			}
		}
		if len(batchOps) > 0 {
			if !dryRun {
				if err := applyUpdates(ctx, pool, batchOps); err != nil {
					return err
				}
			}
			rewritten += len(batchOps)
		}
	}
	if dryRun {
		fmt.Fprintf(w, "dry-run: would rewrite %d rows\n", rewritten)
	} else {
		fmt.Fprintf(w, "rewrote %d rows\n", rewritten)
	}
	return nil
}

type batchUpdate struct {
	ctid string
	at   time.Time
	src  string
	dst  string
}

// applyUpdates writes one UPDATE per row. We use ctid (PostgreSQL row pointer)
// which is fine within a single transaction-less session for offline backfill
// (the table is partitioned so row pointers are stable within a partition).
// For very large rewrites consider switching to a UPDATE … FROM (VALUES (...))
// pattern, but at the typical 24h scale this is simpler and fast enough.
func applyUpdates(ctx context.Context, pool *pgxpool.Pool, ops []batchUpdate) error {
	b := &pgx.Batch{}
	for _, op := range ops {
		b.Queue(`UPDATE network_flows
                    SET src_workload = $1, dst_workload = $2
                  WHERE ctid::text = $3 AND at = $4`,
			op.src, op.dst, op.ctid, op.at)
	}
	br := pool.SendBatch(ctx, b)
	defer br.Close()
	for range ops {
		if _, err := br.Exec(); err != nil {
			return err
		}
	}
	return nil
}

func loadResolverMaps(ctx context.Context, pool *pgxpool.Pool, orgID string, ips []string) (pods, svcs map[string]string, err error) {
	pods = map[string]string{}
	svcs = map[string]string{}
	rs, err := pool.Query(ctx, `
SELECT host(ip), namespace, COALESCE(deployment, pod_name)
  FROM pod_ips
 WHERE org_id = $1::uuid AND ip = ANY($2::inet[])`, orgID, ips)
	if err != nil {
		return nil, nil, fmt.Errorf("pod_ips: %w", err)
	}
	for rs.Next() {
		var ip, ns, name string
		if err := rs.Scan(&ip, &ns, &name); err == nil {
			if a, ok := normalizeIPCLI(ip); ok {
				pods[a] = ns + "/" + name
			}
		}
	}
	rs.Close()
	rs, err = pool.Query(ctx, `
SELECT host(cluster_ip), namespace, name
  FROM cluster_services
 WHERE org_id = $1::uuid AND cluster_ip = ANY($2::inet[])`, orgID, ips)
	if err != nil {
		return nil, nil, fmt.Errorf("cluster_services: %w", err)
	}
	for rs.Next() {
		var ip, ns, name string
		if err := rs.Scan(&ip, &ns, &name); err == nil {
			if a, ok := normalizeIPCLI(ip); ok {
				svcs[a] = ns + "/" + name
			}
		}
	}
	rs.Close()
	return pods, svcs, nil
}

// resolveLabel mirrors the server-side resolver chain
// (internal/handler/network_flows_ingest.go) for offline backfill. We don't
// share the function to avoid pulling internal/* into the CLI binary.
func resolveLabel(workload, addr, nodeHint string, pods, svcs map[string]string) string {
	cand := addr
	if cand == "" {
		cand = extractClusterIPCLI(workload)
	}
	if cand == "" {
		return workload
	}
	key, ok := normalizeIPCLI(cand)
	if !ok {
		return workload
	}
	if parsed, err := netip.ParseAddr(key); err == nil {
		node := ""
		if strings.HasPrefix(nodeHint, "node/") {
			node = nodeHint[len("node/"):]
		}
		if label, isWellKnown := wellKnownLabelCLI(parsed, node); isWellKnown {
			return label
		}
	}
	if v, ok := pods[key]; ok {
		return v
	}
	if v, ok := svcs[key]; ok {
		return v
	}
	return workload
}

// extractClusterIPCLI returns the IP from a "cluster/<ip>" label or "".
func extractClusterIPCLI(workload string) string {
	if !strings.HasPrefix(workload, "cluster/") {
		return ""
	}
	return workload[len("cluster/"):]
}

func normalizeIPCLI(s string) (string, bool) {
	a, err := netip.ParseAddr(strings.TrimSpace(s))
	if err != nil {
		return "", false
	}
	if a.Is4In6() {
		a = a.Unmap()
	}
	return a.WithZone("").String(), true
}

// wellKnownLabelCLI mirrors handler.lookupWellKnown. Kept as a parallel
// implementation so the CLI binary doesn't have to import internal/handler.
func wellKnownLabelCLI(addr netip.Addr, nodeName string) (string, bool) {
	if !addr.IsValid() {
		return "", false
	}
	if addr.IsLoopback() {
		if nodeName != "" {
			return "node/" + nodeName, true
		}
		return "node-local/loopback", true
	}
	mdns := netip.MustParseAddr("224.0.0.251")
	if addr == mdns {
		return "multicast/mdns", true
	}
	metadata := netip.MustParseAddr("169.254.169.254")
	if addr == metadata {
		return "external/cloud-metadata", true
	}
	if addr.IsMulticast() {
		return "multicast/" + addr.String(), true
	}
	cgnat := netip.MustParsePrefix("100.64.0.0/10")
	if cgnat.Contains(addr) {
		return "external/cgnat-" + addr.String(), true
	}
	if addr.IsLinkLocalUnicast() {
		return "link-local/" + addr.String(), true
	}
	return "", false
}

// stdoutWriter is a tiny interface so backfillNetworkFlows takes io.Writer
// without forcing tests to import io/os.
type stdoutWriter interface {
	Write([]byte) (int, error)
}
