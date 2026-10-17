// Test-only entry point: the reporter, comparator, map and clock implementation
// are the actual native objects. Only copied static-symbol visibility changes.
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <arpa/inet.h>
#include "debug.h"
#include "apis.h"
#include "main.h"

typedef struct { struct cds_lfht_node node; DPMsgConnect conn; } test_node_t;
typedef struct {
    uint32_t pol_id, client, server;
    uint16_t port, application;
    uint8_t ipproto;
    bool ingress;
} test_key_t;
extern int conn4_match(struct cds_lfht_node *, const void *);
extern uint32_t conn4_hash(const void *);
extern int dp_ctrl_connect_report(DPMsgSession *, DPMonitorMetric *, int, int);
extern void dp_rate_limiter_reset(dp_rate_limter_t *, uint16_t, uint16_t);
extern time_t g_start_time;
extern uint32_t g_seconds;
static unsigned assertions;
#define REQUIRE(expr, name) do { assertions++; if (!(expr)) { \
    fprintf(stderr, "FAIL %s at line %d\n", name, __LINE__); exit(1); } } while (0)

static DPMsgSession session(void)
{
    DPMsgSession s = {0};
    s.EtherType = ETH_P_IP;
    s.IPProto = IPPROTO_TCP;
    s.Flags = DPSESS_FLAG_INGRESS;
    s.Application = 1001;
    s.PolicyId = 11;
    s.PolicyAction = DP_POLICY_ACTION_ALLOW;
    s.ServerPort = 18080;
    s.ClientPort = 40001;
    s.ClientBytes = 100;
    s.ServerBytes = 20;
    REQUIRE(inet_pton(AF_INET, "10.42.0.2", s.ClientIP) == 1, "client fixture");
    REQUIRE(inet_pton(AF_INET, "10.42.0.3", s.ServerIP) == 1, "server fixture");
    s.EPMAC[0] = 2; s.EPMAC[5] = 1;
    return s;
}

static void reset(void)
{
    dp_thread_data_t *t = &g_dp_thread_data[0];
    memset(t, 0, sizeof(*t));
    g_start_time = 100; g_seconds = 0;
    for (unsigned i = 0; i < 2; i++) {
        REQUIRE(rcu_map_init(&t->conn4_map[i], 16, offsetof(test_node_t, node),
                            conn4_match, conn4_hash) != NULL, "actual map initialize");
    }
    dp_rate_limiter_reset(&t->conn4_rl, CONNECT_RL_DUR, CONNECT_RL_CNT);
}

static void cleanup(void)
{
    dp_thread_data_t *t = &g_dp_thread_data[0];
    for (unsigned i = 0; i < 2; i++) {
        rcu_map_t *m = &t->conn4_map[i];
        struct cds_lfht_iter it;
        struct cds_lfht_node *node;
        struct cds_lfht_node *retired[32];
        unsigned retired_count = 0;
        rcu_read_lock();
        cds_lfht_for_each(m->map, &it, node) {
            if (retired_count == 32) {
                fputs("unexpected fixture map size\n", stderr);
                exit(1);
            }
            REQUIRE(rcu_map_del(m, node) == 0, "remove test-owned map entry");
            retired[retired_count++] = node;
        }
        rcu_read_unlock();
        synchronize_rcu();
        for (unsigned j = 0; j < retired_count; j++) free(retired[j]);
        REQUIRE(rcu_map_destroy(m) == 0, "destroy test-owned map");
    }
}

static void report(DPMsgSession *s, DPMonitorMetric *m, int sessions, int violates)
{
    rcu_read_lock();
    int result = dp_ctrl_connect_report(s, m, sessions, violates);
    rcu_read_unlock();
    REQUIRE(result == sizeof(*s), "actual report accepted IPv4");
}

static DPMsgConnect lookup(DPMsgSession *s)
{
    test_key_t key = {0};
    memcpy(&key.client, s->ClientIP, 4); memcpy(&key.server, s->ServerIP, 4);
    key.pol_id = s->PolicyId; key.port = s->ServerPort;
    key.application = s->Application; key.ipproto = s->IPProto;
    key.ingress = (s->Flags & DPSESS_FLAG_INGRESS) != 0;
    dp_thread_data_t *t = &g_dp_thread_data[0];
    rcu_read_lock();
    test_node_t *n = rcu_map_lookup(&t->conn4_map[t->conn4_map_cur], &key);
    REQUIRE(n != NULL, "actual comparator finds exact application");
    DPMsgConnect result = n->conn;
    rcu_read_unlock();
    return result;
}

static void folding(void)
{
    reset();
    DPMsgSession s = session();
    DPMonitorMetric m = {.EpSessCurIn = 1, .EpSessIn12 = 2, .EpByteIn12 = 3};
    report(&s, &m, 1, 0);
    g_seconds = 5;
    s.ClientPort++; // Existing aggregate intentionally ignores TCP client port.
    s.PolicyAction = DP_POLICY_ACTION_DENY;
    s.Severity = 3; s.ThreatID = 77;
    m.EpSessCurIn = 4; m.EpSessIn12 = 5; m.EpByteIn12 = 6;
    report(&s, &m, 1, 1);
    unsigned buckets = g_dp_thread_data[0].conn4_map_cnt[0];
    if (buckets != 1) fprintf(stderr, "identical HTTP1001 expected buckets=1 actual=%u\n", buckets);
    REQUIRE(buckets == 1, "same application folds into one bucket");
    DPMsgConnect c = lookup(&s);
    REQUIRE(c.Application == 1001 && c.Sessions == 2 && c.Violates == 1 && c.Bytes == 240,
            "sessions violations and bytes fold");
    REQUIRE(c.FirstSeenAt == 100 && c.LastSeenAt == 105 && c.PolicyAction == DP_POLICY_ACTION_DENY,
            "latest action preserves original first seen");
    REQUIRE(c.ClientPort == 0, "ordinary TCP aggregate does not invent client port");
    REQUIRE(c.EpSessCurIn == 4 && c.EpSessIn12 == 5 && c.EpByteIn12 == 6,
            "latest monitor metrics retained");
    REQUIRE(c.ThreatID == 77 && c.Severity == 3, "highest severity retained");
    s.Idle = 15; s.PolicyAction = DP_POLICY_ACTION_ALLOW; s.Severity = 1;
    report(&s, NULL, 0, 0);
    c = lookup(&s);
    REQUIRE(c.FirstSeenAt == 100 && c.LastSeenAt == 105 && c.PolicyAction == DP_POLICY_ACTION_DENY,
            "older report cannot replace latest action/time");
    REQUIRE(c.Sessions == 2 && c.Bytes == 360 && c.Severity == 3 && c.ThreatID == 77,
            "older report adds only its existing aggregate contributions");
    cleanup();
    puts("PASS identical application folding and native aggregate semantics");
}

static void applications(void)
{
    reset();
    DPMsgSession s = session();
    unsigned apps[] = {1001, 1002, 0};
    for (unsigned i = 0; i < 3; i++) {
        s.Application = apps[i];
        report(&s, NULL, 1, 0); report(&s, NULL, 1, 0);
        DPMsgConnect c = lookup(&s);
        REQUIRE(c.Application == apps[i] && c.Sessions == 2, "application-specific bucket");
    }
    REQUIRE(g_dp_thread_data[0].conn4_map_cnt[0] == 3, "distinct and unknown applications stay separate");
    cleanup();
    puts("PASS different and unknown applications separated");
}

static void dimensions(void)
{
    reset();
    DPMsgSession original = session();
    for (unsigned i = 0; i < 7; i++) {
        DPMsgSession s = original;
        switch (i) {
        case 1: s.PolicyId++; break;
        case 2: s.IPProto = IPPROTO_UDP; break;
        case 3: s.Flags = 0; break;
        case 4: s.ServerPort++; break;
        case 5: s.ClientIP[3]++; break;
        case 6: s.ServerIP[3]++; break;
        }
        report(&s, NULL, 1, 0); report(&s, NULL, 1, 0);
        DPMsgConnect c = lookup(&s);
        REQUIRE(c.Sessions == 2 && c.PolicyId == s.PolicyId && c.ServerPort == s.ServerPort &&
                c.IPProto == s.IPProto, "existing tuple identity separates retained buckets");
    }
    REQUIRE(g_dp_thread_data[0].conn4_map_cnt[0] == 7, "all existing comparator dimensions preserved");
    cleanup();
    puts("PASS policy protocol direction port and IP identity preserved");
}

static void map_swap(void)
{
    reset();
    DPMsgSession s = session();
    report(&s, NULL, 1, 0);
    g_dp_thread_data[0].conn4_map_cur = 1;
    g_seconds = 7;
    report(&s, NULL, 1, 0);
    DPMsgConnect c = lookup(&s);
    REQUIRE(c.FirstSeenAt == 107 && c.Sessions == 1, "new batch is not cumulative old map state");
    REQUIRE(g_dp_thread_data[0].conn4_map_cnt[0] == 1 && g_dp_thread_data[0].conn4_map_cnt[1] == 1,
            "report follows actual selected map");
    cleanup();
    puts("PASS independent selected map/batch identity");
}

int main(void)
{
    g_debug_levels = 0; THREAD_ID = 0;
    rcu_register_thread();
    folding(); applications(); dimensions(); map_swap();
    rcu_unregister_thread();
    printf("PASS %u actual dp_ctrl_connect_report assertions\n", assertions);
    return 0;
}
