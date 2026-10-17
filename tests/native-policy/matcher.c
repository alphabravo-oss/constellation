// Test-only entry point. All parsing, policy staging, application rules and
// IP/range/default matching below call the actual unchanged vendored objects.
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <netinet/ether.h>
#include "debug.h"
#include "apis.h"
#include "dpi/dpi_module.h"

extern int dp_ctrl_cfg_policy(json_t *message);
extern int dp_ctrl_add_mac(json_t *message);
extern int dp_ctrl_enable_icmp_policy(json_t *message);
extern int _dpi_policy_lookup_by_key(dpi_policy_hdl_t *handle, dpi_rule_key_t *key,
                                    int ingress, dpi_policy_desc_t *description);
extern int dpi_policy_lookup_by_key(dpi_policy_hdl_t *handle, uint32_t source,
                                   uint32_t destination, uint16_t port,
                                   uint16_t protocol, uint32_t application,
                                   int ingress, dpi_policy_desc_t *description,
                                   dpi_packet_t *packet);

extern int dp_ep_match(struct cds_lfht_node *node, const void *key);
extern uint32_t dp_ep_hash(const void *key);

static const char *text_field(json_t *object, const char *field)
{
    return json_string_value(json_object_get(object, field));
}

static int query_matcher(json_t *query, const char *name)
{
    struct ether_addr address;
    const char *mac = text_field(query, "mac");
    const char *source = text_field(query, "sip");
    const char *destination = text_field(query, "dip");
    dpi_rule_key_t key = {0};
    if (!mac || !source || !destination || !ether_aton_r(mac, &address) ||
        inet_pton(AF_INET, source, &key.sip) != 1 ||
        inet_pton(AF_INET, destination, &key.dip) != 1) {
        fprintf(stderr, "invalid native lookup fixture: %s\n", name);
        return -1;
    }
    key.dport = json_integer_value(json_object_get(query, "port"));
    key.proto = json_integer_value(json_object_get(query, "proto"));
    key.app = json_integer_value(json_object_get(query, "app"));
    int ingress = json_is_true(json_object_get(query, "ingress"));
    dpi_policy_desc_t description = {0};
    rcu_read_lock();
    io_mac_t *endpoint = rcu_map_lookup(&g_ep_map, &address);
    if (!endpoint) {
        rcu_read_unlock();
        fprintf(stderr, "lookup has no registered native MAC: %s\n", name);
        return -1;
    }
    dpi_policy_hdl_t *handle = endpoint->ep->policy_hdl;
    // Call the actual native policy wrapper as well as its keyed matcher.
    // No subnet overrides are configured: native's ordinary empty inventory
    // classification applies, with no FQDN/unknown-address fixture substitutes.
    if (json_is_true(json_object_get(query, "packet"))) {
        struct iphdr ip = { .saddr = key.sip, .daddr = key.dip };
        dpi_session_t session = {0};
        dpi_packet_t packet = {
            .pkt = (uint8_t *)&ip, .session = &session, .ep = endpoint->ep,
            .eth_type = ETH_P_IP, .ip_proto = key.proto, .dport = key.dport,
            .flags = ingress ? DPI_PKT_FLAG_INGRESS : 0,
        };
        // This is the full packet policy wrapper, including unknown-address
        // grace. No policy-address or internal-subnet inventory is installed.
        dpi_policy_lookup(&packet, handle, key.app, true, false, &description, 0);
    } else {
        dpi_policy_lookup_by_key(handle, key.sip, key.dip, key.dport, key.proto,
                                 key.app, ingress, &description, NULL);
    }
    rcu_read_unlock();
    if (json_is_true(json_object_get(query, "finite_order")) && description.order == UINT32_MAX) {
        fprintf(stderr, "%s: reviewed default retained implicit native order\n",name);
        return -1;
    }
    int expected_action = json_integer_value(json_object_get(query, "action"));
    uint32_t expected_id = json_integer_value(json_object_get(query, "id"));
    json_t *expected_tmp = json_object_get(query, "tmp_open");
    if (expected_tmp && json_is_true(expected_tmp) !=
        ((description.flags & POLICY_DESC_TMP_OPEN) != 0)) {
        fprintf(stderr, "%s: unexpected native temporary-open flag: %u\n", name, description.flags);
        return -1;
    }
    if (description.action != expected_action || description.id != expected_id) {
        fprintf(stderr, "%s: native action=%u id=%u, expected action=%d id=%u\n",
                name, description.action, description.id, expected_action, expected_id);
        return -1;
    }
    printf("PASS %s action=%u id=%u\n", name, description.action, description.id);
    return 0;
}

static int apply_command(json_t *command, size_t *assertions)
{
    const char *name = text_field(command, "case");
    if (!name) name = "native-control";
    json_t *payload;
    int result;
    if ((payload = json_object_get(command, "lookup"))) {
        (*assertions)++;
        return query_matcher(payload, name);
    }
    if ((payload = json_object_get(command, "ctrl_cfg_policy"))) {
        result = dp_ctrl_cfg_policy(payload);
    } else if ((payload = json_object_get(command, "ctrl_add_mac"))) {
        result = dp_ctrl_add_mac(payload);
    } else if ((payload = json_object_get(command, "ctrl_enable_icmp_policy"))) {
        result = dp_ctrl_enable_icmp_policy(payload);
    } else {
        fprintf(stderr, "unsupported test command: %s\n", name);
        return -1;
    }
    int expected = json_integer_value(json_object_get(command, "expect_ret"));
    if (result != expected) {
        fprintf(stderr, "%s: native parser result=%d expected=%d\n", name, result, expected);
        return -1;
    }
    return 0;
}

int main(void)
{
    // No native daemon threads, sockets, shared memory or capture ports start.
    // These are in-memory endpoint records with the actual RCU implementation.
    g_debug_levels = 0;
    THREAD_ID = 0;
    rcu_register_thread();
    if (!rcu_map_init(&g_ep_map, 16, offsetof(io_mac_t, node), dp_ep_match, dp_ep_hash)) {
        fprintf(stderr, "cannot initialize native endpoint map\n");
        return EXIT_FAILURE;
    }
    if (dpi_policy_init() != 0) {
        fprintf(stderr, "cannot initialize native policy subsystem\n");
        return EXIT_FAILURE;
    }
    timer_wheel_init(&th_timer);
    dpi_unknown_ip_init();
    char *line = NULL;
    size_t capacity = 0, assertions = 0;
    int status = EXIT_SUCCESS;
    while (getline(&line, &capacity, stdin) >= 0) {
        json_error_t error;
        json_t *command = json_loads(line, JSON_REJECT_DUPLICATES, &error);
        if (!command || !json_is_object(command)) {
            fprintf(stderr, "native Jansson parse failed at line %d: %s\n", error.line, error.text);
            json_decref(command);
            status = EXIT_FAILURE;
            break;
        }
        int result = apply_command(command, &assertions);
        json_decref(command);
        if (result != 0) {
            status = EXIT_FAILURE;
            break;
        }
    }
    if (ferror(stdin) || assertions == 0) status = EXIT_FAILURE;
    free(line);
    printf("native matcher assertions=%zu status=%d\n", assertions, status);
    rcu_unregister_thread();
    return status;
}
