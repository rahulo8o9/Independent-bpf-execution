/* eBPF example program:
 * - creates arraymap in kernel with key 4 bytes and value 8 bytes
 *
 * - loads eBPF program:
 *   r0 = skb->data[ETH_HLEN + offsetof(struct iphdr, protocol)];
 *   *(u32*)(fp - 4) = r0;
 *   // assuming packet is IPv4, lookup ip->proto in a map
 *   value = bpf_map_lookup_elem(map_fd, fp - 4);
 *   if (value)
 *        (*(u64*)value) += 1;
 *
 * - attaches this program to loopback interface "lo" raw socket
 *
 * - every second user space reads map[tcp], map[udp], map[icmp] to see
 *   how many packets of given protocol were seen on "lo"
 */
#include <stdio.h>
#include <unistd.h>
#include <assert.h>
#include <linux/bpf.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <stddef.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include "bpf_insn.h"
#include "sock_example.h"

char bpf_log_buf[BPF_LOG_BUF_SIZE];

static int test_sock(void)
{
	int sock = -1, map_fd, prog_fd, i, key;
	long long value = 0, tcp_cnt, udp_cnt, icmp_cnt;

	map_fd = bpf_map_create(BPF_MAP_TYPE_ARRAY, "test_map", sizeof(key), sizeof(value),
				256, NULL);
	if (map_fd < 0) {
		printf("failed to create map '%s'\n", strerror(errno));
		goto cleanup;
	}
	struct bpf_insn prog[] = {
		#include "Input.txt"
	};
	size_t insns_cnt = sizeof(prog) / sizeof(struct bpf_insn);

	LIBBPF_OPTS(bpf_prog_load_opts, load_opts,
		.log_buf = bpf_log_buf,
		.log_size = BPF_LOG_BUF_SIZE,
		.log_level = 2,
	);
	prog_fd = bpf_prog_load(BPF_PROG_TYPE_SOCKET_FILTER, "test_prog", "GPL",
				 prog, insns_cnt, &load_opts);
	printf("--- VERIFIER LOG ---\n%s\n--- END LOG ---\n", bpf_log_buf);
	if (prog_fd < 0) {
		printf("failed to load prog '%s'\n", strerror(errno));
		goto cleanup;
	}

	sock = open_raw_sock("lo");

	if (setsockopt(sock, SOL_SOCKET, SO_ATTACH_BPF, &prog_fd,
		       sizeof(prog_fd)) < 0) {
		printf("setsockopt %s\n", strerror(errno));
		goto cleanup;
	}

	for (i = 0; i < 10; i++) {
		key = IPPROTO_TCP;
		assert(bpf_map_lookup_elem(map_fd, &key, &tcp_cnt) == 0);

		key = IPPROTO_UDP;
		assert(bpf_map_lookup_elem(map_fd, &key, &udp_cnt) == 0);

		key = IPPROTO_ICMP;
		assert(bpf_map_lookup_elem(map_fd, &key, &icmp_cnt) == 0);

		printf("TCP %lld UDP %lld ICMP %lld packets\n",
		       tcp_cnt, udp_cnt, icmp_cnt);
		sleep(1);
	}

cleanup:
	/* maps, programs, raw sockets will auto cleanup on process exit */
	return 0;
}
static int run_test_program(void)
{
	int prog_fd;
	char dummy_data[64] = {0};

	struct bpf_insn prog[] = {
		#include "Input.txt"
	};
	size_t insns_cnt = sizeof(prog) / sizeof(struct bpf_insn);

	LIBBPF_OPTS(bpf_prog_load_opts, load_opts,
		.log_buf = bpf_log_buf,
		.log_size = BPF_LOG_BUF_SIZE,
		.log_level = 2,
	);
	prog_fd = bpf_prog_load(BPF_PROG_TYPE_SOCKET_FILTER, "test_prog", "GPL",
				 prog, insns_cnt, &load_opts);
	printf("--- VERIFIER LOG ---\n%s\n--- END LOG ---\n", bpf_log_buf);
	if (prog_fd < 0) {
		printf("failed to load prog '%s'\n", strerror(errno));
		return -1;
	}

	LIBBPF_OPTS(bpf_test_run_opts, test_opts,
		.data_in = dummy_data,
		.data_size_in = sizeof(dummy_data),
		.repeat = 1,
	);
	int ret = bpf_prog_test_run_opts(prog_fd, &test_opts);
	if (ret < 0) {
		printf("test_run failed '%s'\n", strerror(errno));
		return -1;
	}

	printf("--- RUNTIME RESULT ---\n");
	printf("r0 (retval) = %u\n", test_opts.retval);
	printf("----------------------\n");
	return 0;
}

int main(void)
{
	FILE *f;

	f = popen("ping -4 -c5 localhost", "r");
	(void)f;
	return run_test_program();

	//return test_sock();
}
