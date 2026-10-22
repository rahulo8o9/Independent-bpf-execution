#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <linux/bpf.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#define LOG_SIZE (1u << 26)

static char log_buf[LOG_SIZE];

int main(int argc, char **argv)
{
	FILE *f;
	long size;
	struct bpf_insn *prog;
	size_t cnt, i;
	int map_fd, prog_fd, err;
	char data[64] = {0};

	if (argc < 2) {
		fprintf(stderr, "usage: %s prog.bin\n", argv[0]);
		return 2;
	}
	f = fopen(argv[1], "rb");
	if (!f) {
		perror("open");
		return 2;
	}
	fseek(f, 0, SEEK_END);
	size = ftell(f);
	fseek(f, 0, SEEK_SET);
	prog = malloc(size);
	if (!prog || fread(prog, 1, size, f) != (size_t)size) {
		perror("read");
		return 2;
	}
	fclose(f);
	cnt = size / sizeof(struct bpf_insn);

	map_fd = bpf_map_create(BPF_MAP_TYPE_ARRAY, "m", 4, 8, 4, NULL);
	if (map_fd < 0) {
		printf("failed to create map '%s'\n", strerror(errno));
		return 1;
	}
	for (i = 0; i < cnt; i++) {
		if (prog[i].code == (BPF_LD | BPF_DW | BPF_IMM) &&
		    prog[i].src_reg == BPF_PSEUDO_MAP_FD)
			prog[i].imm = map_fd;
	}

	LIBBPF_OPTS(bpf_prog_load_opts, lo,
		.log_buf = log_buf,
		.log_size = LOG_SIZE,
		.log_level = 2,
	);
	prog_fd = bpf_prog_load(BPF_PROG_TYPE_SOCKET_FILTER, "t", "GPL", prog, cnt, &lo);
	printf("--- VERIFIER LOG ---\n%s\n--- END LOG ---\n", log_buf);
	if (prog_fd < 0) {
		printf("failed to load prog '%s'\n", strerror(errno));
		return 1;
	}

	LIBBPF_OPTS(bpf_test_run_opts, to,
		.data_in = data,
		.data_size_in = sizeof(data),
		.repeat = 1,
	);
	err = bpf_prog_test_run_opts(prog_fd, &to);
	if (err < 0) {
		printf("test_run failed '%s'\n", strerror(errno));
		return 1;
	}
	printf("--- RUNTIME RESULT ---\nr0 (retval) = %u\n----------------------\n", to.retval);
	return 0;
}
