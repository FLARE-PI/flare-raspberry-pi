#define _POSIX_C_SOURCE 200809L

// SPDX-License-Identifier: MIT
/* Minimal dependency-free GPIO v2 client for Phase 3 ABAC tests. */
#include <errno.h>
#include <fcntl.h>
#include <linux/gpio.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <time.h>
#include <unistd.h>

static long long now_ns(void)
{
	struct timespec ts;
	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (long long)ts.tv_sec * 1000000000LL + ts.tv_nsec;
}

static void usage(const char *program)
{
	fprintf(stderr,
		"Usage: %s request|read|write|configure --chip /dev/gpiochip0 --line N "
		"[--value 0|1] [--direction input|output]\n", program);
	exit(2);
}

int main(int argc, char **argv)
{
	const char *operation;
	const char *chip = "/dev/gpiochip0";
	const char *direction = NULL;
	unsigned int line = UINT32_MAX;
	int value = 0, chip_fd, ret;
	unsigned long long reported_value;
	long long start, end;
	struct gpio_v2_line_request request = { 0 };
	struct gpio_v2_line_values values = { .mask = 1 };

	if (argc < 2)
		usage(argv[0]);
	operation = argv[1];
	for (int i = 2; i < argc; i++) {
		if (!strcmp(argv[i], "--chip") && i + 1 < argc)
			chip = argv[++i];
		else if (!strcmp(argv[i], "--line") && i + 1 < argc)
			line = strtoul(argv[++i], NULL, 10);
		else if (!strcmp(argv[i], "--value") && i + 1 < argc)
			value = atoi(argv[++i]);
		else if (!strcmp(argv[i], "--direction") && i + 1 < argc)
			direction = argv[++i];
		else
			usage(argv[0]);
	}
	if (line == UINT32_MAX ||
	    (strcmp(operation, "request") && strcmp(operation, "read") && strcmp(operation, "write") &&
	     strcmp(operation, "configure")) ||
	    (direction && strcmp(direction, "input") && strcmp(direction, "output")) ||
	    (value != 0 && value != 1))
		usage(argv[0]);

	chip_fd = open(chip, O_RDWR | O_CLOEXEC);
	if (chip_fd < 0) {
		perror("open gpiochip");
		return 1;
	}
	printf("stage=open chip=%s fd=%d\n", chip, chip_fd);
	request.offsets[0] = line;
	request.num_lines = 1;
	strncpy(request.consumer, "abac-phase3", sizeof(request.consumer) - 1);
	if (!strcmp(operation, "write") ||
	    (direction && !strcmp(direction, "output"))) {
		request.config.flags = GPIO_V2_LINE_FLAG_OUTPUT;
		request.config.num_attrs = 1;
		request.config.attrs[0].attr.id = GPIO_V2_LINE_ATTR_ID_OUTPUT_VALUES;
		request.config.attrs[0].attr.values = value;
		request.config.attrs[0].mask = 1;
	} else {
		request.config.flags = GPIO_V2_LINE_FLAG_INPUT;
	}

	start = now_ns();
	printf("stage=request line=%u direction=%s\n", line,
		request.config.flags & GPIO_V2_LINE_FLAG_OUTPUT ? "output" : "input");
	ret = ioctl(chip_fd, GPIO_V2_GET_LINE_IOCTL, &request);
	if (ret == 0)
		printf("stage=request_ok line_fd=%d\n", request.fd);
	if (ret == 0 && !strcmp(operation, "read")) {
		printf("stage=read\n");
		ret = ioctl(request.fd, GPIO_V2_LINE_GET_VALUES_IOCTL, &values);
	}
	if (ret == 0 && !strcmp(operation, "configure")) {
		struct gpio_v2_line_config config = { 0 };

		config.flags = (direction && !strcmp(direction, "output")) ?
			GPIO_V2_LINE_FLAG_OUTPUT : GPIO_V2_LINE_FLAG_INPUT;
		printf("stage=configure direction=%s\n",
			config.flags & GPIO_V2_LINE_FLAG_OUTPUT ? "output" : "input");
		ret = ioctl(request.fd, GPIO_V2_LINE_SET_CONFIG_IOCTL, &config);
	}
	if (ret == 0 && !strcmp(operation, "write")) {
		values.bits = value;
		printf("stage=write value=%d\n", value);
		ret = ioctl(request.fd, GPIO_V2_LINE_SET_VALUES_IOCTL, &values);
	}
	end = now_ns();
	if (ret < 0) {
		fprintf(stderr, "gpio_%s_error errno=%d (%s) latency_ns=%lld\n",
			operation, errno, strerror(errno), end - start);
		close(chip_fd);
		return errno == EPERM ? 13 : 1;
	}
	reported_value = !strcmp(operation, "read") ? values.bits :
		(unsigned long long)value;
	printf("operation=%s line=%u value=%llu latency_ns=%lld\n", operation, line,
	       reported_value, end - start);
	printf("stage=release line_fd=%d\n", request.fd);
	close(request.fd);
	printf("stage=close chip_fd=%d\n", chip_fd);
	close(chip_fd);
	return 0;
}
