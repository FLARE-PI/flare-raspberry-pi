/*
	ABAC environmental attribute parsing methods
	Copyright (C) <2021>  Hariyala Omkara Naga Sai Varshith
*/

#include <linux/errno.h>
#include <linux/kernel.h>
#include <linux/string.h>
#include "env.h"

int parse_env_attr(const char *buffer, int length, avp **out)
{
	avp *head = NULL;
	avp *tail = NULL;
	avp *pair;
	int start = 0;
	int i;
	int ret;

	if (!out)
		return -EINVAL;
	*out = NULL;
	if (!buffer || length <= 1 || buffer[length - 1] != '\n')
		return -EINVAL;

	for (i = 0; i < length; i++) {
		if (buffer[i] != '\n')
			continue;
		if (i == start) {
			ret = -EINVAL;
			goto fail;
		}
		ret = parse_avp(buffer, start, i, &pair);
		if (ret)
			goto fail;
		if (tail)
			tail->next = pair;
		else
			head = pair;
		tail = pair;
		start = i + 1;
	}
	*out = head;
	return 0;

fail:
	destroy_avp_list(head);
	return ret;
}

void print_env_attrs(avp *head)
{
	while (head) {
		printk("%s=%s", head->name, head->value);
		head = head->next;
	}
}

static bool avp_list_contains(const avp *required, const avp *actual)
{
	const avp *required_cursor = required;
	const avp *actual_cursor;

	while (required_cursor) {
		actual_cursor = actual;
		while (actual_cursor &&
		       (strcmp(required_cursor->name, actual_cursor->name) ||
			strcmp(required_cursor->value, actual_cursor->value)))
			actual_cursor = actual_cursor->next;
		if (!actual_cursor)
			return false;
		required_cursor = required_cursor->next;
	}
	return true;
}

static unsigned int avp_list_count(const avp *head)
{
	unsigned int count = 0;

	while (head) {
		count++;
		head = head->next;
	}
	return count;
}

bool abac_env_attr_equal(const avp *left, const avp *right)
{
	return avp_list_count(left) == avp_list_count(right) &&
		avp_list_contains(left, right) && avp_list_contains(right, left);
}
