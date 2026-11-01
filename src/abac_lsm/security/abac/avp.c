/*
	ABAC AVP parsing methods
	Copyright (C) <2021>  Hariyala Omkara Naga Sai Varshith
*/

#include <linux/errno.h>
#include <linux/slab.h>
#include <linux/string.h>
#include "avp.h"

void destroy_avp_list(avp *head)
{
	avp *next;

	while (head) {
		next = head->next;
		kfree(head->name);
		kfree(head->value);
		kfree(head);
		head = next;
	}
}

int findidx(const char *buffer, char ch, int start, int end)
{
	int i;

	if (!buffer || start < 0 || end < start)
		return -1;
	for (i = start; i < end; i++) {
		if (buffer[i] == ch)
			return i;
	}
	return -1;
}

int parse_avp(const char *buffer, int start, int end, avp **out)
{
	avp *pair;
	int delim;
	int name_len;
	int value_len;

	if (!out)
		return -EINVAL;
	*out = NULL;
	if (!buffer || start < 0 || end <= start)
		return -EINVAL;

	delim = findidx(buffer, '=', start, end);
	if (delim <= start || delim >= end - 1)
		return -EINVAL;
	/* An AVP is intentionally a single name=value pair. */
	if (findidx(buffer, '=', delim + 1, end) != -1)
		return -EINVAL;

	name_len = delim - start;
	value_len = end - delim - 1;
	pair = kzalloc(sizeof(*pair), GFP_KERNEL);
	if (!pair)
		return -ENOMEM;
	pair->name = kmemdup_nul(buffer + start, name_len, GFP_KERNEL);
	pair->value = kmemdup_nul(buffer + delim + 1, value_len, GFP_KERNEL);
	if (!pair->name || !pair->value) {
		kfree(pair->name);
		kfree(pair->value);
		kfree(pair);
		return -ENOMEM;
	}
	*out = pair;
	return 0;
}

int parse_avp_section(const char *buffer, int start, int end, avp **out)
{
	avp *head = NULL;
	avp *tail = NULL;
	avp *pair;
	int cursor;
	int delim;
	int ret;

	if (!out)
		return -EINVAL;
	*out = NULL;
	if (!buffer || start < 0 || end <= start)
		return -EINVAL;

	cursor = start;
	while (cursor < end) {
		delim = findidx(buffer, ',', cursor, end);
		if (delim == -1)
			delim = end;
		ret = parse_avp(buffer, cursor, delim, &pair);
		if (ret)
			goto fail;
		if (tail)
			tail->next = pair;
		else
			head = pair;
		tail = pair;
		if (delim == end)
			break;
		cursor = delim + 1;
		if (cursor == end) {
			ret = -EINVAL;
			goto fail;
		}
	}
	*out = head;
	return 0;

fail:
	destroy_avp_list(head);
	return ret;
}
