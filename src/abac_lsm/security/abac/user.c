/*
	ABAC user attribute parsing methods
	Copyright (C) <2021>  Hariyala Omkara Naga Sai Varshith
*/

#include <linux/errno.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/string.h>
#include "user.h"

void destroy_user_list(abac_user *head)
{
	abac_user *next;

	while (head) {
		next = head->next;
		destroy_avp_list(head->attrs);
		kfree(head);
		head = next;
	}
}

static int parse_line(const char *buffer, int start, int end, abac_user **out)
{
	abac_user *user;
	char *uidbuf;
	int delim;
	int uid_len;
	int ret;

	if (!out)
		return -EINVAL;
	*out = NULL;
	delim = findidx(buffer, ':', start, end);
	if (delim <= start || delim >= end - 1 ||
	    findidx(buffer, ':', delim + 1, end) != -1)
		return -EINVAL;
	uid_len = delim - start;
	uidbuf = kmemdup_nul(buffer + start, uid_len, GFP_KERNEL);
	if (!uidbuf)
		return -ENOMEM;

	user = kzalloc(sizeof(*user), GFP_KERNEL);
	if (!user) {
		kfree(uidbuf);
		return -ENOMEM;
	}
	ret = kstrtouint(uidbuf, 10, &user->uid);
	kfree(uidbuf);
	if (ret) {
		kfree(user);
		return ret == -ERANGE ? -ERANGE : -EINVAL;
	}
	ret = parse_avp_section(buffer, delim + 1, end, &user->attrs);
	if (ret) {
		kfree(user);
		return ret;
	}
	*out = user;
	return 0;
}

int parse_user_attr(const char *buffer, int length, abac_user **out)
{
	abac_user *head = NULL;
	abac_user *tail = NULL;
	abac_user *user;
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
		ret = parse_line(buffer, start, i, &user);
		if (ret)
			goto fail;
		if (tail)
			tail->next = user;
		else
			head = user;
		tail = user;
		start = i + 1;
	}
	*out = head;
	return 0;

fail:
	destroy_user_list(head);
	return ret;
}

void print_user_attrs(abac_user *user)
{
	avp *attr;

	while (user) {
		printk("%u", user->uid);
		for (attr = user->attrs; attr; attr = attr->next)
			printk("%s=%s", attr->name, attr->value);
		user = user->next;
		printk("\n");
	}
	printk("\n");
}
