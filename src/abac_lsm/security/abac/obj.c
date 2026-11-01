/*
	ABAC object attribute parsing methods
	Copyright (C) <2021>  Hariyala Omkara Naga Sai Varshith
*/

#include <linux/errno.h>
#include <linux/slab.h>
#include <linux/string.h>
#include "obj.h"

void destroy_obj_list(abac_obj *head)
{
	abac_obj *next;

	while (head) {
		next = head->next;
		destroy_avp_list(head->attrs);
		kfree(head);
		head = next;
	}
}

static int parse_line(const char *buffer, int start, int end, abac_obj **out)
{
	abac_obj *object;
	int delim;
	int path_len;
	int ret;

	if (!out)
		return -EINVAL;
	*out = NULL;
	delim = findidx(buffer, ':', start, end);
	if (delim <= start || delim >= end - 1 ||
	    findidx(buffer, ':', delim + 1, end) != -1)
		return -EINVAL;
	path_len = delim - start;
	if (path_len >= PATH_MAX ||
	    (buffer[start] != '/' &&
	     (path_len < 5 || strncmp(buffer + start, "gpio/", 5))))
		return path_len >= PATH_MAX ? -ENAMETOOLONG : -EINVAL;

	object = kzalloc(sizeof(*object), GFP_KERNEL);
	if (!object)
		return -ENOMEM;
	memcpy(object->path, buffer + start, path_len);
	object->path[path_len] = '\0';
	ret = parse_avp_section(buffer, delim + 1, end, &object->attrs);
	if (ret) {
		kfree(object);
		return ret;
	}
	*out = object;
	return 0;
}

int parse_obj_attr(const char *buffer, int length, abac_obj **out)
{
	abac_obj *head = NULL;
	abac_obj *tail = NULL;
	abac_obj *object;
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
		ret = parse_line(buffer, start, i, &object);
		if (ret)
			goto fail;
		if (tail)
			tail->next = object;
		else
			head = object;
		tail = object;
		start = i + 1;
	}
	*out = head;
	return 0;

fail:
	destroy_obj_list(head);
	return ret;
}

void print_obj_attrs(abac_obj *object)
{
	avp *attr;

	while (object) {
		printk("%s", object->path);
		for (attr = object->attrs; attr; attr = attr->next)
			printk("%s=%s", attr->name, attr->value);
		object = object->next;
		printk("\n");
	}
	printk("\n");
}
