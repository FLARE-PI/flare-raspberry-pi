/*
	ABAC include/exclude path parsing helpers
*/

#include <linux/errno.h>
#include <linux/slab.h>
#include <linux/string.h>
#include "pathcfg.h"

int parse_path_entries(const char *buffer, int length,
		       struct abac_path_entry **out)
{
	struct abac_path_entry *head = NULL;
	struct abac_path_entry *tail = NULL;
	struct abac_path_entry *entry;
	int start = 0;
	int i;
	int path_len;

	if (!out)
		return -EINVAL;
	*out = NULL;
	/* Empty input is the established, explicit way to clear a path list. */
	if (length == 0)
		return 0;
	if (!buffer || length < 2 || buffer[length - 1] != '\n')
		return -EINVAL;

	for (i = 0; i < length; i++) {
		if (buffer[i] != '\n')
			continue;
		path_len = i - start;
		if (path_len <= 0 || buffer[start] != '/')
			goto invalid;
		entry = kzalloc(sizeof(*entry), GFP_KERNEL);
		if (!entry)
			goto nomem;
		entry->path = kmemdup_nul(buffer + start, path_len, GFP_KERNEL);
		if (!entry->path) {
			kfree(entry);
			goto nomem;
		}
		if (tail)
			tail->next = entry;
		else
			head = entry;
		tail = entry;
		start = i + 1;
	}
	*out = head;
	return 0;

nomem:
	destroy_path_entries(head);
	return -ENOMEM;
invalid:
	destroy_path_entries(head);
	return -EINVAL;
}

void destroy_path_entries(struct abac_path_entry *head)
{
	struct abac_path_entry *next;

	while (head) {
		next = head->next;
		kfree(head->path);
		kfree(head);
		head = next;
	}
}

bool path_matches_entries(const char *path, struct abac_path_entry *head)
{
	size_t prefix_len;

	while (head) {
		prefix_len = strlen(head->path);
		if (prefix_len && !strncmp(path, head->path, prefix_len))
			return true;
		head = head->next;
	}
	return false;
}
