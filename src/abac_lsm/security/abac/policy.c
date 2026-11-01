/*
	ABAC policy parsing methods
	Copyright (C) <2021>  Hariyala Omkara Naga Sai Varshith
*/

#include <linux/errno.h>
#include <linux/fs.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/string.h>
#include "avp.h"
#include "policy.h"

void destroy_policy(abac_policy *policy)
{
	abac_rule *next;

	if (!policy)
		return;
	destroy_policy_tree(policy->tree);
	while (policy->rules) {
		next = policy->rules->next;
		destroy_avp_list(policy->rules->user);
		destroy_avp_list(policy->rules->object);
		destroy_avp_list(policy->rules->env);
		kfree(policy->rules);
		policy->rules = next;
	}
	kfree(policy);
}

char *abac_op_str(enum abac_op mode)
{
	if (mode == ABAC_READ)
		return "ABAC_READ";
	if (mode == ABAC_MODIFY)
		return "ABAC_MODIFY";
	return "ABAC_IGNORE";
}

char *abac_effect_str(enum abac_effect effect)
{
	return effect == ABAC_DENY ? "ABAC_DENY" : "ABAC_ALLOW";
}

enum abac_op convert_to_abac_op(int mask)
{
	if (mask & (MAY_WRITE | MAY_APPEND))
		return ABAC_MODIFY;
	if (mask & (MAY_READ | MAY_OPEN | MAY_ACCESS))
		return ABAC_READ;
	return ABAC_IGNORE;
}

static int parse_rule_op(const char *token, int length, enum abac_op *op)
{
	if (length == 6 && !memcmp(token, "MODIFY", length)) {
		*op = ABAC_MODIFY;
		return 0;
	}
	if (length == 4 && !memcmp(token, "READ", length)) {
		*op = ABAC_READ;
		return 0;
	}
	return -EINVAL;
}

static int parse_rule_effect(const char *token, int length,
			     enum abac_effect *effect)
{
	if (length == 5 && !memcmp(token, "ALLOW", length)) {
		*effect = ABAC_ALLOW;
		return 0;
	}
	if (length == 4 && !memcmp(token, "DENY", length)) {
		*effect = ABAC_DENY;
		return 0;
	}
	return -EINVAL;
}

static int parse_line(const char *buffer, int start, int end, abac_rule **out)
{
	abac_rule *rule;
	int fields[4];
	int field_count = 0;
	int cursor = start;
	int delim;
	int ret;

	if (!out)
		return -EINVAL;
	*out = NULL;
	if (!buffer || end <= start)
		return -EINVAL;

	while ((delim = findidx(buffer, '|', cursor, end)) != -1) {
		if (field_count == ARRAY_SIZE(fields))
			return -EINVAL;
		fields[field_count++] = delim;
		cursor = delim + 1;
	}
	if (field_count != 3 && field_count != 4)
		return -EINVAL;
	if (fields[0] == start || fields[1] == fields[0] + 1 ||
	    fields[2] == fields[1] + 1 ||
	    (field_count == 4 && fields[3] == fields[2] + 1) ||
	    end == fields[field_count - 1] + 1)
		return -EINVAL;

	rule = kzalloc(sizeof(*rule), GFP_KERNEL);
	if (!rule)
		return -ENOMEM;
	ret = parse_avp_section(buffer, start, fields[0], &rule->user);
	if (ret)
		goto fail;
	ret = parse_avp_section(buffer, fields[0] + 1, fields[1], &rule->object);
	if (ret)
		goto fail;
	if (!(fields[2] == fields[1] + 2 && buffer[fields[1] + 1] == '*')) {
		ret = parse_avp_section(buffer, fields[1] + 1, fields[2], &rule->env);
		if (ret)
			goto fail;
	}
	ret = parse_rule_op(buffer + fields[2] + 1,
			    (field_count == 4 ? fields[3] : end) - fields[2] - 1,
			    &rule->op);
	if (ret)
		goto fail;
	rule->effect = ABAC_ALLOW;
	if (field_count == 4) {
		ret = parse_rule_effect(buffer + fields[3] + 1,
					end - fields[3] - 1, &rule->effect);
		if (ret)
			goto fail;
	}
	*out = rule;
	return 0;

fail:
	destroy_avp_list(rule->user);
	destroy_avp_list(rule->object);
	destroy_avp_list(rule->env);
	kfree(rule);
	return ret;
}

int parse_policy(const char *buffer, int length, abac_policy **out)
{
	abac_policy *policy;
	abac_rule *tail = NULL;
	abac_rule *rule;
	int start = 0;
	int i;
	int ret;

	if (!out)
		return -EINVAL;
	*out = NULL;
	if (!buffer || length <= 1 || buffer[length - 1] != '\n')
		return -EINVAL;
	policy = kzalloc(sizeof(*policy), GFP_KERNEL);
	if (!policy)
		return -ENOMEM;

	for (i = 0; i < length; i++) {
		if (buffer[i] != '\n')
			continue;
		if (i == start) {
			ret = -EINVAL;
			goto fail;
		}
		ret = parse_line(buffer, start, i, &rule);
		if (ret)
			goto fail;
		rule->id = ++policy->count;
		if (tail)
			tail->next = rule;
		else
			policy->rules = rule;
		tail = rule;
		start = i + 1;
	}
	policy->tree = build_policy_tree(policy->rules);
	if (!policy->tree) {
		ret = -ENOMEM;
		goto fail;
	}
	*out = policy;
	return 0;

fail:
	destroy_policy(policy);
	return ret;
}

void print_abac_policy(abac_policy *policy)
{
	abac_rule *rule;
	avp *attr;

	if (!policy)
		return;
	printk("Policy contains %d rules", policy->count);
	for (rule = policy->rules; rule; rule = rule->next) {
		printk("ID: %d", rule->id);
		for (attr = rule->user; attr; attr = attr->next)
			printk("%s=%s, ", attr->name, attr->value);
		printk("%s %s\n", abac_effect_str(rule->effect),
		       abac_op_str(rule->op));
	}
}
