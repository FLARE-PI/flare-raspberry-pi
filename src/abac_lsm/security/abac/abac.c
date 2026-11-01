/*
	ABAC LSM hooks
	Copyright (C) <2021>  Hariyala Omkara Naga Sai Varshith
*/

#include <linux/limits.h>
#include <linux/string.h>
#include <linux/types.h>
#include <linux/binfmts.h>
#include <linux/xattr.h>
#include <linux/kernel_read_file.h>
#include <linux/lsm_hooks.h>
#include <linux/dcache.h>
#include <linux/cred.h>
#include <linux/slab.h>
#include <linux/timekeeping.h>
#include <uapi/linux/gpio.h>
#include "abacfs.h"
#include "resolve.h"

static struct lsm_id abac_lsmid __ro_after_init = {
	.name = "abac",
};

// File read/write hook
static int abac_file_permission(struct file *file, int mask)
{
	u64 start_ns, elapsed_ns;
	bool allowed;
	// if the user is root, don't evaluate
	unsigned int UID = current_uid().val;
	if (UID < 1000) {
		return 0;
	}
	char *path = NULL;
	struct dentry *dentry = file->f_path.dentry;
	char *buff = kmalloc(PATH_MAX, GFP_KERNEL);
	if (!buff)
		return -ENOMEM;
	path = dentry_path_raw(dentry, buff, PATH_MAX);
	if (IS_ERR(path)) {
		kfree(buff);
		return -EPERM;
	}
	down_read(&abac_state_lock);
	// Scope and policy state are published together under this lock.
	if (!abac_path_is_covered(path)) {
		up_read(&abac_state_lock);
		kfree(buff);
		return 0;
	}
	// if the policy is not yet initalized, DENY permission
	if (policy == NULL || user_attr == NULL || obj_attr == NULL) {
		up_read(&abac_state_lock);
		kfree(buff);
		return -EPERM;
	}
	start_ns = abac_recording ? ktime_get_ns() : 0;
	allowed = abac_resolve(UID, path, mask);
	if (abac_recording) {
		elapsed_ns = ktime_get_ns() - start_ns;
		abac_record_decision(ABAC_RESOURCE_FILE, elapsed_ns, allowed);
	}
	up_read(&abac_state_lock);
	kfree(buff);
	if (allowed) {
		return 0;
	}
	return -EPERM;
}

static int abac_gpio_permission(const char *chip_name, unsigned int offset,
				enum abac_op op)
{
	char resource_id[96];
	u64 start_ns, elapsed_ns;
	bool allowed;
	unsigned int uid = current_uid().val;

	if (uid < 1000)
		return 0;
	if (!chip_name || scnprintf(resource_id, sizeof(resource_id),
				    "gpio/%s/%u", chip_name, offset) >=
		    sizeof(resource_id))
		return -EPERM;
	down_read(&abac_state_lock);
	if (!abac_resource_is_managed(resource_id))
		goto allow;
	if (!policy || !user_attr || !obj_attr)
		goto deny;
	start_ns = abac_recording ? ktime_get_ns() : 0;
	allowed = abac_resolve_resource(uid, resource_id, op);
	if (abac_recording) {
		elapsed_ns = ktime_get_ns() - start_ns;
		abac_record_decision(ABAC_RESOURCE_GPIO, elapsed_ns, allowed);
		abac_record_gpio_policy_decision(uid, offset, op, allowed,
						 abac_policy_generation);
	}
	up_read(&abac_state_lock);
	return allowed ? 0 : -EPERM;

allow:
	up_read(&abac_state_lock);
	return 0;

deny:
	up_read(&abac_state_lock);
	return -EPERM;
}

static int abac_gpio_line_request(const char *chip_name, unsigned int offset,
				  u64 flags)
{
	return abac_gpio_permission(chip_name, offset,
			(flags & GPIO_V2_LINE_FLAG_OUTPUT) ? ABAC_MODIFY : ABAC_READ);
}

static int abac_gpio_line_config(const char *chip_name, unsigned int offset,
				 u64 flags)
{
	return abac_gpio_permission(chip_name, offset,
			(flags & GPIO_V2_LINE_FLAG_OUTPUT) ? ABAC_MODIFY : ABAC_READ);
}

static int abac_gpio_line_get_value(const char *chip_name, unsigned int offset)
{
	return abac_gpio_permission(chip_name, offset, ABAC_READ);
}

static int abac_gpio_line_set_value(const char *chip_name, unsigned int offset)
{
	return abac_gpio_permission(chip_name, offset, ABAC_MODIFY);
}

// The hooks we wish to be installed.
static struct security_hook_list abac_hooks[] __ro_after_init = {
	LSM_HOOK_INIT(file_permission, abac_file_permission),
	LSM_HOOK_INIT(gpio_line_request, abac_gpio_line_request),
	LSM_HOOK_INIT(gpio_line_config, abac_gpio_line_config),
	LSM_HOOK_INIT(gpio_line_get_value, abac_gpio_line_get_value),
	LSM_HOOK_INIT(gpio_line_set_value, abac_gpio_line_set_value),
};

// Initialize our module.
static int __init abac_init(void)
{
	security_add_hooks(abac_hooks, ARRAY_SIZE(abac_hooks), &abac_lsmid);
	printk(KERN_INFO
	       "ABAC LSM: Initialized.\n Protected files are selected by ABAC include/exclude path rules.\n");
	return 0;
}

DEFINE_LSM(abac) = {
	.name = "abac",
	.init = abac_init,
};
