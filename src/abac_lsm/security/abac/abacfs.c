/*
	ABAC securityFS system calls
	Copyright (C) <2021>  Hariyala Omkara Naga Sai Varshith
*/

#include "abacfs.h"
#include "pathcfg.h"
#include "resolve.h"
#include <linux/fs.h>
#include <linux/ctype.h>
#include <linux/init.h>
#include <linux/math64.h>
#include <linux/security.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/timekeeping.h>
#include <linux/uaccess.h>

// const size_t MAX_FILE_SIZE = 65536; // 64Kb
const size_t MAX_FILE_SIZE = 16777216; // 16MB

struct dentry *abacfs;
struct dentry *policy_file;
struct dentry *policy_status_file;
struct dentry *user_attr_file;
struct dentry *obj_attr_file;
struct dentry *env_attr_file;
struct dentry *env_status_file;
struct dentry *env_ttl_file;
struct dentry *action_file;
struct dentry *perf_file;
struct dentry *stats_file;
struct dentry *mode_file;
struct dentry *hashmap_file;
struct dentry *include_paths_file;
struct dentry *exclude_paths_file;

char *policy_buf = NULL;
char *user_attr_buf = NULL;
char *obj_attr_buf = NULL;
char *env_attr_buf = NULL;
char *include_paths_buf = NULL;
char *exclude_paths_buf = NULL;

abac_policy *policy = NULL;
u64 abac_policy_generation;
abac_user *user_attr = NULL;
abac_obj *obj_attr = NULL;
avp *env_attr = NULL;
DECLARE_RWSEM(abac_state_lock);
u64 abac_env_generation;
u64 abac_env_last_update_ns;
#define ABAC_ENV_TTL_DEFAULT_MS 6000ULL
#define ABAC_ENV_TTL_MIN_MS 1000ULL
#define ABAC_ENV_TTL_MAX_MS 600000ULL
u64 abac_env_last_refresh_ns;
u64 abac_env_ttl_ms = ABAC_ENV_TTL_DEFAULT_MS;
enum abac_resolve_mode abac_mode = ABAC_RESOLVE_TREE;
bool abac_use_hashmap;
int abac_recording;
struct abac_perf_stats abac_stats;
struct abac_path_entry *abac_include_paths = NULL;
struct abac_path_entry *abac_exclude_paths = NULL;
u64 abac_last_gpio_sequence;
u64 abac_last_gpio_policy_generation;
u64 abac_last_gpio_timestamp_ns;
unsigned int abac_last_gpio_uid;
unsigned int abac_last_gpio_offset;
enum abac_op abac_last_gpio_op;
bool abac_last_gpio_allowed;

void abac_reset_perf_stats(void)
{
	memset(&abac_stats, 0, sizeof(abac_stats));
}

void abac_record_decision(enum abac_resource_class resource, u64 elapsed_ns,
			  bool allowed)
{
	abac_stats.prev_access_time_ns = elapsed_ns;
	abac_stats.total_time_ns += elapsed_ns;
	abac_stats.decision_count++;
	if (resource == ABAC_RESOURCE_FILE)
		abac_stats.file_decision_count++;
	else if (resource == ABAC_RESOURCE_GPIO)
		abac_stats.gpio_decision_count++;
	if (abac_stats.min_time_ns == 0 || elapsed_ns < abac_stats.min_time_ns)
		abac_stats.min_time_ns = elapsed_ns;
	if (elapsed_ns > abac_stats.max_time_ns)
		abac_stats.max_time_ns = elapsed_ns;
	if (allowed)
		abac_stats.allow_count++;
	else
		abac_stats.deny_count++;
}

/* Called while abac_state_lock is held by the GPIO authorization path. */
void abac_record_gpio_policy_decision(unsigned int uid, unsigned int offset,
			      enum abac_op op, bool allowed,
			      u64 policy_generation)
{
	abac_last_gpio_sequence++;
	abac_last_gpio_policy_generation = policy_generation;
	abac_last_gpio_timestamp_ns = ktime_get_ns();
	abac_last_gpio_uid = uid;
	abac_last_gpio_offset = offset;
	abac_last_gpio_op = op;
	abac_last_gpio_allowed = allowed;
}

bool abac_path_is_covered(const char *path)
{
	bool included = true;

	if (!path || path[0] != '/')
		return false;
	if (abac_include_paths)
		included = path_matches_entries(path, abac_include_paths);
	if (!included)
		return false;
	if (abac_exclude_paths && path_matches_entries(path, abac_exclude_paths))
		return false;
	return true;
}

bool abac_env_is_fresh(void)
{
	u64 now;

	if (!env_attr || !abac_env_last_refresh_ns)
		return false;
	now = ktime_get_boottime_ns();
	return now - abac_env_last_refresh_ns <=
		abac_env_ttl_ms * NSEC_PER_MSEC;
}

// method for opening policy file
static int abac_open(struct inode *i, struct file *f)
{
	// TODO: Add a check to let only the root access the policy file
	return 0;
}

/* Userspace emits this only when an otherwise-empty JSON section is reloaded. */
static bool abac_clear_request(const char *buffer, size_t len)
{
	return len == 6 && !memcmp(buffer, "CLEAR\n", len);
}

// method for writing to policy file
static ssize_t policy_write(struct file *filp, const char __user *buffer,
			    size_t len, loff_t *off)
{
	char *new_buf;
	abac_policy *new_policy;
	abac_policy *old_policy;
	char *old_buf;

	if (!len || len >= MAX_FILE_SIZE)
		return len >= MAX_FILE_SIZE ? -E2BIG : -EINVAL;
	new_buf = memdup_user_nul(buffer, len);
	if (IS_ERR(new_buf)) {
		return PTR_ERR(new_buf);
	}
	if (abac_clear_request(new_buf, len)) {
		new_policy = NULL;
	} else {
		int ret = parse_policy(new_buf, len, &new_policy);

		if (ret) {
			kfree(new_buf);
			return ret;
		}
	}
	down_write(&abac_state_lock);
	old_policy = policy;
	old_buf = policy_buf;
	policy = new_policy;
	policy_buf = new_buf;
	abac_policy_generation++;
	up_write(&abac_state_lock);
	destroy_policy(old_policy);
	kfree(old_buf);
	return len;
}

static ssize_t policy_status_read(struct file *filp, char __user *buffer,
				  size_t len, loff_t *off)
{
	char out[384];
	int out_len;

	down_read(&abac_state_lock);
	out_len = scnprintf(out, sizeof(out),
			    "policy_generation=%llu\n"
			    "last_gpio_sequence=%llu\n"
			    "last_gpio_policy_generation=%llu\n"
			    "last_gpio_timestamp_ns=%llu\n"
			    "last_gpio_uid=%u\n"
			    "last_gpio_offset=%u\n"
			    "last_gpio_operation=%s\n"
			    "last_gpio_decision=%s\n",
			    abac_policy_generation, abac_last_gpio_sequence,
			    abac_last_gpio_policy_generation,
			    abac_last_gpio_timestamp_ns, abac_last_gpio_uid,
			    abac_last_gpio_offset,
			    abac_op_str(abac_last_gpio_op),
			    abac_last_gpio_allowed ? "ALLOW" : "DENY");
	up_read(&abac_state_lock);
	return simple_read_from_buffer(buffer, len, off, out, out_len);
}

// method for reading from policy file
static ssize_t policy_read(struct file *filp, char __user *buffer, size_t len,
			   loff_t *off)
{
	ssize_t result;
	int policy_buf_len;

	down_read(&abac_state_lock);
	if (!policy_buf) {
		up_read(&abac_state_lock);
		return -EFAULT;
	}
	/*
static int finished = 0;
if (finished) {
    finished = 0;
    return 0;
}
finished = 1;
*/

	policy_buf_len = strlen(policy_buf);
	if (copy_to_user(buffer, policy_buf, policy_buf_len) != 0) {
		printk(KERN_INFO "Read from policy failed\n");
		result = -EFAULT;
	} else {
		result = policy_buf_len;
	}
	up_read(&abac_state_lock);
	return result;
}

// method for writing to user_attrs file
static ssize_t user_attr_write(struct file *filp, const char __user *buffer,
			       size_t len, loff_t *off)
{
	char *new_buf;
	abac_user *new_user_attr;
	abac_user *old_user_attr;
	char *old_buf;
	if (!len || len >= MAX_FILE_SIZE)
		return len >= MAX_FILE_SIZE ? -E2BIG : -EINVAL;
	new_buf = memdup_user_nul(buffer, len);
	if (IS_ERR(new_buf)) {
		return PTR_ERR(new_buf);
	}
	if (abac_clear_request(new_buf, len)) {
		new_user_attr = NULL;
	} else {
		int ret = parse_user_attr(new_buf, len, &new_user_attr);

		if (ret) {
			kfree(new_buf);
			return ret;
		}
	}
	down_write(&abac_state_lock);
	abac_destroy_lookup_maps();
	old_user_attr = user_attr;
	old_buf = user_attr_buf;
	user_attr = new_user_attr;
	user_attr_buf = new_buf;
	abac_rebuild_lookup_maps();
	up_write(&abac_state_lock);
	destroy_user_list(old_user_attr);
	kfree(old_buf);
	return len;
}

// method for writing to obj_attrs file
static ssize_t obj_attr_write(struct file *filp, const char __user *buffer,
			      size_t len, loff_t *off)
{
	char *new_buf;
	abac_obj *new_obj_attr;
	abac_obj *old_obj_attr;
	char *old_buf;
	if (!len || len >= MAX_FILE_SIZE)
		return len >= MAX_FILE_SIZE ? -E2BIG : -EINVAL;
	new_buf = memdup_user_nul(buffer, len);
	if (IS_ERR(new_buf)) {
		return PTR_ERR(new_buf);
	}
	if (abac_clear_request(new_buf, len)) {
		new_obj_attr = NULL;
	} else {
		int ret = parse_obj_attr(new_buf, len, &new_obj_attr);

		if (ret) {
			kfree(new_buf);
			return ret;
		}
	}
	down_write(&abac_state_lock);
	abac_destroy_lookup_maps();
	old_obj_attr = obj_attr;
	old_buf = obj_attr_buf;
	obj_attr = new_obj_attr;
	obj_attr_buf = new_buf;
	abac_rebuild_lookup_maps();
	up_write(&abac_state_lock);
	destroy_obj_list(old_obj_attr);
	kfree(old_buf);
	return len;
}

// method for writing to env_attrs file
static ssize_t env_attr_write(struct file *filp, const char __user *buffer,
				      size_t len, loff_t *off)
{
	char *new_buf;
	avp *new_env_attr;
	avp *old_env_attr;
	char *old_buf;
	u64 now;
	bool content_changed;
	bool valid_publication;
	if (!len || len >= MAX_FILE_SIZE)
		return len >= MAX_FILE_SIZE ? -E2BIG : -EINVAL;
	new_buf = memdup_user_nul(buffer, len);
	if (IS_ERR(new_buf)) {
		return PTR_ERR(new_buf);
	}
	if (abac_clear_request(new_buf, len)) {
		new_env_attr = NULL;
		valid_publication = false;
	} else {
		int ret = parse_env_attr(new_buf, len, &new_env_attr);

		if (ret) {
			kfree(new_buf);
			return ret;
		}
		valid_publication = true;
	}
	down_write(&abac_state_lock);
	now = ktime_get_boottime_ns();
	content_changed = !abac_env_attr_equal(env_attr, new_env_attr);
	old_env_attr = NULL;
	old_buf = NULL;
	if (content_changed) {
		old_env_attr = env_attr;
		old_buf = env_attr_buf;
		env_attr = new_env_attr;
		env_attr_buf = new_buf;
		abac_env_generation++;
		abac_env_last_update_ns = now;
	} else {
		destroy_avp_list(new_env_attr);
		kfree(new_buf);
	}
	if (valid_publication)
		abac_env_last_refresh_ns = now;
	else
		abac_env_last_refresh_ns = 0;
	up_write(&abac_state_lock);
	destroy_avp_list(old_env_attr);
	kfree(old_buf);
	return len;
}

static const struct file_operations policy_fops = {
	.open = abac_open,
	.read = policy_read,
	.write = policy_write,
};

static const struct file_operations policy_status_fops = {
	.open = abac_open,
	.read = policy_status_read,
};

static const struct file_operations user_attr_fops = {
	.open = abac_open,
	.write = user_attr_write,
};

static const struct file_operations obj_attr_fops = {
	.open = abac_open,
	.write = obj_attr_write,
};

static const struct file_operations env_attr_fops = {
	.open = abac_open,
	.write = env_attr_write,
};

static ssize_t env_status_read(struct file *filp, char __user *buffer,
				       size_t len, loff_t *off)
{
	char out[224];
	int out_len;
	u64 now;
	u64 age_ms = 0;
	bool stale;

	down_read(&abac_state_lock);
	now = ktime_get_boottime_ns();
	stale = !abac_env_is_fresh();
	if (abac_env_last_refresh_ns)
		age_ms = div_u64(now - abac_env_last_refresh_ns, NSEC_PER_MSEC);
	out_len = scnprintf(out, sizeof(out),
				    "generation=%llu\nlast_update_ns=%llu\n"
				    "env_generation=%llu\nenv_ttl_ms=%llu\n"
				    "env_last_refresh_ns=%llu\nenv_age_ms=%llu\nenv_stale=%u\n",
				    abac_env_generation, abac_env_last_update_ns,
				    abac_env_generation, abac_env_ttl_ms,
				    abac_env_last_refresh_ns, age_ms, stale ? 1 : 0);
	up_read(&abac_state_lock);
	return simple_read_from_buffer(buffer, len, off, out, out_len);
}

static ssize_t env_ttl_read(struct file *filp, char __user *buffer,
				    size_t len, loff_t *off)
{
	char out[32];
	int out_len;

	down_read(&abac_state_lock);
	out_len = scnprintf(out, sizeof(out), "%llu\n", abac_env_ttl_ms);
	up_read(&abac_state_lock);
	return simple_read_from_buffer(buffer, len, off, out, out_len);
}

static ssize_t env_ttl_write(struct file *filp, const char __user *buffer,
				     size_t len, loff_t *off)
{
	char *value;
	u64 ttl_ms;
	int ret;
	size_t index;
	size_t original_len = len;

	if (!len || len >= 32)
		return len >= 32 ? -E2BIG : -EINVAL;
	value = memdup_user_nul(buffer, len);
	if (IS_ERR(value))
		return PTR_ERR(value);
	if (value[len - 1] == '\n')
		value[--len] = '\0';
	if (!len) {
		kfree(value);
		return -EINVAL;
	}
	for (index = 0; index < len; index++) {
		if (!isdigit((unsigned char)value[index])) {
			kfree(value);
			return -EINVAL;
		}
	}
	ret = kstrtoull(value, 10, &ttl_ms);
	kfree(value);
	if (ret)
		return ret;
	if (ttl_ms < ABAC_ENV_TTL_MIN_MS || ttl_ms > ABAC_ENV_TTL_MAX_MS)
		return -ERANGE;
	down_write(&abac_state_lock);
	abac_env_ttl_ms = ttl_ms;
	up_write(&abac_state_lock);
	return original_len;
}

static const struct file_operations env_status_fops = {
	.open = abac_open,
	.read = env_status_read,
};

static const struct file_operations env_ttl_fops = {
	.open = abac_open,
	.read = env_ttl_read,
	.write = env_ttl_write,
};

static ssize_t path_entries_write(const char __user *buffer, size_t len,
				  bool include)
{
	struct abac_path_entry *new_entries;
	struct abac_path_entry *old_entries;
	char *new_buf;
	char *old_buf;
	int ret;

	if (len >= MAX_FILE_SIZE)
		return -E2BIG;
	if (len) {
		new_buf = memdup_user_nul(buffer, len);
		if (IS_ERR(new_buf))
			return PTR_ERR(new_buf);
	} else {
		new_buf = kzalloc(1, GFP_KERNEL);
		if (!new_buf)
			return -ENOMEM;
	}
	/* A zero-length write is not delivered by normal shell redirection. */
	if (abac_clear_request(new_buf, len)) {
		kfree(new_buf);
		new_buf = kzalloc(1, GFP_KERNEL);
		if (!new_buf)
			return -ENOMEM;
		new_entries = NULL;
	} else {
		ret = parse_path_entries(new_buf, len, &new_entries);
		if (ret) {
			kfree(new_buf);
			return ret;
		}
	}

	down_write(&abac_state_lock);
	if (include) {
		old_entries = abac_include_paths;
		old_buf = include_paths_buf;
		abac_include_paths = new_entries;
		include_paths_buf = new_buf;
	} else {
		old_entries = abac_exclude_paths;
		old_buf = exclude_paths_buf;
		abac_exclude_paths = new_entries;
		exclude_paths_buf = new_buf;
	}
	up_write(&abac_state_lock);
	destroy_path_entries(old_entries);
	kfree(old_buf);
	return len;
}

static ssize_t include_paths_write(struct file *filp,
				   const char __user *buffer,
				   size_t len, loff_t *off)
{
	return path_entries_write(buffer, len, true);
}

static ssize_t exclude_paths_write(struct file *filp,
				   const char __user *buffer,
				   size_t len, loff_t *off)
{
	return path_entries_write(buffer, len, false);
}

static ssize_t include_paths_read(struct file *filp, char __user *buffer,
				  size_t len, loff_t *off)
{
	ssize_t ret;

	down_read(&abac_state_lock);
	ret = include_paths_buf ? simple_read_from_buffer(buffer, len, off,
						 include_paths_buf,
						 strlen(include_paths_buf)) : 0;
	up_read(&abac_state_lock);
	return ret;
}

static ssize_t exclude_paths_read(struct file *filp, char __user *buffer,
				  size_t len, loff_t *off)
{
	ssize_t ret;

	down_read(&abac_state_lock);
	ret = exclude_paths_buf ? simple_read_from_buffer(buffer, len, off,
						 exclude_paths_buf,
						 strlen(exclude_paths_buf)) : 0;
	up_read(&abac_state_lock);
	return ret;
}

static int read_control_token(const char __user *buffer, size_t len,
			      char *token, size_t token_size)
{
	if (!len || len >= token_size)
		return -EINVAL;
	if (copy_from_user(token, buffer, len))
		return -EFAULT;
	if (memchr(token, '\0', len))
		return -EINVAL;
	if (token[len - 1] == '\n')
		len--;
	if (!len || memchr(token, '\n', len))
		return -EINVAL;
	token[len] = '\0';
	return 0;
}

static ssize_t action_write(struct file *filp, const char __user *buffer,
			    size_t len, loff_t *off)
{
	char cmd[32];
	int ret = read_control_token(buffer, len, cmd, sizeof(cmd));

	if (ret)
		return ret;
	if (strcmp(cmd, "RECORD") == 0) {
		down_write(&abac_state_lock);
		abac_recording = 1;
		up_write(&abac_state_lock);
		return len;
	}
	if (strcmp(cmd, "STOP") == 0) {
		down_write(&abac_state_lock);
		abac_recording = 0;
		up_write(&abac_state_lock);
		return len;
	}
	if (strcmp(cmd, "RESET") == 0) {
		down_write(&abac_state_lock);
		abac_reset_perf_stats();
		up_write(&abac_state_lock);
		return len;
	}
	return -EINVAL;
}

static ssize_t perf_read(struct file *filp, char __user *buffer, size_t len,
			 loff_t *off)
{
	char out[32];
	int out_len;

	out_len = scnprintf(out, sizeof(out), "%llu\n",
			    abac_stats.prev_access_time_ns);
	return simple_read_from_buffer(buffer, len, off, out, out_len);
}

static ssize_t stats_read(struct file *filp, char __user *buffer, size_t len,
			  loff_t *off)
{
	char out[384];
	int out_len;

	out_len = scnprintf(out, sizeof(out),
			    "decision_count=%llu\nallow_count=%llu\ndeny_count=%llu\ntotal_time_ns=%llu\nmin_time_ns=%llu\nmax_time_ns=%llu\nprev_access_time_ns=%llu\nfile_decision_count=%llu\ngpio_decision_count=%llu\n",
			    abac_stats.decision_count, abac_stats.allow_count,
			    abac_stats.deny_count, abac_stats.total_time_ns,
			    abac_stats.min_time_ns, abac_stats.max_time_ns,
			    abac_stats.prev_access_time_ns, abac_stats.file_decision_count,
			    abac_stats.gpio_decision_count);
	return simple_read_from_buffer(buffer, len, off, out, out_len);
}

static ssize_t mode_read(struct file *filp, char __user *buffer, size_t len,
			 loff_t *off)
{
	const char *mode;
	ssize_t ret;

	down_read(&abac_state_lock);
	mode = abac_mode == ABAC_RESOLVE_LINEAR ? "linear\n" : "tree\n";
	ret = simple_read_from_buffer(buffer, len, off, mode, strlen(mode));
	up_read(&abac_state_lock);
	return ret;
}

static ssize_t mode_write(struct file *filp, const char __user *buffer,
			  size_t len, loff_t *off)
{
	char mode[16];
	int ret = read_control_token(buffer, len, mode, sizeof(mode));

	if (ret)
		return ret;
	if (strcmp(mode, "linear") == 0) {
		down_write(&abac_state_lock);
		abac_mode = ABAC_RESOLVE_LINEAR;
		up_write(&abac_state_lock);
		return len;
	}
	if (strcmp(mode, "tree") == 0) {
		down_write(&abac_state_lock);
		abac_mode = ABAC_RESOLVE_TREE;
		up_write(&abac_state_lock);
		return len;
	}
	return -EINVAL;
}

static const struct file_operations action_fops = {
	.open = abac_open,
	.write = action_write,
};

static const struct file_operations perf_fops = {
	.open = abac_open,
	.read = perf_read,
};

static const struct file_operations stats_fops = {
	.open = abac_open,
	.read = stats_read,
};

static const struct file_operations mode_fops = {
	.open = abac_open,
	.read = mode_read,
	.write = mode_write,
};

static ssize_t hashmap_read(struct file *filp, char __user *buffer, size_t len,
			    loff_t *off)
{
	const char *state;
	ssize_t ret;

	down_read(&abac_state_lock);
	state = abac_use_hashmap ? "on\n" : "off\n";
	ret = simple_read_from_buffer(buffer, len, off, state, strlen(state));
	up_read(&abac_state_lock);
	return ret;
}

static ssize_t hashmap_write(struct file *filp, const char __user *buffer,
			     size_t len, loff_t *off)
{
	char state[16];
	int ret = read_control_token(buffer, len, state, sizeof(state));

	if (ret)
		return ret;
	if (strcmp(state, "on") == 0 || strcmp(state, "1") == 0 ||
	    strcmp(state, "enabled") == 0) {
		down_write(&abac_state_lock);
		abac_use_hashmap = true;
		up_write(&abac_state_lock);
		return len;
	}
	if (strcmp(state, "off") == 0 || strcmp(state, "0") == 0 ||
	    strcmp(state, "disabled") == 0) {
		down_write(&abac_state_lock);
		abac_use_hashmap = false;
		up_write(&abac_state_lock);
		return len;
	}
	return -EINVAL;
}

static const struct file_operations hashmap_fops = {
	.open = abac_open,
	.read = hashmap_read,
	.write = hashmap_write,
};

static const struct file_operations include_paths_fops = {
	.open = abac_open,
	.read = include_paths_read,
	.write = include_paths_write,
};

static const struct file_operations exclude_paths_fops = {
	.open = abac_open,
	.read = exclude_paths_read,
	.write = exclude_paths_write,
};

static void destroy_abac_fs(void)
{
	if (policy_file) {
		securityfs_remove(policy_file);
	}
	if (policy_status_file) {
		securityfs_remove(policy_status_file);
	}
	if (user_attr_file) {
		securityfs_remove(user_attr_file);
	}
	if (obj_attr_file) {
		securityfs_remove(obj_attr_file);
	}
	if (env_attr_file) {
		securityfs_remove(env_attr_file);
	}
	if (env_status_file) {
		securityfs_remove(env_status_file);
	}
	if (env_ttl_file) {
		securityfs_remove(env_ttl_file);
	}
	if (action_file) {
		securityfs_remove(action_file);
	}
	if (perf_file) {
		securityfs_remove(perf_file);
	}
	if (stats_file) {
		securityfs_remove(stats_file);
	}
	if (mode_file) {
		securityfs_remove(mode_file);
	}
	if (hashmap_file) {
		securityfs_remove(hashmap_file);
	}
	if (include_paths_file) {
		securityfs_remove(include_paths_file);
	}
	if (exclude_paths_file) {
		securityfs_remove(exclude_paths_file);
	}
	if (abacfs) {
		securityfs_remove(abacfs);
	}
}

/* create the abac filesystem */
static int __init abac_create_fs(void)
{
	// create the root 'abac' directory
	abacfs = securityfs_create_dir("abac", NULL);
	if (!abacfs) {
		printk(KERN_ERR "ABAC LSM: Failed to create abac securityfs "
				"/sys/kernel/security/abac/");
		destroy_abac_fs();
		return -ENOMEM;
	}

	// create the policy file
	policy_file = securityfs_create_file("policy", 0666, abacfs, NULL,
					     &policy_fops);
	if (!policy_file) {
		printk(KERN_ERR
		       "ABAC LSM: Failed to create file /sys/kernel/security/abac/policy");
		destroy_abac_fs();
		return -ENOMEM;
	}
	printk(KERN_INFO
	       "ABAC LSM: Created file /sys/kernel/security/abac/policy");
	policy_status_file = securityfs_create_file("policy_status", 0444,
						    abacfs, NULL,
						    &policy_status_fops);
	if (!policy_status_file) {
		printk(KERN_ERR "ABAC LSM: Failed to create policy_status");
		destroy_abac_fs();
		return -ENOMEM;
	}

	// create the user attributes file
	user_attr_file = securityfs_create_file("user_attr", 0666, abacfs, NULL,
						&user_attr_fops);
	if (!user_attr_file) {
		printk(KERN_ERR
		       "ABAC LSM: Failed to create file /sys/kernel/security/abac/user_attr");
		destroy_abac_fs();
		return -ENOMEM;
	}
	printk(KERN_INFO
	       "ABAC LSM: Created file /sys/kernel/security/abac/user_attr");

	// create the object attributes file
	obj_attr_file = securityfs_create_file("obj_attr", 0666, abacfs, NULL,
					       &obj_attr_fops);
	if (!obj_attr_file) {
		printk(KERN_ERR
		       "ABAC LSM: Failed to create file /sys/kernel/security/abac/obj_attr");
		destroy_abac_fs();
		return -ENOMEM;
	}
	printk(KERN_INFO
	       "ABAC LSM: Created file /sys/kernel/security/abac/obj_attr");

	// create the environment attributes file
	env_attr_file = securityfs_create_file("env_attr", 0666, abacfs, NULL,
					       &env_attr_fops);
	if (!env_attr_file) {
		printk(KERN_ERR
		       "ABAC LSM: Failed to create file /sys/kernel/security/abac/env_attr");
		destroy_abac_fs();
		return -ENOMEM;
	}
	printk(KERN_INFO
	       "ABAC LSM: Created file /sys/kernel/security/abac/env_attr");
	env_status_file = securityfs_create_file("env_status", 0444, abacfs, NULL,
						 &env_status_fops);
	if (!env_status_file) {
		printk(KERN_ERR "ABAC LSM: Failed to create env_status");
		destroy_abac_fs();
		return -ENOMEM;
	}
	env_ttl_file = securityfs_create_file("env_ttl_ms", 0600, abacfs, NULL,
					      &env_ttl_fops);
	if (!env_ttl_file) {
		printk(KERN_ERR "ABAC LSM: Failed to create env_ttl_ms");
		destroy_abac_fs();
		return -ENOMEM;
	}

	action_file = securityfs_create_file("action", 0666, abacfs, NULL,
					     &action_fops);
	if (!action_file) {
		printk(KERN_ERR
		       "ABAC LSM: Failed to create file /sys/kernel/security/abac/action");
		destroy_abac_fs();
		return -ENOMEM;
	}
	printk(KERN_INFO
	       "ABAC LSM: Created file /sys/kernel/security/abac/action");

	perf_file = securityfs_create_file("perf", 0444, abacfs, NULL,
					   &perf_fops);
	if (!perf_file) {
		printk(KERN_ERR
		       "ABAC LSM: Failed to create file /sys/kernel/security/abac/perf");
		destroy_abac_fs();
		return -ENOMEM;
	}
	printk(KERN_INFO
	       "ABAC LSM: Created file /sys/kernel/security/abac/perf");

	stats_file = securityfs_create_file("stats", 0444, abacfs, NULL,
					    &stats_fops);
	if (!stats_file) {
		printk(KERN_ERR
		       "ABAC LSM: Failed to create file /sys/kernel/security/abac/stats");
		destroy_abac_fs();
		return -ENOMEM;
	}
	printk(KERN_INFO
	       "ABAC LSM: Created file /sys/kernel/security/abac/stats");

	mode_file = securityfs_create_file("mode", 0666, abacfs, NULL,
					   &mode_fops);
	if (!mode_file) {
		printk(KERN_ERR
		       "ABAC LSM: Failed to create file /sys/kernel/security/abac/mode");
		destroy_abac_fs();
		return -ENOMEM;
	}
	printk(KERN_INFO
	       "ABAC LSM: Created file /sys/kernel/security/abac/mode");

	hashmap_file = securityfs_create_file("hashmap", 0666, abacfs, NULL,
					      &hashmap_fops);
	if (!hashmap_file) {
		printk(KERN_ERR
		       "ABAC LSM: Failed to create file /sys/kernel/security/abac/hashmap");
		destroy_abac_fs();
		return -ENOMEM;
	}
	printk(KERN_INFO
	       "ABAC LSM: Created file /sys/kernel/security/abac/hashmap");

	include_paths_file = securityfs_create_file("include_paths", 0666, abacfs,
						    NULL, &include_paths_fops);
	if (!include_paths_file) {
		printk(KERN_ERR
		       "ABAC LSM: Failed to create file /sys/kernel/security/abac/include_paths");
		destroy_abac_fs();
		return -ENOMEM;
	}
	printk(KERN_INFO
	       "ABAC LSM: Created file /sys/kernel/security/abac/include_paths");

	exclude_paths_file = securityfs_create_file("exclude_paths", 0666, abacfs,
						    NULL, &exclude_paths_fops);
	if (!exclude_paths_file) {
		printk(KERN_ERR
		       "ABAC LSM: Failed to create file /sys/kernel/security/abac/exclude_paths");
		destroy_abac_fs();
		return -ENOMEM;
	}
	printk(KERN_INFO
	       "ABAC LSM: Created file /sys/kernel/security/abac/exclude_paths");

	abac_reset_perf_stats();
	printk(KERN_INFO "ABAC LSM: Securityfs Initialized");
	return 0;
}

fs_initcall(abac_create_fs);
