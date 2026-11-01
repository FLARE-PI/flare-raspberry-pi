/*
	Definitions for ABAC Policy structures and methods
	Copyright (C) <2021>  Hariyala Omkara Naga Sai Varshith
*/

#ifndef _ABAC_POLICY_H
#define _ABAC_POLICY_H

#include <linux/types.h>
#include "avp.h"

/* Supported modes of object access */
enum abac_op { ABAC_READ, ABAC_MODIFY, ABAC_IGNORE };
enum abac_effect { ABAC_ALLOW, ABAC_DENY };

typedef struct abac_rule abac_rule;
struct abac_rule {
    avp *user;
    avp *object;
    avp *env;
    enum abac_op op;
    enum abac_effect effect;
    abac_rule *next;
    int id;
};

struct abac_policy_tree;

typedef struct {
    abac_rule *rules;
    struct abac_policy_tree *tree;
    int count;
} abac_policy;

char *abac_op_str(enum abac_op);
char *abac_effect_str(enum abac_effect);
enum abac_op convert_to_abac_op(int);
int parse_policy(const char *, int, abac_policy **out);
void print_abac_policy(abac_policy *);
void destroy_policy(abac_policy *);

struct abac_policy_tree *build_policy_tree(abac_rule *rules);
void destroy_policy_tree(struct abac_policy_tree *tree);
bool resolve_policy_tree(struct abac_policy_tree *tree, avp *uattr, avp *oattr,
                         avp *env, enum abac_op op);

#endif /* _ABAC_POLICY_H */
