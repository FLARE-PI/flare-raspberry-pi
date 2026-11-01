/*
	Definitions for ABAC Object Attribute structures and methods
	Copyright (C) <2021>  Hariyala Omkara Naga Sai Varshith
*/

#ifndef _ABAC_OBJ_H
#define _ABAC_OBJ_H

#include "avp.h"
#include <linux/limits.h>
#include <linux/list.h>

typedef struct abac_obj abac_obj;
struct abac_obj {
    char path[PATH_MAX];
    avp *attrs;
    struct hlist_node hnode;
    abac_obj *next;
};

int parse_obj_attr(const char *, int, abac_obj **out);
void print_obj_attrs(abac_obj *);
void destroy_obj_list(abac_obj *);

#endif /* _ABAC_OBJ_H */
