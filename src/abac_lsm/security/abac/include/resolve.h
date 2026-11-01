/*
	Definitions for ABAC Resolution methods
	Copyright (C) <2021>  Hariyala Omkara Naga Sai Varshith
*/

#ifndef _ABAC_RESOLVE_H
#define _ABAC_RESOLVE_H

#include <linux/types.h>
#include "policy.h"

bool abac_resolve(unsigned int, char *, int);
bool abac_resolve_linear(unsigned int, char *, int);
bool abac_resolve_tree(unsigned int, char *, int);
bool abac_resolve_resource(unsigned int uid, const char *resource_id,
			   enum abac_op op);
bool abac_resource_is_managed(const char *resource_id);
void abac_rebuild_lookup_maps(void);
void abac_destroy_lookup_maps(void);

#endif /* _ABAC_RESOLVE_H */
