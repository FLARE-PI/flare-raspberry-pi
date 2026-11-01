/*
	Definitions for ABAC Environmental Attribute parsing methods
	Copyright (C) <2021>  Hariyala Omkara Naga Sai Varshith
*/

#ifndef _ABAC_ENV_H
#define _ABAC_ENV_H
#include "avp.h"

int parse_env_attr(const char *, int, avp **out);
void print_env_attrs(avp *);
bool abac_env_attr_equal(const avp *left, const avp *right);

#endif /* _ABAC_ENV_H */
