/*
	Definitions for Attribute Value Pair (AVP) strctures and methods
	Copyright (C) <2021>  Hariyala Omkara Naga Sai Varshith
*/

#ifndef _ABAC_AVP_H
#define _ABAC_AVP_H

#include <linux/types.h>

typedef struct avp avp;
struct avp {
    char *name;
    char *value;
    avp *next;
};

int findidx(const char *, char, int, int);
int parse_avp(const char *, int, int, avp **out);
int parse_avp_section(const char *, int, int, avp **out);
void destroy_avp_list(avp *head);

#endif /* _ABAC_AVP_H */
