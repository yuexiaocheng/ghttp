/*
 * iplib.h: ip lib defines
 *
 * Copyright (C) 2013  linkedshell<www.linkedshell.com>
 *
 * Created:
 * Yue Xiaocheng <yuexiaocheng@gmail.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, version 2 of the License.
 */

#ifndef __IP_LIB_H_2013_01_04_
#define __IP_LIB_H_2013_01_04_

#ifdef __cplusplus
extern "C"
{
#endif

struct acl_node
{
	struct acl_node* left;
	struct acl_node* right;
	int isp_id;
};

struct acl_node g_tree;

typedef struct 
{
	int id;
	char name[128];
} isp;

typedef struct
{
	char ip[32];
	int mask;
	int id;
} isp_ip;

enum
{
	UNKNOWN_ISPID = 800615,
};

int build_iptree(const char* file);
int find_ispid(char* ip, int* ispid);

#ifdef __cplusplus
}
#endif

#endif // __IP_LIB_H_2013_01_04_
