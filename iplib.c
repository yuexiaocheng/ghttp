/*
 * iplib.c: ip lib
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
#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include "iplib.h"

#if 0
static void print_iptree(struct acl_node* node)
{
	int center = 60;
	int location = 0;
	int i;
	static int deep = 0;
	if (NULL == node)
		return;
	if (node == &g_tree)
		location = center;
	else
	{
		if (0 == deep % 2)
			location = center - deep;
		else
			location = center + deep;
		deep++;
	}
	for (i=0; i<location; ++i)
		printf(" ");
	if (0 == strlen(node->netType))
		printf("o\n");
	else
		printf("%s\n", node->netType);
	print_tree(node->left);
	print_tree(node->right);
	return;
}
#endif

static void free_treenode(struct acl_node* node)
{
	if (NULL == node)
		return;
	free_treenode(node->left);
	free_treenode(node->right);
	if (node != &g_tree)
		free(node);
	return;
}


static void free_iptree()
{
	free_treenode(&g_tree);
	memset(&g_tree, 0x00, sizeof(g_tree));
	return;
}


int build_iptree(const char* file)
{
	FILE* f = NULL;
	char* line = NULL;
	size_t len = 0;
	ssize_t read = 0;
	isp_ip one;
	struct acl_node* item = NULL;
	long lip = 0;
	int i = 0;

	f = fopen(file, "r");
	if (NULL == f)
		return -1;
	free_iptree();
	while ((read = getline(&line, &len, f)) != -1) 
	{
		memset(&one, 0x00, sizeof(one));
		// printf("%s", line);
		sscanf(line, "%[^'/']/%d %d", one.ip, &(one.mask), &(one.id));
		item = &g_tree;
		lip = ntohl(inet_addr(one.ip));
		for (i=31; i>=(int)(32-one.mask); --i)
		{
			if (0 == (lip & (1<<i)))
			{
				if (NULL == item->left)
				{
					item->left = (struct acl_node*)malloc(sizeof(struct acl_node));;
					if (NULL != item->left)
					{
						memset(item->left, 0x00, sizeof(struct acl_node));
					}
					else
					{
						printf("%s(%d): no memory to malloc %d", 
							   __FUNCTION__, __LINE__, (int)sizeof(struct acl_node));
						return -2;
					}
				}
				item = item->left;
			}
			else
			{
				if (NULL == item->right)
				{
					item->right = (struct acl_node*)malloc(sizeof(struct acl_node));;
					if (NULL != item->right)
					{
						memset(item->right, 0x00, sizeof(struct acl_node));
					}
					else
					{
						printf("%s(%d): no memory to malloc %d", 
							   __FUNCTION__, __LINE__, (int)sizeof(struct acl_node));
						return -2;
					}
				}
				item = item->right;
			}
		}
		item->isp_id = one.id;
		// printf("%s(%d): item(%p): left=%p, right=%p, ispid=%d", 
		//		__FUNCTION__, __LINE__, item, item->left, item->right, item->isp_id);
	}
	if (line)
		free(line);
	fclose(f);
	f = NULL;
	// print_tree(&g_tree);
	return 0;
}


int find_ispid(char* ip, int* ispid)
{
	int i;
	struct acl_node* item = &g_tree, *lastitem = NULL;
	long lip = ntohl(inet_addr(ip));

	for (i=31; i>=0; --i)
	{
		if (0 == (lip & (1<<i)))
		{
			if (0 != item->isp_id)
				lastitem = item;
			if (NULL == item->left)
				break;
			item = item->left;
		}
		else
		{
			if (0 != item->isp_id)
				lastitem = item;
			if (NULL == item->right)
				break;
			item = item->right;
		}
		if (NULL == item->left && NULL == item->right)
		{
			*ispid = item->isp_id;
			return *ispid;
		}
	}
	if (NULL != lastitem)
		*ispid = lastitem->isp_id;
	else
		*ispid = UNKNOWN_ISPID;
	return *ispid;
}

