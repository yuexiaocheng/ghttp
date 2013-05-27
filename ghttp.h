/*
 * ghttp.h: http server defines
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

#ifndef __GHTTP_H_2012_06_26_
#define __GHTTP_H_2012_06_26_

#ifdef __cplusplus
extern "C"
{
#endif

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <sys/shm.h>
#include <openssl/sha.h>
#include <openssl/md5.h>
#include <unistd.h>
#include <time.h>
#include <sys/vfs.h>
#include <strings.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <dirent.h>
#include <iconv.h>
#include <sys/msg.h>
#include <assert.h>
#include <sys/epoll.h>
#include <sys/resource.h>
#include <string.h>
#include <signal.h>
#include <sys/time.h>
#include <stdbool.h>
#include "http_protocol.h"
#include "iplib.h"
#pragma pack(1)

typedef enum
{
	conn_type_nouse = 0,
	conn_type_listen,
	conn_type_client,
	conn_type_upstream,
	conn_type_upstream_proxy,
} conn_type_t;

enum
{
	socket_unused = -1,
};

#define GHTTP_VERSION "1.0.0"

#define MAX_SOCKET (10*1000)

#define header_recv_buf_size (4*1024)
#define header_send_buf_size (4*1024)
#define max_body_send_buf_size (1024*1024)
#define max_body_recv_buf_size (1024*1024)

typedef struct tag_g_connection_t
{
	// extend
	void* extend;

	// routine
	int conn_type;
	int session_id;
	int sockfd;
	struct sockaddr_in client_addr;

	// epoll
	struct epoll_event ev;
	
	// for upstream
	int up_session_id;
	int up_sockfd;
	struct sockaddr_in up_addr;

	// timestamp
	long long start_at;
	long long active_at;
	int begin_ms;
	char access_time[32]; // 20120704 16:35:00.297

	// buffer bytes
	unsigned int bytes_sent;
	unsigned int bytes_recved;

	unsigned int head_bytes_to_send;
	unsigned int body_bytes_to_send;
	unsigned int bytes_to_recv;

	// buffer for header part
	char recv_buf[header_recv_buf_size];
	char send_buf[header_send_buf_size];

	// buffer for body part
	char* body_recv_buf;
	char* body_send_buf;
	char static_file[256];
	off_t offset;
	int static_file_fd;

	// http protocol part
	cJSON* header;
	cJSON* rsp_header;
	int head_length;
	unsigned int content_length;
	int status;
	bool is_keepalive;
	char real_ip[32];

	// callback function
	int (*do_send)(struct tag_g_connection_t* conn);
	int (*do_recv)(struct tag_g_connection_t* conn);
	int (*do_close)(struct tag_g_connection_t* conn);
	void (*do_timer)(struct tag_g_connection_t* conn);
} g_connection_t;

typedef g_connection_t* g_connection_pt;

typedef void (*extend_free_proc_t)(void*);

typedef g_connection_pt (*init_func)(g_connection_pt conns, int socket);

// INTERFACEs

#pragma pack()

#ifdef __cplusplus
}
#endif

#endif // __GHTTP_H_2012_06_26_
