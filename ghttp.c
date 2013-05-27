/*
 * ghttp.c: http server
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

#include <netdb.h>
#include <mysql.h>
#include <stdarg.h>
#include <sys/sendfile.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>
#include <locale.h>
#include <sys/wait.h>

#include "ghttp.h"
#include "cJSON.h"
#include "xlog.h"

typedef struct {
	char db_host[32];
	char db_user[32];
	char db_passwd[32];
	char db_name[32];
} db_info_s;

typedef struct {
	int proc_num;
	int epollfd;
	int listen_sockfd;
	char listen_ip[32];
	char domain[256];
	unsigned short listen_port;
	struct sockaddr_in listen_addr;

	char log_path[256];
	char data_path[256];
	char access_log_path[256];
	g_connection_pt conns;
	int conns_cnt;
	int session_seed;
	int quit;
	int pid;

	char html_template_path[256];
	char static_html_path[256];

	db_info_s db_info;
	MYSQL* db;
} CONFIG;

CONFIG global;
sig_atomic_t handle_sig_alarm = 0;
int send_http_rsp(g_connection_pt conn, int status);
int send_http_wrong_rsp(g_connection_pt conn, int status);
static int set_rlimit(size_t limit);
static int do_work(g_connection_pt conn);
static bool is_complete_http_header();
static void clear_conn(g_connection_pt conn);
int send_302(g_connection_pt conn, char* s302);
int send_static_file(g_connection_pt conn, const char* path);

static int do_listen_recv(g_connection_pt conn);

static int do_client_recv(g_connection_pt conn);
static int do_client_send_header(g_connection_pt conn);
static int do_client_send_body(g_connection_pt conn);
static int do_client_close(g_connection_pt conn);

#if 0
static void sig_handler(int sig) {
	switch (sig) {
		case SIGUSR1:
			break;
		case SIGUSR2:
			break;
		case SIGINT:
			global.quit = 1;
			break;
		default:
			break;
	}
}
#endif
static int get_cpu_num(void) {
	FILE* f = NULL;
	char buf[64];
	int cpu_num = 0;

	const char* cmd = "cat /proc/cpuinfo | grep processor | wc -l";
	memset(buf, 0x00, sizeof(buf));
	f = popen(cmd, "r");
	if (NULL == f) {
		Error("%s(%d): popen(%s) failed. error(%d): %s\n", __FUNCTION__, __LINE__, cmd, errno, strerror(errno));
		return cpu_num;
	}
	if (NULL != fgets(buf, sizeof(buf)-1, f)) {
		cpu_num = atoi(buf);
	}
	if (NULL != f) {
		pclose(f);
		f = NULL;
	}
	Info("%s(%d): the num of cpu: %d\n", __FUNCTION__, __LINE__, cpu_num);
	return cpu_num;
}

static MYSQL* connect_mysql(db_info_s* di) {
	MYSQL* db = NULL;
	char value = 1;

	if (NULL == (db = mysql_init(NULL))) {
		Error("%s(%d): mysql is NULL, mysql_init() failed\n", __FUNCTION__, __LINE__);
		return NULL;
	}
	if (!mysql_real_connect(db, di->db_host, di->db_user, di->db_passwd, di->db_name, 0, NULL, 0)) {
		Error("%s(%d): Couldn't connect to mysql(host:%s,user:%s,passwd:%s,dbname:%s)!\nerror: %s\n",
				__FUNCTION__, __LINE__, di->db_host, di->db_user, di->db_passwd, di->db_name, mysql_error(db));
		mysql_close(db);
		return NULL;
	}
	// set auto-reconnect
	mysql_options(db, MYSQL_OPT_RECONNECT, (char*)&value);

	if (0 != mysql_query(db, "set names utf8")) {
		Error("%s(%d): Query set names gbk failed. error: %s\n", __FUNCTION__, __LINE__, mysql_error(db));
		mysql_close(db);
		return NULL;
	}
	return db;
}

static int init(int argc, char* argv[]) {
	FILE* fp = NULL;
	char line[1024];
	char name[128];
	char value[128];
	char path[256] = {0};
	int cn = 0;
	int pn = 0;

	safe_snprintf(path, sizeof(path)-1, "%s.conf", argv[0]);
	fp = fopen(path, "r");
	if (NULL == fp) {
		printf("%s(%d): fopen(%s) failed. error(%d): %s\n", __FUNCTION__, __LINE__, path, errno, strerror(errno));	
		return -1;
	}
	while (NULL != fgets(line, 1024, fp)) {
		if ('#' == line[0] || 0 == strcmp(line, ""))
			continue;
		memset(name, 0x00, sizeof(name));
		memset(value, 0x00, sizeof(value));

		sscanf(line, "%s %s", name, value);
		if (0 == strcmp(name, "LISTEN"))
			strcpy(global.listen_ip, value);
		else if (0 == strcmp(name, "PORT"))
			global.listen_port = atoi(value);
		else if (0 == strcmp(name, "DOMAIN"))
			strcpy(global.domain, value);
		else if (0 == strcmp(name, "LOG"))
			strcpy(global.log_path, value);
		else if (0 == strcmp(name, "ACCESS_LOG"))
			strcpy(global.access_log_path, value);
		else if (0 == strcmp(name, "PROC_NUM"))
			pn = atoi(value);
		else if (0 == strcmp(name, "DATA"))
			strcpy(global.data_path, value);
		else if (0 == strcmp(name, "DB_HOST"))
			strcpy(global.db_info.db_host, value);
		else if (0 == strcmp(name, "DB_USER"))
			strcpy(global.db_info.db_user, value);
		else if (0 == strcmp(name, "DB_PASSWD"))
			strcpy(global.db_info.db_passwd, value);
		else if (0 == strcmp(name, "DB_NAME"))
			strcpy(global.db_info.db_name, value);
		else 
			continue;
	}
	fclose(fp);

	cn = get_cpu_num();
	global.proc_num = pn > 0 ? (pn > cn ? cn : pn) : cn;
	printf("the cpu count:%d, PROC_NUM:%d, finally, global.proc_num=%d\n", 
			cn, pn, global.proc_num);

	// init log file
	xlog_init(global.log_path);

	safe_snprintf(path, sizeof(path)-1, "%s/isp_ip.txt", global.data_path);
	build_iptree(path);

	// set listen parameter
	global.listen_addr.sin_family = AF_INET;
	global.listen_addr.sin_addr.s_addr = inet_addr(global.listen_ip);
	global.listen_addr.sin_port = htons(global.listen_port);

	set_rlimit(MAX_SOCKET);
	return 0;
}

static int create_tcp_listen(struct sockaddr_in* a) {
	int sockfd = -1;
	int nb = 1;

	sockfd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (-1 == sockfd) {
		Error("%s(%d): socket() failed. error(%d): %s\n", __FUNCTION__, __LINE__, errno, strerror(errno));
		return -1;
	}
	if (ioctl(sockfd, FIONBIO, &nb)) {
		Error("%s(%d): ioctl(FIONBIO) failed. error(%d): %s\n", __FUNCTION__, __LINE__, errno, strerror(errno));
		close(sockfd);
		return -2;
	}
	if (-1 == setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &nb, sizeof(nb))) {
		Error("%s(%d): setsockopt(SO_REUSEADDR) failed. error(%d): %s\n", __FUNCTION__, __LINE__, errno, strerror(errno));
		close(sockfd);
		return -3;
	}
	if (-1 == bind(sockfd, (struct sockaddr*)a, sizeof(struct sockaddr_in))) {
		Error("%s(%d): bind(%s:%hu) failed. error(%d): %s\n", 
				__FUNCTION__, __LINE__, inet_ntoa(a->sin_addr), ntohs(a->sin_port), errno, strerror(errno));
		close(sockfd);
		return -4;
	}
	if (-1 == listen(sockfd, SOMAXCONN)) {
		Error("%s(%d): listen(%d) failed. error(%d): %s\n", __FUNCTION__, __LINE__, SOMAXCONN, errno, strerror(errno));
		close(sockfd);
		return -5;
	}
	return sockfd;
}

static int set_rlimit(size_t limit) {
	//ulimit -n xxxx
	struct rlimit rlim;

	if (getrlimit(RLIMIT_CORE, &rlim) == 0) {
		rlim.rlim_cur = rlim.rlim_max;
		setrlimit(RLIMIT_CORE, &rlim);
	}
	if (getrlimit(RLIMIT_NOFILE, &rlim) < 0) {
		Error("%s(%d): getrlimit() failed. error(%d): %s\n", __FUNCTION__, __LINE__, errno, strerror(errno));
		return -1;
	}
	printf("%s(%d): getrlimit(RLIMIT_NOFILE): max:%lu, cur:%lu\n", __FUNCTION__, __LINE__, rlim.rlim_max, rlim.rlim_cur);
	rlim.rlim_max = rlim.rlim_cur = limit;
	if (setrlimit(RLIMIT_NOFILE, &rlim) < 0)
		Error("%s(%d): setrlimit() failed. error(%d): %s\n", __FUNCTION__, __LINE__, errno, strerror(errno));
	if (0 == getrlimit(RLIMIT_NOFILE, &rlim))
		Info("%s(%d): getrlimit() %lu %lu %d\n", 
				__FUNCTION__, __LINE__, rlim.rlim_max, rlim.rlim_cur, limit);
	return 0;
}

static int timer(void) {
	int i;
	static int sec_time = 0;
	// static int prev_sec = 0;
	static int idx = 0;
	int now = 0;
	g_connection_pt p = NULL;

	now = time(NULL);
	if (now != sec_time) {   
		sec_time = now;
		for (i=0; i<MAX_SOCKET/100; ++i) {
			idx = (idx + 1) % MAX_SOCKET;
			p = &global.conns[idx];
			if (NULL != p->do_timer) {
				p->do_timer(p);
			}
		}
	}
	return 0;
}

static g_connection_pt init_noused(g_connection_pt conns, int socket) {
	extend_free_proc_t free_extend;
	g_connection_pt p = &(conns[socket]);
	if (NULL != p->extend) {
		free_extend = *(extend_free_proc_t*)(p->extend);
		assert(NULL != free_extend);
		free_extend(p->extend);
		p->extend = NULL;
	}
	if (p->sockfd > 0) {
		close(p->sockfd);
		p->sockfd = socket_unused;
	}
	memset(&(p->client_addr), 0x00, sizeof(p->client_addr));
	p->conn_type = conn_type_nouse;
	p->session_id = 0;

	p->up_session_id = 0;
	p->up_sockfd = 0;
	memset(&(p->up_addr), 0x00, sizeof(p->up_addr));

	p->start_at = 0;
	p->active_at = 0;
	p->begin_ms = 0;
	p->access_time[0] = '\0';

	p->bytes_sent = 0;
	p->bytes_recved = 0;

	p->head_bytes_to_send = 0;
	p->body_bytes_to_send = 0;
	p->bytes_to_recv = 0;

	p->recv_buf[0] = '\0';
	p->send_buf[0] = '\0';

	if (NULL != p->body_send_buf) {
		free(p->body_send_buf);
		p->body_send_buf = NULL;
	}

	if (NULL != p->body_recv_buf) {
		free(p->body_recv_buf);
		p->body_recv_buf = NULL;
	}

	if (p->static_file_fd > 0) {
		close(p->static_file_fd);
		p->static_file_fd = -1;
	}
	p->offset = 0;
	p->static_file[0] = '\0';
	if (NULL != p->header) {
		cJSON_Delete(p->header);
		p->header = NULL;
	}
	p->head_length = 0;
	p->content_length = 0;
	p->status = 0;
	p->is_keepalive = 0;
	p->real_ip[0] = '\0';

	p->do_send = NULL;
	p->do_recv = NULL;
	p->do_close = NULL;
	p->do_timer = NULL;
	return p;
}

static void clear_conn(g_connection_pt conn) {
	conn->bytes_sent = 0;
	conn->bytes_recved = 0;
	conn->head_bytes_to_send = 0;
	conn->bytes_to_recv = 0;

	if (NULL != conn->header) {
		cJSON_Delete(conn->header);
		conn->header = NULL;
	}
	conn->head_length = 0;
	conn->content_length = 0;
	conn->status = 0;
	if (NULL != conn->body_send_buf) {
		free(conn->body_send_buf);
		conn->body_send_buf = NULL;
	}
	if (NULL != conn->body_recv_buf) {
		free(conn->body_recv_buf);
		conn->body_recv_buf = NULL;
	}
	if (conn->static_file_fd > 0) {
		close(conn->static_file_fd);
		conn->static_file_fd = -1;
	}
	conn->offset = 0;
	conn->static_file[0] = '\0';

	conn->do_recv = do_client_recv;
	conn->do_close = do_client_close;
	conn->do_timer = NULL;
	conn->do_send = NULL;
	return;
}

static long long now(void) {
	struct timeval tv;

	gettimeofday(&tv, 0);
	return ((long long)tv.tv_sec*1000*1000 + (long long)tv.tv_usec);
}

static g_connection_pt init_listen(g_connection_pt conns, int socket) {
	g_connection_pt p = init_noused(conns, socket);

	p->conn_type = conn_type_listen;
	p->sockfd = socket;
	p->session_id = global.session_seed++;
	p->active_at = p->start_at = now();

	p->do_recv = do_listen_recv;
	return p;
}

static g_connection_pt init_client(g_connection_pt conns, int socket) {
	g_connection_pt p = init_noused(conns, socket);

	p->conn_type = conn_type_client;
	p->sockfd = socket;
	p->session_id = global.session_seed++;
	p->active_at = p->start_at = now();

	p->do_recv = do_client_recv;
	p->do_close = do_client_close;
	return p;
}

#if 0
g_connection_pt init_upstream(g_connection_pt conns, int socket)
{
	g_connection_pt p = init_noused(conns, socket);

	p->conn_type = conn_type_upstream;
	p->sockfd = socket;
	p->session_id = global.session_seed++;
	p->active_at = p->start_at = now();

	p->do_recv = do_upstream_recv_header;
	p->do_close = do_upstream_close;
	return p;
}


g_connection_pt init_upstream_proxy(g_connection_pt conns, int socket)
{
	g_connection_pt p = init_noused(conns, socket);

	p->conn_type = conn_type_upstream_proxy;
	p->sockfd = socket;
	p->session_id = global.session_seed++;
	p->active_at = p->start_at = now();

	p->do_recv = do_upstream_proxy_recv_header;
	p->do_close = do_upstream_proxy_close;
	return p;
}
#endif

static init_func g_init_func[] = {
	&init_noused,
	&init_listen,
	&init_client,
	// &init_upstream,
	// &init_upstream_proxy,
};

static g_connection_pt create_conn(g_connection_pt conns, int socket, conn_type_t type) {
	assert(sizeof(g_init_func)/sizeof(g_init_func[0]) > type);
	global.conns_cnt++;
	return (*(g_init_func[type]))(conns, socket);
}

#if 0
static g_connection_pt take_conn(g_connection_pt conns, int socket, int session) {
	g_connection_pt c = &(conns[socket]);
	if (session == c->session_id)
		return c;
	return NULL;
}
#endif

static void free_conn(g_connection_pt conns, int socket) {
	global.conns_cnt--;
	init_noused(conns, socket);	
}

static bool is_complete_http_header(g_connection_pt conn) {
	cJSON* json = NULL;
	char* ip = NULL;
	char* debug = NULL;

	conn->header = http_parse_request_header(conn->recv_buf, conn->bytes_recved);
	if (NULL == conn->header)
		return false;
	// record real ip
	if (NULL != (json = cJSON_GetObjectItem_EX(conn->header, "client_ip"))) {
		ip = json->valuestring;
		safe_memcpy_0(conn->real_ip, sizeof(conn->real_ip)-1, ip, strlen(ip));
	}
	else if (NULL != (json = cJSON_GetObjectItem_EX(conn->header, "x-forwarded-for"))) {
		ip = json->valuestring;
		safe_memcpy_0(conn->real_ip, sizeof(conn->real_ip)-1, ip, strlen(ip));
	}
	else {
		ip = inet_ntoa(conn->client_addr.sin_addr);
		safe_memcpy_0(conn->real_ip, sizeof(conn->real_ip)-1, ip, strlen(ip));
	}
	json = cJSON_GetObjectItem_EX(conn->header, "Connection");
	if (NULL == json)
		conn->is_keepalive = 0;
	else if (0 == memcmp(json->valuestring, "keep-alive", sizeof("keep-alive")-1))
		conn->is_keepalive = 1;
	else
		conn->is_keepalive = 0;
	debug = cJSON_Print(conn->header);
	Info("%s(%d): \n%s\n", __FUNCTION__, __LINE__, debug);
	free(debug);
	return true;
}

static int do_client_recv(g_connection_pt conn) {
	int ret = 0;
	int left = 0;
	int status = 0;

	assert(conn_type_client == conn->conn_type);

	left = sizeof(conn->recv_buf) - conn->bytes_recved;
	ret = recv(conn->sockfd, conn->recv_buf+conn->bytes_recved, left, 0);
	if (ret < 0) {
		if (EAGAIN == errno || EINTR == errno) {
			Info("%s(%d): recv(%d,%d) not ready\n", __FUNCTION__, __LINE__, conn->sockfd, left);
			return 0;
		}
		Error("%s(%d): recv(%d,%d) failed. error(%d): %s\n", 
				__FUNCTION__, __LINE__, conn->sockfd, left, errno, strerror(errno));
		conn->do_close(conn);
		return -1;
	}
	else if (0 == ret) {
		// peer close
		// Error("%s(%d): recv(%d,%d) return 0, peer closed\n", __FUNCTION__, __LINE__, conn->sockfd, left);
		conn->do_close(conn);
		return -2;
	}
	else {
		// ok get some data
		conn->active_at = now();
		conn->bytes_recved += ret;

		// if a complete http package?
		if (is_complete_http_header(conn)) {
			status = do_work(conn);
			if (status != 200)
				send_http_wrong_rsp(conn, status);
		}
		else if (ret == left) {
			// wrong requst
			Error("%s(%d): recv_buf(%d,%lu) is full, but not find http header ending, illegal request\n", 
					__FUNCTION__, __LINE__, conn->sockfd, sizeof(conn->recv_buf));
			conn->do_close(conn);
		}
	}
	return 0;
}

static int do_client_close(g_connection_pt conn) {
	// Error("%s(%d): close(%d,%d)\n", __FUNCTION__, __LINE__, global.pid, conn->sockfd);
	close(conn->sockfd);
	conn->sockfd = socket_unused;

	conn->head_bytes_to_send = 0;
	conn->body_bytes_to_send = 0;
	conn->bytes_to_recv = 0;
	conn->do_send = NULL;
	conn->do_recv = NULL;
	conn->do_close = NULL;
	return 0;
}

static int do_client_send_body(g_connection_pt conn) {
	int ret = 0;
	unsigned int need_send = 0;
	unsigned int bs = 0;
	ssize_t ssize;

	assert(conn_type_client == conn->conn_type);

	// send static file
	if (NULL == conn->body_send_buf && conn->content_length > 0) {
		need_send = conn->content_length - conn->bytes_sent;
		if (need_send > 0) {
			if (conn->static_file_fd <= 0) {
				conn->static_file_fd = open(conn->static_file, O_RDONLY);
				if (-1 == conn->static_file_fd) {
					Error("%s(%d): open(%s) failed, error(%d):%s\n", 
							__FUNCTION__, __LINE__, conn->static_file, errno, strerror(errno));
					return -1;
				}
			}
			ssize = sendfile(conn->sockfd, conn->static_file_fd, &conn->offset, conn->content_length);
			if (-1 == ssize) {
				if (EAGAIN == errno || EINTR == errno) {
					Info("%s(%d): send(%d,%u) not ready\n", __FUNCTION__, __LINE__, conn->sockfd, need_send);
					return 0;
				}
				conn->do_close(conn);
				return -1;
			}
			else {
				conn->active_at = now();
				conn->bytes_sent = conn->offset;
				if (conn->bytes_sent == conn->content_length) {
					Info("%s(%d): %s+%d, http body is sent\n", 
							__FUNCTION__, __LINE__, conn->access_time, now()/1000 - conn->begin_ms);
					// sent all
					if (conn->is_keepalive) {
						clear_conn(conn);
						conn->ev.events &= ~EPOLLOUT;
						conn->ev.events |= EPOLLIN;
						if (epoll_ctl(global.epollfd, EPOLL_CTL_MOD, conn->sockfd, &(conn->ev)) < 0) {
							Error("%s(%d): epoll_ctl(%d, EPOLL_CTL_MOD, ~EPOLLOUT) failed. error(%d): %s\n", 
									__FUNCTION__, __LINE__, conn->sockfd, errno, strerror(errno));
							conn->do_close(conn);
							return -1;
						}
						/* Error("%s(%d): epoll_ctl(%d,%d, EPOLL_CTL_MOD, &~EPOLLOUT|EPOLLIN)\n",  */
						/* 		__FUNCTION__, __LINE__, global.pid, conn->sockfd); */
					}
					else{
						conn->do_close(conn);
					}
				}
			}
		}
		return 0;
	}

	// send memory buffer
	need_send = conn->content_length - conn->bytes_sent;
	bs = conn->body_bytes_to_send;
	need_send = need_send > bs ? bs : need_send;
	ret = send(conn->sockfd, conn->body_send_buf, need_send, 0);
	if (ret < 0) {
		if (EAGAIN == errno || EINTR == errno) {
			Info("%s(%d): send(%d,%u) not ready\n", __FUNCTION__, __LINE__, conn->sockfd, need_send);
			return 0;
		}
		Error("%s(%d): send(%d,%u) failed. error(%d): %s\n", 
				__FUNCTION__, __LINE__, conn->sockfd, need_send, errno, strerror(errno));
		conn->do_close(conn);
		return -1;
	}
	else {
		// ok get some data
		conn->active_at = now();
		conn->bytes_sent += ret;
		conn->body_bytes_to_send -= ret;
		memmove(conn->body_send_buf, conn->body_send_buf+ret, conn->body_bytes_to_send);
		if (conn->bytes_sent == conn->content_length) {
			Info("%s(%d): %s+%d, http body is sent\n", 
					__FUNCTION__, __LINE__, conn->access_time, now()/1000 - conn->begin_ms);
			// sent all
			if (conn->is_keepalive) {
				clear_conn(conn);
				conn->ev.events &= ~EPOLLOUT;
				conn->ev.events |= EPOLLIN;
				if (epoll_ctl(global.epollfd, EPOLL_CTL_MOD, conn->sockfd, &(conn->ev)) < 0) {
					Error("%s(%d): epoll_ctl(%d, EPOLL_CTL_MOD, ~EPOLLOUT) failed. error(%d): %s\n", 
							__FUNCTION__, __LINE__, conn->sockfd, errno, strerror(errno));
					conn->do_close(conn);
					return -1;
				}
				/* Error("%s(%d): epoll_ctl(%d,%d, EPOLL_CTL_MOD, &~EPOLLOUT|EPOLLIN)\n",  */
				/* 		__FUNCTION__, __LINE__, global.pid, conn->sockfd); */
			}
			else {
				conn->do_close(conn);
			}
		}
	}
	return 0;
}

static int do_client_send_header(g_connection_pt conn)
{
	int ret = 0;
	long long need_send = 0;

	assert(conn_type_client == conn->conn_type);

	need_send = conn->head_bytes_to_send - conn->bytes_sent;
	ret = send(conn->sockfd, conn->send_buf+conn->bytes_sent, need_send, 0);
	if (ret < 0) {
		if (EAGAIN == errno || EINTR == errno) {
			Info("%s(%d): send(%d,%lld) not ready\n", __FUNCTION__, __LINE__, conn->sockfd, need_send);
			return 0;
		}
		Error("%s(%d): send(%d,%lld) failed. error(%d): %s\n", 
				__FUNCTION__, __LINE__, conn->sockfd, need_send, errno, strerror(errno));
		conn->do_close(conn);
		return -1;
	}
	else {
		// ok get some data
		conn->active_at = now();
		conn->bytes_sent += ret;
		if (conn->bytes_sent == conn->head_bytes_to_send) {
			Info("%s(%d): %s+%d, http header is sent\n", 
					__FUNCTION__, __LINE__, conn->access_time, now()/1000 - conn->begin_ms);
			// head over, now body
			conn->bytes_sent = 0;
			conn->do_send = do_client_send_body;
		}
	}
	return 0;
}

static int do_listen_recv(g_connection_pt conn) {
	struct sockaddr_in addr;
	socklen_t addr_len = sizeof(struct sockaddr_in);
	int sockfd = 0;
	int nb = 1;
	g_connection_pt client_conn = NULL;

	assert(conn_type_listen == conn->conn_type);
	sockfd = accept(conn->sockfd, (struct sockaddr*)&addr, &addr_len);	
	if (sockfd < 0) {
		if (EAGAIN == errno || EINTR == errno)
			return 0;
		Error("%s(%d): accept(%d) failed. error(%d): %s\n", 
				__FUNCTION__, __LINE__, global.pid, errno, strerror(errno));
		return -1;
	}
	if (sockfd >= MAX_SOCKET) {
		Error("%s(%d): socket(%d) is bigger than MAX_SOCKET(%d), close it.\n",
				__FUNCTION__, __LINE__, sockfd, MAX_SOCKET);
		close(sockfd);
		return -2;
	}
	fcntl(sockfd, F_SETFD, FD_CLOEXEC);
	if (ioctl(sockfd, FIONBIO, &nb)) {
		Error("%s(%d): ioctl(%d, FIONBIO) failed. error(%d): %s\n",
				__FUNCTION__, __LINE__, sockfd, errno, strerror(errno));
		close(sockfd);
		return -3;
	}
	client_conn = create_conn(global.conns, sockfd, conn_type_client);
	client_conn->ev.data.fd = client_conn->sockfd;
	client_conn->ev.events = EPOLLIN | EPOLLHUP | EPOLLERR;
	if (epoll_ctl(global.epollfd, EPOLL_CTL_ADD, client_conn->sockfd, &(client_conn->ev)) < 0) {
		Error("%s(%d): epoll_ctl(%d, EPOLL_CTL_ADD, EPOLLIN | EPOLLHUP | EPOLLERR) failed. error(%d): %s\n", 
				__FUNCTION__, __LINE__, client_conn->sockfd, errno, strerror(errno));
		close(sockfd);
		return -4;
	}
	memcpy(&client_conn->client_addr, &addr, sizeof(struct sockaddr_in));
	// Error("%s(%d): accept(%d,%d)\n", __FUNCTION__, __LINE__, global.pid, client_conn->sockfd);
	return client_conn->sockfd;
}

static int business_worker(void) {
	struct epoll_event evs[MAX_SOCKET];
	int i = 0, triggered = 0, timeout = 0;
	g_connection_pt conn = NULL;
	g_connection_pt listen_conn = NULL;
	size_t sz = 0;
	static int loop = 0;

	global.pid = getpid();

	// malloc connections
	sz = sizeof(g_connection_t) * MAX_SOCKET;
	global.conns = (g_connection_pt)malloc(sz);
	if (NULL == global.conns) {
		Error("%s(%d): malloc(%lu,%d) failed. error(%d): %s\n", 
				__FUNCTION__, __LINE__, sz, MAX_SOCKET, errno, strerror(errno));	
		return -1;
	}
	global.conns_cnt = 0;
	Info("%s(%d): malloc(%lu) memory for %d connections\n", __FUNCTION__, __LINE__, sz, MAX_SOCKET);

	// epoll
	global.epollfd = epoll_create(MAX_SOCKET);
	if (global.epollfd < 0) {
		Error("%s(%d): epoll_create(%d) failed. error(%d): %s\n", 
				__FUNCTION__, __LINE__, MAX_SOCKET, errno, strerror(errno));
		return -2;
	}
	// listen
	global.listen_addr.sin_family = AF_INET;
	global.listen_addr.sin_addr.s_addr = inet_addr(global.listen_ip);
	global.listen_addr.sin_port = htons(global.listen_port);

	global.listen_sockfd = create_tcp_listen(&(global.listen_addr));
	if (global.listen_sockfd < 0) {
		Error("%s(%d): create_tcp_listen() failed.\n", __FUNCTION__, __LINE__);
		return -3;
	}
	Info("%s(%d): %s:%d is listening...\n", __FUNCTION__, __LINE__, global.listen_ip, global.listen_port);
	listen_conn = create_conn(global.conns, global.listen_sockfd, conn_type_listen);
	listen_conn->ev.data.fd = listen_conn->sockfd;
	listen_conn->ev.events = EPOLLIN | EPOLLHUP | EPOLLERR;
	if (epoll_ctl(global.epollfd, EPOLL_CTL_ADD, listen_conn->sockfd, &(listen_conn->ev)) < 0) {
		Error("%s(%d): epoll_ctl(%d, EPOLL_CTL_ADD, EPOLLHUP | EPOLLERR) failed. error(%d): %s\n", 
				__FUNCTION__, __LINE__, listen_conn->sockfd, errno, strerror(errno));
		return -4;
	}
	// connect to mysql
	global.db = connect_mysql(&global.db_info);

	// main proc
	timeout = 10;
	while (!global.quit) {
		timer();
		loop++;
		if (0 == (loop % 1000)) {
			loop = 0;
			if (0 == mysql_ping(global.db)) {
				mysql_close(global.db);
				global.db = connect_mysql(&global.db_info);
			}
		}
		// loop
		triggered = epoll_wait(global.epollfd, evs, MAX_SOCKET, timeout);
		if (triggered < 0) {
			Error("%s(%d): epoll_wait(%d) failed. error(%d): %s\n", 
					__FUNCTION__, __LINE__, MAX_SOCKET, errno, strerror(errno));
			continue;
		}
		if (0 == triggered)
			continue;
		for (i=0; i<triggered; ++i) {
			conn = &(global.conns[evs[i].data.fd]);
			if (conn_type_nouse == conn->conn_type) {
				free_conn(global.conns, evs[i].data.fd);
				continue;
			}
			if (evs[i].events & (EPOLLERR|EPOLLHUP)) {
				if (NULL == conn->do_close)
					continue;
				conn->do_close(conn);
			}
			if (evs[i].events & EPOLLIN) {
				if (NULL == conn->do_recv)
					continue;
				conn->do_recv(conn);
			}
			if (evs[i].events & EPOLLOUT) {
				if (NULL == conn->do_send)
					continue;
				conn->do_send(conn);
			}
		}
	}
	return 0;
}

int main(int argc, char* argv[]) {
	int ret = 0, i;
	memset(&global, 0x00, sizeof(global));

	/* for nice %b handling in strfime() */
	setlocale(LC_TIME, "C");

	ret = init(argc, argv);
	if (ret < 0) {
		printf("%s(%d): init() failed. return %d\n", __FUNCTION__, __LINE__, ret);
		return -1;
	}

	ret = daemon(1, 1);

	// fork worker proc
	Info("%s(%d): global.proc_num: %d\n", __FUNCTION__, __LINE__, global.proc_num);
	for (i=0; i<global.proc_num; ++i) {
		ret = fork();
		if (ret < 0) {
			// failed
			return -2;
		}
		else if (ret > 0) {
			// parent
			global.listen_port++;
			continue;
		}
		else {
			// child
			business_worker();
			return 0;
		}
	}
	// main proc
	wait(NULL);
	return 0;
}

static void write_access_log(g_connection_pt conn) {
	struct timeval tv;
	struct tm* n;
	char time_now[64] = {0};
	char time_now_hour[64] = {0};
	cJSON* cj = NULL;
	FILE* p = NULL;
	char* client_ip = NULL;
	char* xforward_ip = NULL;
	char* host = NULL;
	char* ua = NULL;
	char* first_line = NULL;
	char path[256] = {0};

	static int a[] = { 
		0,0,0,0,0,5,5,5,5,5,
		10,10,10,10,10,15,15,15,15,15,
		20,20,20,20,20,25,25,25,25,25,
		30,30,30,30,30,35,35,35,35,35,
		40,40,40,40,40,45,45,45,45,45,
		50,50,50,50,50,55,55,55,55,55,
	};
	gettimeofday(&tv, 0);
	n = localtime(&tv.tv_sec);
	strftime(time_now, sizeof(time_now)-1, "%Y%m%d %H:%M:%S", n);
	strftime(time_now_hour, sizeof(time_now_hour)-1, "%Y%m%d_%H", n);
	safe_snprintf(path, sizeof(path)-1, "%s_%s%02d.log", global.access_log_path, time_now_hour, a[n->tm_min]);

	mkdir_r(path);
	p = fopen(path, "a+");
	if (NULL != p) {
		cj = cJSON_GetObjectItem_EX(conn->header, "client_ip");
		if (NULL != cj) {
			client_ip = cj->valuestring;
		}
		cj = cJSON_GetObjectItem_EX(conn->header, "x-forwarded-for");
		if (NULL != cj) {
			xforward_ip = cj->valuestring;
		}
		cj = cJSON_GetObjectItem_EX(conn->header, "Host");
		if (NULL != cj) {
			host = cj->valuestring;
		}
		cj = cJSON_GetObjectItem_EX(conn->header, "User-Agent");
		if (NULL != cj) {
			ua = cJSON_Print(cj);
		}
		cj = cJSON_GetObjectItem_EX(conn->header, "first_line");
		if (NULL != cj) {
			first_line = cj->valuestring;
		}
		fprintf(p, "%s.%03ld - %s %s %s %s %s %s\n", 
				time_now, (tv.tv_usec/1000), 
				conn->real_ip, 
				host ? host : "-", 
				first_line ? first_line : "unknown",
				ua? ua : "\"-\"", 
				client_ip ? client_ip : "-", 
				xforward_ip ? xforward_ip : "-");
		if (ua)
			free(ua);
		fclose(p);
	}
	else
		Error("can't write access log(%s), something is wrong", path);

	int64_t now = (int64_t)tv.tv_sec*1000*1000 + (int64_t)tv.tv_usec;
	conn->begin_ms = (int)(now/1000);
	safe_snprintf(conn->access_time, sizeof(conn->access_time)-1, "%s.%03ld", time_now, (tv.tv_usec/1000));
	return;
}

// User-Define functions
static int on_all_task(g_connection_pt conn);
static int on_set_task(g_connection_pt conn);
static int on_del_task(g_connection_pt conn);

static int do_work(g_connection_pt conn) {
	write_access_log(conn);

	char* cmd = cJSON_GetObjectItem_EX(conn->header, "cmd")->valuestring;
	int n = strlen(cmd);
	if ((n == sizeof("/all_task")-1) && (0 == memcmp(cmd, "/all_task", sizeof("/all_task")-1)))
		on_all_task(conn);
	else if ((n == sizeof("/set_task")-1) && (0 == memcmp(cmd, "/set_task", sizeof("/set_task")-1)))
		on_set_task(conn);
	else if ((n == sizeof("/del_task")-1) && (0 == memcmp(cmd, "/del_task", sizeof("/del_task")-1)))
		on_del_task(conn);
	else
		return 400;
	return 200;
}

static int on_all_task(g_connection_pt conn) {
	MYSQL* db = NULL;
	MYSQL_RES* res = NULL;
	static char sql[10240];
	int row_c = 0;
	MYSQL_ROW row;
	int field_c = 0;
	MYSQL_FIELD* fields;
	int i, j;
	char first_line[256];

	cJSON *root = NULL, *cata = NULL, *cata_item = NULL, *cj = NULL;
	char* out = NULL;
	int out_len = 0;
	int ret_code = 0;
	char* jsonp = NULL;
	int jsonp_len = 0;
	char* jsonp_out = NULL;
	
	cj = cJSON_GetObjectItem_EX(conn->header, "param.kv.jsoncallback");
	if (NULL != cj)
		jsonp = cj->valuestring;

	// create sql
	safe_snprintf(sql, sizeof(sql)-1, "select * from timer_tasks");

	Info("%s(%d): %s\n", __FUNCTION__, __LINE__, sql);
	db = global.db;
	if (0 != mysql_query(db, sql)) {
		Error("%s(%d): Query failed. error: %s\n", __FUNCTION__, __LINE__, mysql_error(db));
		mysql_close(db);
		return -7;
	}
	res = mysql_store_result(db);
	fields = mysql_fetch_fields(res);
	field_c = mysql_num_fields(res);
	row = mysql_fetch_row(res);
	row_c = mysql_num_rows(res);

	// json
	root = cJSON_CreateObject();
	cJSON_AddNumberToObject(root, "ret_code", ret_code);
	cJSON_AddStringToObject(root, "ret_msg", "success");
	cJSON_AddItemToObject(root, "task_list", cata=cJSON_CreateArray());
	for (i=0; i<row_c; ++i) {
		row = mysql_fetch_row(res);
		if (row) {
			cJSON_AddItemToArray(cata, cata_item=cJSON_CreateObject());
			for (j=0; j<field_c; ++j) {
				if (IS_NUM(fields[j].type))
					cJSON_AddNumberToObject(cata_item, fields[j].name, atoi(row[j]));
				else
					cJSON_AddStringToObject(cata_item, fields[j].name, row[j]);
			}
		}
	}
	out = cJSON_PrintUnformatted(root);
	cJSON_Delete(root);
	if (NULL == out) {
		send_http_wrong_rsp(conn, 500);
		return -1;
	}
	// prepare for send rsp
	out_len = strlen(out);
	if (jsonp) {
		jsonp_len = strlen(jsonp);
		conn->content_length = jsonp_len + out_len + 2; // `jsonp(out)`
		jsonp_out = (char*)malloc(conn->content_length + 1);
		safe_snprintf(jsonp_out, conn->content_length + 1, "%s(%s)", jsonp, out);
		conn->body_send_buf = jsonp_out;
		free(out);
		out = NULL;
	}
	else {
		conn->content_length = out_len;
		conn->body_send_buf = out;
	}
	Info("%s(%d): \n%s\n", __FUNCTION__, __LINE__, conn->body_send_buf);
	safe_snprintf(first_line, sizeof(first_line)-1, "HTTP/1.1 %d %s", 200, DESC_200);
	conn->rsp_header = cJSON_CreateObject();
	cJSON_AddStringToObject(conn->rsp_header, "first_line", first_line);
	cJSON_AddStringToObject(conn->rsp_header, "Content-Type", "application/json;charset=UTF-8");
	cJSON_AddStringToObject(conn->rsp_header, "Server", GHTTP_SERVER);
	if (conn->is_keepalive)
		cJSON_AddStringToObject(conn->rsp_header, "Connection", "keep-alive");
	else
		cJSON_AddStringToObject(conn->rsp_header, "Connection", "close");
	cJSON_AddNumberToObject(conn->rsp_header, "Content-Length", conn->content_length);

	send_http_rsp(conn, 200);
	return 0;
}

static int on_set_task(g_connection_pt conn) {
	MYSQL* db = NULL;
	static char sql[10240];
	char first_line[256];

	cJSON *root = NULL, * cj = NULL, *kv = NULL;
	char* out = NULL;
	int out_len = 0;
	int ret_code = 0;
	
	char* mon_title = NULL;
	char* mon_url = NULL;
	char* mon_condition = NULL;
	int mon_period = 86400;
	int mon_lifecycle = 15;
	int user_id = 0;
	int is_finish = 0;
	int task_id = 0;
	char* jsonp = NULL;
	int jsonp_len = 0;
	char* jsonp_out = NULL;

	kv = cJSON_GetObjectItem_EX(conn->header, "param.kv");
	if (NULL == kv) {
		send_http_wrong_rsp(conn, 400);
		return -1;
	}
	cj = cJSON_GetObjectItem_EX(kv, "title");
	if (NULL != cj)
		mon_title = cj->valuestring;
	cj = cJSON_GetObjectItem_EX(kv, "url");
	if (NULL != cj)
		mon_url = cj->valuestring;
	cj = cJSON_GetObjectItem_EX(kv, "condition");
	if (NULL != cj)
		mon_condition = cj->valuestring;
	cj = cJSON_GetObjectItem_EX(kv, "period");
	if (NULL != cj)
		mon_period = atoi(cj->valuestring);
	cj = cJSON_GetObjectItem_EX(kv, "lifecycle");
	if (NULL != cj)
		mon_lifecycle = atoi(cj->valuestring);
	cj = cJSON_GetObjectItem_EX(kv, "jsoncallback");
	if (NULL != cj)
		jsonp = cj->valuestring;

	// json
	root = cJSON_CreateObject();
	
	// create sql
	safe_snprintf(sql, sizeof(sql)-1, "insert into timer_tasks(mon_title, mon_url, mon_condition, mon_period, mon_lifecycle, user_id, is_finish, dt_create, dt_last_update) values('%s', '%s', '%s', %d, %d, %d, %d, now(), now())", 
			mon_title, mon_url, mon_condition, mon_period, mon_lifecycle, user_id, is_finish);

	Info("%s(%d): %s\n", __FUNCTION__, __LINE__, sql);
	db = global.db;
	if (0 != mysql_query(db, sql)) {
		Error("%s(%d): Query failed. error: %s\n", __FUNCTION__, __LINE__, mysql_error(db));
		mysql_close(db);
		task_id = -1;
		cJSON_AddNumberToObject(root, "ret_code", -1);
		cJSON_AddStringToObject(root, "ret_msg", mysql_error(db));
		cJSON_AddNumberToObject(root, "task_id", task_id);
	}
	else {
		task_id = mysql_insert_id(db);
		cJSON_AddNumberToObject(root, "ret_code", ret_code);
		cJSON_AddStringToObject(root, "ret_msg", "success");
		cJSON_AddNumberToObject(root, "task_id", task_id);
	}

	out = cJSON_PrintUnformatted(root);
	cJSON_Delete(root);
	if (NULL == out) {
		send_http_wrong_rsp(conn, 500);
		return -1;
	}
	// prepare for send rsp
	out_len = strlen(out);
	if (jsonp) {
		jsonp_len = strlen(jsonp);
		conn->content_length = jsonp_len + out_len + 2; // `jsonp(out)\0`
		jsonp_out = (char*)malloc(conn->content_length + 1);
		safe_snprintf(jsonp_out, conn->content_length + 1, "%s(%s)", jsonp, out);
		conn->body_send_buf = jsonp_out;
		free(out);
		out = NULL;
	}
	else {
		conn->content_length = out_len;
		conn->body_send_buf = out;
	}
	Info("%s(%d): \n%s\n", __FUNCTION__, __LINE__, conn->body_send_buf);
	safe_snprintf(first_line, sizeof(first_line)-1, "HTTP/1.1 %d %s", 200, DESC_200);
	conn->rsp_header = cJSON_CreateObject();
	cJSON_AddStringToObject(conn->rsp_header, "first_line", first_line);
	cJSON_AddStringToObject(conn->rsp_header, "Content-Type", "application/json;charset=UTF-8");
	cJSON_AddStringToObject(conn->rsp_header, "Server", GHTTP_SERVER);
	if (conn->is_keepalive)
		cJSON_AddStringToObject(conn->rsp_header, "Connection", "keep-alive");
	else
		cJSON_AddStringToObject(conn->rsp_header, "Connection", "close");
	cJSON_AddNumberToObject(conn->rsp_header, "Content-Length", conn->content_length);

	send_http_rsp(conn, 200);
	return 0;
}

static int on_del_task(g_connection_pt conn) {
	MYSQL* db = NULL;
	static char sql[10240];
	char first_line[256];

	cJSON *root = NULL, * cj = NULL, *kv = NULL;
	char* out = NULL;
	int out_len =0;
	int ret_code = 0;
	char* jsonp = NULL;
	int jsonp_len = 0;
	char* jsonp_out = NULL;
	int task_id = 0;
	
	kv = cJSON_GetObjectItem_EX(conn->header, "param.kv");
	if (NULL == kv) {
		send_http_wrong_rsp(conn, 400);
		return -1;
	}
	cj = cJSON_GetObjectItem_EX(kv, "id");
	if (NULL != cj)
		task_id = atoi(cj->valuestring);
	cj = cJSON_GetObjectItem_EX(kv, "jsoncallback");
	if (NULL != cj)
		jsonp = cj->valuestring;

	// json
	root = cJSON_CreateObject();
	// create sql
	safe_snprintf(sql, sizeof(sql)-1, "delete from timer_tasks where id = %d", task_id);

	Info("%s(%d): %s\n", __FUNCTION__, __LINE__, sql);
	db = global.db;
	if (0 != mysql_query(db, sql)) {
		Error("%s(%d): Query failed. error: %s\n", __FUNCTION__, __LINE__, mysql_error(db));
		mysql_close(db);
		task_id = -1;
		cJSON_AddNumberToObject(root, "ret_code", -1);
		cJSON_AddStringToObject(root, "ret_msg", mysql_error(db));
		cJSON_AddNumberToObject(root, "task_id", task_id);
	}
	else {
		cJSON_AddNumberToObject(root, "ret_code", ret_code);
		cJSON_AddStringToObject(root, "ret_msg", "success");
		cJSON_AddNumberToObject(root, "task_id", task_id);
	}
	out = cJSON_PrintUnformatted(root);
	cJSON_Delete(root);
	if (NULL == out) {
		send_http_wrong_rsp(conn, 500);
		return -1;
	}
	// prepare for send rsp
	out_len = strlen(out);
	if (jsonp) {
		jsonp_len = strlen(jsonp);
		conn->content_length = jsonp_len + out_len + 2; // `jsonp(out)`
		jsonp_out = (char*)malloc(conn->content_length + 1);
		safe_snprintf(jsonp_out, conn->content_length + 1, "%s(%s)", jsonp, out);
		conn->body_send_buf = jsonp_out;
		free(out);
		out = NULL;
	}
	else {
		conn->content_length = out_len;
		conn->body_send_buf = out;
	}
	Info("%s(%d): \n%s\n", __FUNCTION__, __LINE__, conn->body_send_buf);
	safe_snprintf(first_line, sizeof(first_line)-1, "HTTP/1.1 %d %s", 200, DESC_200);
	conn->rsp_header = cJSON_CreateObject();
	cJSON_AddStringToObject(conn->rsp_header, "first_line", first_line);
	cJSON_AddStringToObject(conn->rsp_header, "Content-Type", "application/json;charset=UTF-8");
	cJSON_AddStringToObject(conn->rsp_header, "Server", GHTTP_SERVER);
	if (conn->is_keepalive)
		cJSON_AddStringToObject(conn->rsp_header, "Connection", "keep-alive");
	else
		cJSON_AddStringToObject(conn->rsp_header, "Connection", "close");
	cJSON_AddNumberToObject(conn->rsp_header, "Content-Length", conn->content_length);

	send_http_rsp(conn, 200);
	return 0;
}

int send_http_rsp(g_connection_pt conn, int status) {
	if (conn->sockfd < 0)
		return 0;
	dyn_buf buf;

	init_buffer(&buf, 1024);
	http_create_rsponse_header(conn->rsp_header, &buf);
	conn->head_bytes_to_send = get_buffer_len(&buf);
	safe_memcpy(conn->send_buf, sizeof(conn->send_buf), get_buffer(&buf), conn->head_bytes_to_send);
	conn->do_send = do_client_send_header;
	conn->body_bytes_to_send = conn->content_length;
	conn->bytes_sent = 0;
	conn->status = status;
	conn->ev.events |= EPOLLOUT;
	if (epoll_ctl(global.epollfd, EPOLL_CTL_MOD, conn->sockfd, &(conn->ev)) < 0) {
		Error("%s(%d): epoll_ctl(%d, EPOLL_CTL_MOD, EPOLLOUT) failed. error(%d): %s\n", 
				__FUNCTION__, __LINE__, conn->sockfd, errno, strerror(errno));
		conn->do_close(conn);
		return -1;
	}
	return 0;
}

int send_http_wrong_rsp(g_connection_pt conn, int status) {
	if (conn->sockfd < 0)
		return 0;
	dyn_buf buf;
	char first_line[256];
	init_buffer(&buf, 1024);

	char* desc = NULL;
	switch (status) {
		case 200:
			desc = DESC_200;
			break;
		case 206:
			desc = DESC_206;
			break;
		case 302:
			desc = DESC_302;
			break;
		case 304:
			desc = DESC_304;
			break;
		case 400:
			desc = DESC_400;
			break;
		case 403:
			desc = DESC_403;
			break;
		case 404:
			desc = DESC_404;
			break;
		case 408:
			desc = DESC_408;
			break;
		case 500:
			desc = DESC_500;
			break;
		case 501:
			desc = DESC_501;
			break;
		case 503:
			desc = DESC_503;
			break;
		default:
			desc = other_desc;
			break;
	}
	safe_snprintf(first_line, sizeof(first_line)-1, "HTTP/1.1 %d %s", status, desc);
	conn->rsp_header = cJSON_CreateObject();
	cJSON_AddStringToObject(conn->rsp_header, "first_line", first_line);
	cJSON_AddStringToObject(conn->rsp_header, "Content-Type", "text/plain;charset=UTF-8");
	cJSON_AddStringToObject(conn->rsp_header, "Server", GHTTP_SERVER);
	if (conn->is_keepalive)
		cJSON_AddStringToObject(conn->rsp_header, "Connection", "keep-alive");
	else
		cJSON_AddStringToObject(conn->rsp_header, "Connection", "close");
	conn->content_length = 0;
	http_create_rsponse_header(conn->rsp_header, &buf);
	conn->head_bytes_to_send = get_buffer_len(&buf);
	safe_memcpy(conn->send_buf, sizeof(conn->send_buf), get_buffer(&buf), conn->head_bytes_to_send);
	conn->do_send = do_client_send_header;
	conn->body_bytes_to_send = conn->content_length;
	conn->bytes_sent = 0;
	conn->status = status;
	conn->ev.events |= EPOLLOUT;
	if (epoll_ctl(global.epollfd, EPOLL_CTL_MOD, conn->sockfd, &(conn->ev)) < 0) {
		Error("%s(%d): epoll_ctl(%d, EPOLL_CTL_MOD, EPOLLOUT) failed. error(%d): %s\n", 
				__FUNCTION__, __LINE__, conn->sockfd, errno, strerror(errno));
		conn->do_close(conn);
		return -1;
	}
	return 0;
}

int send_html_rsp(g_connection_pt conn, int status, const char* content_type)
{
	if (conn->sockfd < 0)
		return 0;
	conn->do_send = do_client_send_header;
	conn->body_bytes_to_send = conn->content_length;
	conn->bytes_sent = 0;
	conn->status = status;
	conn->ev.events |= EPOLLOUT;
	if (epoll_ctl(global.epollfd, EPOLL_CTL_MOD, conn->sockfd, &(conn->ev)) < 0)
	{
		Error("%s(%d): epoll_ctl(%d, EPOLL_CTL_MOD, EPOLLOUT) failed. error(%d): %s\n", 
				__FUNCTION__, __LINE__, conn->sockfd, errno, strerror(errno));
		conn->do_close(conn);
		return -1;
	}
	return 0;
}


int send_302(g_connection_pt conn, char* s302)
{
	Info("%s(%d): play url:\n%s\n", __FUNCTION__, __LINE__, s302);
	if (conn->sockfd < 0)
		return 0;
	conn->do_send = do_client_send_header;
	conn->body_bytes_to_send = conn->content_length;
	conn->bytes_sent = 0;
	conn->status = 302;
	conn->ev.events |= EPOLLOUT;
	if (epoll_ctl(global.epollfd, EPOLL_CTL_MOD, conn->sockfd, &(conn->ev)) < 0)
	{
		Error("%s(%d): epoll_ctl(%d, EPOLL_CTL_MOD, EPOLLOUT) failed. error(%d): %s\n", 
				__FUNCTION__, __LINE__, conn->sockfd, errno, strerror(errno));
		conn->do_close(conn);
		return -1;
	}
	return 0;
}
