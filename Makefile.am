AUTOMAKE_OPTIONS=foreign
INCLUDES=-I./ -I/usr/include/mysql

EXTRA_DIST = config.h.in config.h

bin_PROGRAMS=ghttp
ghttp_SOURCES=ghttp.c \
			  http_protocol.c \
			  iplib.c \
			  xlog.c \
			  cJSON.c \
			  dyn_buf.c

ghttp_LDFLAGS=-L./ -L/usr/lib64/mysql/
ghttp_LDADD= -lmysqlclient -lm -lz -lssl

CFLAGS=-Wall -Wpointer-arith -Wno-unused-parameter -Werror -g -Wunreachable-code -finline-functions  

include_HEADERS = ghttp.h \
				  http_protocol.h \
				  iplib.h  \
				  xlog.h \
				  cJSON.h \
				  dyn_buf.h

EXTRA_DIST += ghttp.conf
