#ifndef __ISNS_H__
#define __ISNS_H__

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <ctype.h>
#include <errno.h>
#include <sys/types.h>
#include "queue.h"
#include "isns_sock.h"
#include "isns_pdu.h"
#include "isns_utils.h"
#include "isns_target.h"


/* 
 * iSNS defines	
 */

#define ISNS_SERVER_PORT_DEFAULT 3205
#define ISNS_EID_LENGTH 	 256
#define ISNS_POLL_PERIOD_DEFAULT 60

/*
 * registration state flags
 */
#define ISNS_FLAG_UPDATING 	0x1
#define ISNS_FLAG_CHANGED	0x2
#define ISNS_FLAG_REGISTERED	0x4
#define ISNS_FLAG_REMOVE	0x8
#define ISNS_FLAG_PEER_CHANGED	0x10
#define ISNS_FLAG_IPV6		0x80		/* derived from ISCSI_PORTAL */

#define ISNS_LOG_PATH	       "/etc/chelsio-iscsi/log/isns."
#define ISNS_LOG_PATH_MAX 	sizeof(ISNS_LOG_PATH) + sizeof(pid_t)
/* 
 * msg logging
 */
#define isns_log_error(...)	\
		do { \
			if (t_eid) \
				fprintf(stderr, "chisns %s: ERR! ", t_eid); \
			fprintf(stderr, __VA_ARGS__); \
			fflush(stderr); \
		} while(0)

#define isns_log_msg(...)	\
		do { \
			if (t_eid) \
				fprintf(stdout, "chisns %s: ", t_eid); \
			fprintf(stdout, __VA_ARGS__); \
			fflush(stdout); \
		} while(0)

//#define isns_log_debug        isns_log_msg
#define isns_log_debug(...)

#define isns_log_msg_to_file(...)       \
                if(isns_log) { \
                        fprintf(fp, __VA_ARGS__); \
                        fflush(fp); \
                } while(0)

/* 
 * ipv4 address decode/encode
 */
#define IP_STRING_LENGTH		16	/* xxx.xxx.xxx.xxx */
#define ADDR_IPV4(addr)	\
		((unsigned char *)&addr)[0], \
		((unsigned char *)&addr)[1], \
		((unsigned char *)&addr)[2], \
		((unsigned char *)&addr)[3]

#define ADDR_IPV6(ipv6_addr) \
        ADDR_IPV4(((unsigned int *)&ipv6_addr)[0]), \
        ADDR_IPV4(((unsigned int *)&ipv6_addr)[1]), \
        ADDR_IPV4(((unsigned int *)&ipv6_addr)[2]), \
        ADDR_IPV4(((unsigned int *)&ipv6_addr)[3])

#define FORMAT_IPV6             "%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x"
#define FORMAT_IPV6_PORT        "[" FORMAT_IPV6 "]:%u"
#define FORMAT_IPV4             "%u.%u.%u.%u"
#define FORMAT_IPV4_PORT        FORMAT_IPV4 ":%u"
#define IPV6_OFFSET             3
#define IPV6_PREFIX		"::ffff:"

/* 
 * common data structs
 */

struct portal {
	struct portal *p_next;
	unsigned int p_flag;
	unsigned int p_ip[4];
	unsigned int p_port;
	unsigned int p_tag;
};
#define portal_enqueue(Q,P) ch_enqueue_tail(struct portal,p_next,Q,P)
#define portal_dequeue(Q,P) ch_dequeue_head(struct portal,p_next,Q,P)
#define portal_ch_qremove(Q,P) ch_qremove(struct portal,p_next,Q,P)

#define portal_alloc() 	({ \
		struct portal *__p = malloc(sizeof(struct portal)); \
		if (__p) {  \
			isns_log_debug("portal alloc %p.\n", __p); \
			memset(__p, 0, sizeof(struct portal)); \
		} else { \
			isns_log_error("out of memory (portal).\n"); \
		} \
		__p; })

#define portal_free(p)	\
		do { \
			if (p) { \
				isns_log_debug("portal free %p.\n", p); \
				free(p); \
			} \
		} while (0)

#define portal_dump(p) \
		do { \
			if(!(p->p_ip[0])) { \
				fprintf(stdout, "\t\t\tportal = " FORMAT_IPV4 "(0x%x),port %u, tag %u.\n", \
						ADDR_IPV4((p)->p_ip[3]), (p)->p_ip[3], (p)->p_port, (p)->p_tag); \
				isns_log_msg_to_file("\tportalgroup \t: " FORMAT_IPV4 "\n",ADDR_IPV4((p)->p_ip)); \
			} else {\
                                fprintf(stdout, "\t\t\tportal = " FORMAT_IPV6 "(0x%x%x%x%x),port %u, tag %u.\n", \
                                                ADDR_IPV6((p)->p_ip), (p)->p_ip[0], (p)->p_ip[1], (p)->p_ip[2], (p)->p_ip[3], \
						 (p)->p_port, (p)->p_tag); \
                                isns_log_msg_to_file("\tportalgroup \t: " FORMAT_IPV6 "\n",ADDR_IPV6((p)->p_ip)); \
			} \
			isns_log_msg_to_file("\t\tport \t: %d\n\t\ttag \t: %d\n",(p)->p_port, (p)->p_tag); \
		} while(0)

#define portalq_dump(Q) \
		do { \
			struct portal	*__p; \
			for (__p = (Q)->q_head; __p; __p = __p->p_next) {  \
				portal_dump(__p); \
			} \
		} while(0)

#define portalq_find_by_addr(Q,ip,port) ({ \
		struct portal	*__p;  \
		for (__p = (Q)->q_head; __p; __p = __p->p_next) {  \
			if (!memcmp(__p->p_ip, ip, sizeof(unsigned int) * 4) && __p->p_port == port) break; \
		} \
		__p; })

#define portalq_find_by_ip(Q,ip) ({ \
		struct portal	*__p;  \
		for (__p = (Q)->q_head; __p; __p = __p->p_next) {  \
			if (!memcmp(__p->p_ip, ip, sizeof(unsigned int) * 4)) break; \
		} \
		__p; })

#define portalq_release_all(Q) \
		queue_remove_all(struct portal,p_next,Q,portal_free)

/* used to hold informations about other target/initiator in the same DD */
struct peer {
	struct peer *p_next;
	char    p_name[256];
	unsigned int p_flag;
	queue   p_portalq;
};

#define peer_enqueue(Q,P) ch_enqueue_tail(struct peer,p_next,Q,P)
#define peer_dequeue(Q,P) ch_dequeue_head(struct peer,p_next,Q,P)
#define peer_ch_qremove(Q,P) ch_qremove(struct peer,p_next,Q,P)

#define peerq_find_by_name(Q,name) ({ \
		struct peer	*__p; \
		for (__p = (Q)->q_head; __p; __p = __p->p_next) { \
			if (!(strcmp(name, __p->p_name))) break; \
		}  \
		__p; })

#define peer_alloc()  ({ \
		struct peer	*__p = malloc(sizeof(struct peer)); \
		if (__p) { \
			isns_log_debug("peer alloc %p.\n", __p); \
			memset(__p, 0, sizeof(struct peer)); \
			ch_queue_init(&__p->p_portalq); \
		} else { \
			isns_log_error("out of memory (peer).\n"); \
		}  \
		__p; })

#define peer_free(peer) \
		do { \
			if (peer) { \
				struct portal	*__pp, *__np = NULL; \
				for (__pp = peer->p_portalq.q_head; __pp; __pp = __np) { \
					__np = __pp->p_next; \
					portal_free(__pp); \
				} \
				/* queue	*q = &((peer)->p_portalq);*/ \
				/* portalq_release_all(q); */ \
				isns_log_debug("peer free %p.\n", peer); \
				free(peer); \
				/* peer = NULL; */ \
			} \
		} while(0)

#define peer_dump(p) \
		do { \
			queue	*__q = &(p)->p_portalq; \
			fprintf(stdout, "\t\tpeer %s:\n", (p)->p_name); \
			isns_log_msg_to_file("initiator \t: %s\n",(p)->p_name); \
			portalq_dump(__q); \
		} while(0)

#define peerq_dump(Q) \
		do { \
			struct peer	*__p; \
			for (__p = (Q)->q_head; __p; __p = __p->p_next) {  \
				peer_dump(__p); \
			} \
		} while(0)

#define peerq_release_all(Q) \
		queue_remove_all(struct peer,p_next,Q,peer_free)


#endif /* ifndef __ISNS_H__ */
