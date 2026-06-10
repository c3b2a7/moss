#include <libproc.h>
#include <netinet/in.h>
#include <netinet/in_pcb.h>
#include <netinet/tcp_fsm.h>
#include <netinet/tcp_var.h>
#include <netinet/udp_var.h>
#include <sys/proc_info.h>
#include <sys/socketvar.h>
#include <sys/un.h>
#include <sys/unpcb.h>

struct moss_xunpcb64_list_entry {
    u_int64_t le_next;
    u_int64_t le_prev;
} __attribute__((packed, aligned(4)));

struct moss_xunpcb64 {
    u_int32_t xu_len;
    u_int64_t xu_unpp;
    struct moss_xunpcb64_list_entry xunp_link;
    u_int64_t xunp_socket;
    u_int64_t xunp_vnode;
    u_int64_t xunp_ino;
    u_int64_t xunp_conn;
    u_int64_t xunp_refs;
    struct moss_xunpcb64_list_entry xunp_reflink;
    int xunp_cc;
    int xunp_mbcnt;
    u_quad_t xunp_gencnt;
    int xunp_flags;
    union {
        struct sockaddr_un xuu_addr;
        char xu_dummy1[256];
    } xu_au;
    union {
        struct sockaddr_un xuu_caddr;
        char xu_dummy2[256];
    } xu_cau;
    struct xsocket64 xu_socket;
} __attribute__((packed, aligned(4)));
