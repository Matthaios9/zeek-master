// arpa/nameser.h
// Copyright (c) 2022/10/19 Noah Treuhaft <noah@brimdata.io>
// License open source MIT

#ifndef arpa_nameser_h
#define arpa_nameser_h

#include <stdlib.h>

#define NS_PACKETSZ  512
#define NS_MAXDNAME  1025
#define NS_MAXMSG    65535
#define NS_MAXCDNAME 255
#define NS_MAXLABEL  63
#define NS_HFIXEDSZ  12
#define NS_QFIXEDSZ  4
#define NS_RRFIXEDSZ 10
#define NS_INT32SZ   4
#define NS_INT16SZ   2
#define NS_INADDRSZ  4
#define NS_IN6ADDRSZ 16

#define HFIXEDSZ NS_HFIXEDSZ
#define QFIXEDSZ NS_QFIXEDSZ
#define RRFIXEDSZ NS_RRFIXEDSZ

#define T_A    1
#define T_PTR  12
#define T_TXT  16
#define T_AAAA 28

#define ns_o_query 0

#define ns_r_noerror  0
#define ns_r_formerr  1
#define ns_r_servfail 2
#define ns_r_nxdomain 3
#define ns_r_notimpl  4
#define ns_r_refused  5

typedef void ns_rr;

#define ns_rr_type(rr)	0
#define ns_rr_ttl(rr)	0
#define ns_rr_rdlen(rr)	0
#define ns_rr_rdata(rr)	0

typedef void ns_msg;

#define ns_msg_id(handle) 0
#define ns_msg_count(handle, section) 0
#define ns_msg_getflag(handle, flag) 0

typedef struct
{	int id;
} HEADER;

#define ns_initparse(a, b, c) (-1)
#define ns_parserr(a, b, c, d) (-1)

// Available NS request types
#define ns_t_invalid  0   /* Cookie. */
#define ns_t_a        1   /* Host address. */
#define ns_t_ns       2   /* Authoritative server. */
#define ns_t_md       3   /* Mail destination. */
#define ns_t_mf       4   /* Mail forwarder. */
#define ns_t_cname    5   /* Canonical name. */
#define ns_t_soa      6   /* Start of authority zone. */
#define ns_t_mb       7   /* Mailbox domain name. */
#define ns_t_mg       8   /* Mail group member. */
#define ns_t_mr       9   /* Mail rename name. */
#define ns_t_null     10  /* Null resource record. */
#define ns_t_wks      11  /* Well known service. */
#define ns_t_ptr      12  /* Domain name pointer. */
#define ns_t_hinfo    13  /* Host information. */
#define ns_t_minfo    14  /* Mailbox information. */
#define ns_t_mx       15  /* Mail routing information. */
#define ns_t_txt      16  /* Text strings. */
#define ns_t_rp       17  /* Responsible person. */
#define ns_t_afsdb    18  /* AFS cell database. */
#define ns_t_x25      19  /* X_25 calling address. */
#define ns_t_isdn     20  /* ISDN calling address. */
#define ns_t_rt       21  /* Router. */
#define ns_t_nsap     22  /* NSAP address. */
#define ns_t_nsap_ptr 23  /* Reverse NSAP lookup (deprecated). */
#define ns_t_sig      24  /* Security signature. */
#define ns_t_key      25  /* Security key. */
#define ns_t_px       26  /* X.400 mail mapping. */
#define ns_t_gpos     27  /* Geographical position (withdrawn). */
#define ns_t_aaaa     28  /* Ip6 Address. */
#define ns_t_loc      29  /* Location Information. */
#define ns_t_nxt      30  /* Next domain (security). */
#define ns_t_eid      31  /* Endpoint identifier. */
#define ns_t_nimloc   32  /* Nimrod Locator. */
#define ns_t_srv      33  /* Server Selection. */
#define ns_t_atma     34  /* ATM Address */
#define ns_t_naptr    35  /* Naming Authority PoinTeR */
#define ns_t_kx       36  /* Key Exchange */
#define ns_t_cert     37  /* Certification record */
#define ns_t_a6       38  /* IPv6 address (deprecates AAAA) */
#define ns_t_dname    39  /* Non-terminal DNAME (for IPv6) */
#define ns_t_sink     40  /* Kitchen sink (experimental) */
#define ns_t_opt      41  /* EDNS0 option (meta-RR) */
#define ns_t_apl      42  /* Address prefix list (RFC3123) */
#define ns_t_ds       43  /* Delegation Signer (RFC4034) */
#define ns_t_sshfp    44  /* SSH Key Fingerprint (RFC4255) */
#define ns_t_rrsig    46  /* Resource Record Signature (RFC4034) */
#define ns_t_nsec     47  /* Next Secure (RFC4034) */
#define ns_t_dnskey   48  /* DNS Public Key (RFC4034) */
#define ns_t_nsec3    50  /* Negative security type 3 */
#define ns_t_nsec3param 51 /* Negative security type 3 parameters */
#define ns_t_hip      55  /* Host Identity Protocol */
#define ns_t_spf      99  /* Sender Policy Framework */
#define ns_t_tkey     249 /* Transaction key */
#define ns_t_tsig     250 /* Transaction signature. */
#define ns_t_ixfr     251 /* Incremental zone transfer. */
#define ns_t_axfr     252 /* Transfer zone of authority. */
#define ns_t_mailb    253 /* Transfer mailbox records. */
#define ns_t_maila    254 /* Transfer mail agent records. */
#define ns_t_any      255 /* Wildcard match. */
#define ns_t_uri      256 /* Uniform Resource Identifier (RFC7553) */
#define ns_t_caa      257 /* Certification Authority Authorization. */
#define ns_t_dlv      32769 /* DNSSEC look-aside validatation. */

#endif
