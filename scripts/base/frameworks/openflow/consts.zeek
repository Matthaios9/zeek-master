




module OpenFlow;



const COOKIE_BID_SIZE = 16777216;

const COOKIE_BID_START = 1099511627776;

const ZEEK_COOKIE_ID = 4;

const COOKIE_GID_SIZE = 256;

const COOKIE_GID_START = 4294967296;

const COOKIE_UID_SIZE = 4294967296;

const COOKIE_UID_START = 0;

export {





	const ETH_IPv4 = 0x0800;

	const ETH_ARP = 0x0806;

	const ETH_WOL = 0x0842;

	const ETH_RARP = 0x8035;

	const ETH_APPLETALK = 0x809B;

	const ETH_APPLETALK_ARP = 0x80F3;

	const ETH_VLAN = 0x8100;

	const ETH_IPX_OLD = 0x8137;

	const ETH_IPX = 0x8138;

	const ETH_IPv6 = 0x86DD;

	const ETH_ETHER_FLOW_CONTROL = 0x8808;

	const ETH_MPLS_UNICAST = 0x8847;

	const ETH_MPLS_MULTICAST = 0x8848;

	const ETH_PPPOE_DISCOVERY = 0x8863;

	const ETH_PPPOE_SESSION = 0x8864;

	const ETH_JUMBO_FRAMES = 0x8870;

	const ETH_EAP_OVER_LAN = 0x888E;

	const ETH_PROVIDER_BRIDING = 0x88A8;

	const ETH_MAC_SECURITY = 0x88E5;

	const ETH_QINQ = 0x9100;






	const IP_HOPOPT = 0x00;

	const IP_ICMP = 0x01;

	const IP_IGMP = 0x02;

	const IP_GGP = 0x03;

	const IP_IPIP = 0x04;

	const IP_ST = 0x05;

	const IP_TCP = 0x06;

	const IP_CBT = 0x07;

	const IP_EGP = 0x08;


	const IP_IGP = 0x09;

	const IP_UDP = 0x11;

	const IP_RDP = 0x1B;

	const IP_IPv6 = 0x29;

	const IP_RSVP = 0x2E;

	const IP_GRE = 0x2F;

	const IP_OSPF = 0x59;

	const IP_MTP = 0x5C;



	const IP_ETHERIP = 0x61;

	const IP_L2TP = 0x73;

	const IP_ISIS = 0x7C;

	const IP_FC = 0x85;

	const IP_MPLS = 0x89;





	const INVALID_COOKIE = 0x7fffffffffffffff;




	const OFPP_IN_PORT = 0xfffffff8;



	const OFPP_TABLE = 0xfffffff9;

	const OFPP_NORMAL = 0xfffffffa;


	const OFPP_FLOOD = 0xfffffffb;

	const OFPP_ALL = 0xfffffffc;

	const OFPP_CONTROLLER = 0xfffffffd;

	const OFPP_LOCAL = 0xfffffffe;

	const OFPP_ANY = 0xffffffff;

	const OFP_NO_BUFFER = 0xffffffff;


	const OFPFF_SEND_FLOW_REM = 0x1;

	const OFPFF_CHECK_OVERLAP = 0x2;



	const OFPFF_EMERG = 0x4;



	const OFPTT_ALL = 0xff;






	type ofp_action_type: enum {

		OFPAT_OUTPUT = 0x0000,

		OFPAT_SET_VLAN_VID = 0x0001,

		OFPAT_SET_VLAN_PCP = 0x0002,

		OFPAT_STRIP_VLAN = 0x0003,

		OFPAT_SET_DL_SRC = 0x0004,

		OFPAT_SET_DL_DST = 0x0005,

		OFPAT_SET_NW_SRC = 0x0006,

		OFPAT_SET_NW_DST = 0x0007,

		OFPAT_SET_NW_TOS = 0x0008,

		OFPAT_SET_TP_SRC = 0x0009,

		OFPAT_SET_TP_DST = 0x000a,

		OFPAT_ENQUEUE = 0x000b,

		OFPAT_VENDOR = 0xffff,
	};





	type ofp_flow_mod_command: enum {

		OFPFC_ADD = 0x0,

		OFPFC_MODIFY = 0x1,

		OFPFC_MODIFY_STRICT = 0x2,

		OFPFC_DELETE = 0x3,

		OFPFC_DELETE_STRICT = 0x4,
	};




	type ofp_config_flags: enum {

		OFPC_FRAG_NORMAL = 0,

		OFPC_FRAG_DROP = 1,

		OFPC_FRAG_REASM = 2,
		OFPC_FRAG_MASK = 3,
	};

}
