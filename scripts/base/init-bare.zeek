@load base/bif/const.bif
@load base/bif/types.bif









type string_array: table[count] of string;






type string_any_table: table[string] of any;






type string_set: set[string];






type subnet_set: set[subnet];






type addr_set: set[addr];






type count_set: set[count];






type index_vec: vector of count;






type int_vec: vector of int;






type double_vec: vector of double;






type subnet_vec: vector of subnet;







type any_vec: vector of any;






type string_vec: vector of string;






type x509_opaque_vector: vector of opaque of x509;






type addr_vec: vector of addr;






type table_string_of_string: table[string] of string;






type table_string_of_count: table[string] of count;






type files_tag_set: set[Files::Tag];






type interval_set: set[interval];






type string_mapper: function(s: string): string;





type mime_match: record {
	strength: int;


	mime:     string;
};





type mime_matches: vector of mime_match;


type PacketSource: record {

	live: bool;


	path: string;

	link_type: int;

	netmask: count;
};











const packet_source_inactivity_timeout = 100msec &redef;













const allow_network_time_forward = T &redef;



type transport_proto: enum {
	unknown_transport,
	tcp,
	udp,
	icmp
};








type conn_id_ctx: record { };










type conn_id: record {
	orig_h: addr &log;
	orig_p: port &log;
	resp_h: addr &log;
	resp_p: port &log;
	proto: count &default=65535;
	ctx: conn_id_ctx &log &default=conn_id_ctx();
};






type flow_id : record {
	src_h: addr;
	src_p: port;
	dst_h: addr;
	dst_p: port;
} &log;






type icmp_info: record {
	v6: bool;
	itype: count;
	icode: count;
	len: count;
	ttl: count;
};





type icmp_context: record {
	id: conn_id;
	len: count;
	proto: count;
	frag_offset: count;




	bad_hdr_len: bool;
	bad_checksum: bool;
	MF: bool;
	DF: bool;
};





type icmp6_nd_prefix_info: record {

	prefix_len: count;

	L_flag: bool;

	A_flag: bool;


	valid_lifetime: interval;



	preferred_lifetime: interval;


	prefix: addr;
};







type icmp6_nd_option: record {

	otype:        count;


	len:          count;


	link_address: string &optional;

	prefix:       icmp6_nd_prefix_info &optional;


	redirect:     icmp_context &optional;

	mtu:          count &optional;




	payload:      string &optional;
};


type icmp6_nd_options: vector of icmp6_nd_option;



type icmp6_mldv2_group_type: enum {
	MLDV2_MODE_IS_INCLUDE        = 1,
	MLDV2_MODE_IS_EXCLUDE        = 2,
	MLDV2_CHANGE_TO_INCLUDE_MODE = 3,
	MLDV2_CHANGE_TO_EXCLUDE_MODE = 4,
	MLDV2_ALLOW_NEW_SOURCES      = 5,
	MLDV2_BLOCK_OLD_SOURCES      = 6
};



type icmp6_mldv2_mar: record {

	group_type:     icmp6_mldv2_group_type;

	aux_data_len:   count;

	num_sources:    count;

	multicast_addr: addr;

	sources:        addr_vec;

	aux_data:       string &optional;
};

type icmp6_mldv2_mar_vec: vector of icmp6_mldv2_mar;






type dns_mapping: record {


	creation_time: time;


	req_host: string;


	req_addr: addr;


	valid: bool;


	hostname: string;


	addrs: addr_set;
};






type ftp_port: record {
	h: addr;
	p: port;
	valid: bool;
};




type endpoint_stats: record {
	num_pkts: count;
	num_rxmit: count;
	num_rxmit_bytes: count;
	num_in_order: count;
	num_OO: count;
	num_repl: count;




	endian_type: count;
};




type PluginComponent: record {
	name: string;
	canonical_name: string;
	tag: string;
	enabled: bool;
};

type plugin_component_vec : vector of PluginComponent;











const zeek_script_args: vector of string = vector();


const cmd_line_bpf_filter = "" &redef;


const log_rotate_base_time = "0:00" &redef;





const detect_filtered_trace = F &redef;






const report_gaps_for_partial = F &redef;








const exit_only_after_terminate = F &redef;











const packet_filter_default = F &redef;


const sig_max_group_size = 50 &redef;


const peer_description = "zeek" &redef;










const dpd_reassemble_first_packets = T &redef;











const dpd_buffer_size = 1024 &redef;











const dpd_max_packets = 100 &redef;









const dpd_match_only_beginning = T &redef;











const dpd_late_match_stop = F &redef;






const dpd_ignore_ports = F &redef;




const likely_server_ports: set[port] &redef;




const trace_output_file = "";








const record_all_packets = F &redef;








const ignore_keep_alive_rexmit = F &redef;






const global_hash_seed: string = "" &redef;




const bits_per_uid: count = 96 &redef;







const digest_salt = "Please change this value." &redef;



const max_find_all_string_length: int = 10000 &redef;












const io_poll_interval_default = 100 &redef;














const io_poll_interval_live = 10 &redef;



const running_under_test: bool = F &redef;



const netbios_ssn_session_timeout: interval = 15 sec &redef;

module EventMetadata;

export {

	type ID: enum {
		NETWORK_TIMESTAMP = 1,
	};


	type Entry: record {
		id: EventMetadata::ID;
		val: any;
	};








	const add_network_timestamp: bool = F &redef;









	const add_missing_remote_network_timestamp: bool = F &redef;
}

module ConnKey;

export {







	const factory = ConnKey::CONNKEY_FIVETUPLE &redef;
}

module FTP;

export {


	const max_command_length = 100 &redef;
}

module SMTP;

export {



	const bdat_max_line_length = 4096 &redef;







	const enable_rfc822_msg_file_analysis = F &redef;
}

module TCP;

export {

	type Option: record {


		kind: count;


		length: count;



		data: string &optional;

		mss: count &optional;

		window_scale: count &optional;



		sack: index_vec &optional;

		send_timestamp: count &optional;

		echo_timestamp: count &optional;

		rate: count &optional;
		ttl_diff: count &optional;
		qs_nonce: count &optional;
	};


	type OptionList: vector of Option;


	type RawOption: record {

		kind: count;

		data: string;
	};


	type RawOptionList: vector of RawOption;
}

module Tunnel;

export {

	type EncapsulatingConn: record {





		cid: conn_id;

		tunnel_type: Tunnel::Type;


		uid: string &optional;
	} &log;





	const max_changes_per_connection: count = 5 &redef;



	const max_depth: count = 4 &redef;






	const delay_teredo_confirmation = T &redef;








	const delay_gtp_confirmation = F &redef;



	const ip_tunnel_timeout = 24hrs &redef;





	const validate_vxlan_checksums = T &redef;

}

module HTTP;

export {




	const upgrade_analyzers: table[string] of Analyzer::Tag &redef;
}

module WebSocket;

export {





	const payload_chunk_size = 8192 &redef;





	const max_control_frame_size = 125 &redef;


	const use_dpd_default = T &redef;





	const use_spicy_analyzer = F &redef;





	type AnalyzerConfig: record {



		analyzer: Analyzer::Tag &optional;




		use_dpd: bool &default=use_dpd_default;


		subprotocol: string &optional;


		server_extensions: vector of string &optional;
	};
}

module GLOBAL;







type EncapsulatingConnVector: vector of Tunnel::EncapsulatingConn;


type event_metadata_vec: vector of EventMetadata::Entry;







































type endpoint: record {
	size: count;





	state: count;


	num_pkts: count &optional;


	num_bytes_ip: count &optional;


	flow_label: count;

	l2_addr: string &optional;
};




































type connection: record {
	id: conn_id;
	orig: endpoint;
	resp: endpoint;
	start_time: time;



	duration: interval;







	service: set[string] &ordered;
	history: string;




	uid: string;





	tunnel: EncapsulatingConnVector &optional;


	vlan: int &optional;


	inner_vlan: int &optional;
};



option default_file_timeout_interval: interval = 2 mins;




option default_file_bof_buffer_size: count = 4096;






type fa_file: record {

	id: string;



	parent_id: string &optional;






	source: string;



	is_orig: bool &optional;


	conns: table[conn_id] of connection &optional;


	last_active: time;


	seen_bytes: count &default=0;


	total_bytes: count &optional;



	missing_bytes: count &default=0;





	overflow_bytes: count &default=0;



	timeout_interval: interval &default=default_file_timeout_interval;



	bof_buffer_size: count &default=default_file_bof_buffer_size;



	bof_buffer: string &optional;
} &redef;






type string_any_file_hook: hook(f: fa_file, e: any, str: string);


type fa_metadata: record {

	mime_type: string &optional;

	mime_types: mime_matches &optional;


	inferred: bool &default=T;
};





type AnalyzerConfirmationInfo: record {





	c: connection &optional;


	f: fa_file &optional;



	aid: count &optional;
};




type AnalyzerViolationInfo: record {

	reason: string;






	c: connection &optional;


	f: fa_file &optional;



	aid: count &optional;


	data: string &optional;
};








const max_analyzer_violations = 1000 &redef;




type SYN_packet: record {
	is_orig: bool;
	DF: bool;
	ttl: count;
	size: count;
	win_size: count;
	win_scale: int;
	MSS: count;
	SACK_OK: bool;
	TSval: count &optional;
	TSecr: count &optional;
};




type NetStats: record {
	pkts_recvd:    count &default=0;
	pkts_dropped:  count &default=0;





	pkts_link:     count &default=0;
	bytes_recvd:   count &default=0;
	pkts_filtered: count &optional;
};

type ConnStats: record {
	total_conns: count;
	current_conns: count;
	sess_current_conns: count;

	num_packets: count;
	num_fragments: count;
	max_fragments: count;

	num_tcp_conns: count;
	max_tcp_conns: count;
	cumulative_tcp_conns: count;

	num_udp_conns: count;
	max_udp_conns: count;
	cumulative_udp_conns: count;

	num_icmp_conns: count;
	max_icmp_conns: count;
	cumulative_icmp_conns: count;
	num_packets_unprocessed: count;

	killed_by_inactivity: count;
};







type ProcStats: record {
	debug: bool;
	start_time: time;
	real_time: interval;
	user_time: interval;
	system_time: interval;
	mem: count;
	minor_faults: count;
	major_faults: count;
	num_swap: count;
	blocking_input: count;
	blocking_output: count;
	num_context: count;
};

type EventStats: record {
	queued:     count;
	dispatched: count;
};




type ReassemblerStats: record {
	file_size:    count;
	frag_size:    count;
	tcp_size:     count;
	unknown_size: count;
};




type MatcherStats: record {
	matchers: count;
	nfa_states: count;
	dfa_states: count;
	computed: count;
	mem: count;
	hits: count;
	misses: count;
};




type TimerStats: record {
	current:    count;
	max:        count;
	cumulative: count;
};




type FileAnalysisStats: record {
	current:    count;
	max:        count;
	cumulative: count;
};






type DNSStats: record {
	requests:         count;
	successful:       count;
	failed:           count;
	pending:          count;
	cached_hosts:     count;
	cached_addresses: count;
	cached_texts:     count;
	cached_total:     count;
};




type GapStats: record {
	ack_events: count;
	ack_bytes: count;
	gap_events: count;
	gap_bytes: count;
};




type ThreadStats: record {
	num_threads: count;
};




type BrokerStats: record {
	num_peers: count;

	num_stores: count;

	num_pending_queries: count;

	num_events_incoming: count;

	num_events_outgoing: count;

	num_logs_incoming: count;

	num_logs_outgoing: count;

	num_ids_incoming: count;

	num_ids_outgoing: count;
};



type BrokerPeeringStats: record {

	num_queued: count;


	max_queued_recently: count;

	num_overflows: count;
};

type BrokerPeeringStatsTable: table[string] of BrokerPeeringStats;




type ReporterStats: record {

	weirds: count;


	weirds_by_type:	table[string] of count;
};




type EventNameCounter: record {

	name: string &log;

	times_called: count &log;
} &log;

type EventNameStats: vector of EventNameCounter;






type var_sizes: table[string] of count;


type script_id_attr: record {
    name: string;
    expr: string &optional;
};

type script_id_attrs: vector of script_id_attr;




type script_id: record {
	type_name: string;
	exported: bool;
	constant: bool;
	enum_constant: bool;
	option_value: bool;
	redefinable: bool;
	broker_backend: bool;
	value: any &optional;
	attributes: script_id_attrs &optional;
};









type id_table: table[string] of script_id;




type record_field: record {
	type_name: string;
	log: bool;


	value: any &optional;
	default_val: any &optional;
	optional: bool;
};









type record_field_table: table[string] of record_field;




type call_argument: record {
	name: string;
	type_name: string;
	default_val: any &optional;




	value: any &optional;
};




type call_argument_vector: vector of call_argument;




type BacktraceElement: record {

	function_name: string;

	function_args: call_argument_vector;

	file_location: string &optional;

	line_location: count &optional;
};




type Backtrace: vector of BacktraceElement;
















type assertion_failure: hook(cond: string, msg: string, bt: Backtrace);





















type assertion_result: hook(result: bool, cond: string, msg: string, bt: Backtrace);















global capture_filters: table[string] of string &redef;






global restrict_filters: table[string] of string &redef;



type PcapFilterID: enum { None };


type IPAddrAnonymization: enum {
	KEEP_ORIG_ADDR,
	SEQUENTIALLY_NUMBERED,
	PREFIX_PRESERVING_A50,
	RANDOM_MD5 &deprecated="Remove in v9.1. Use the A50 or SHA256 anonymizers instead.",
	PREFIX_PRESERVING_MD5 &deprecated="Remove in v9.1. Use the A50 or SHA256 anonymizers instead.",
	RANDOM_SHA256,
	PREFIX_PRESERVING_SHA256,
};


type IPAddrAnonymizationClass: enum {
	ORIG_ADDR,
	RESP_ADDR,
	OTHER_ADDR,
};


type rotate_info: record {
	old_name: string;
	new_name: string;
	open: time;
	close: time;
};












type sw_params: record {

	min_strlen: count &default = 3;


	sw_variant: count &default = 0;
};




type sw_align: record {
	str: string;
	index: count;
};




type sw_align_vec: vector of sw_align;





type sw_substring: record {
	str: string;
	aligns: sw_align_vec;
	new: bool;
};








type sw_substring_vec: vector of sw_substring;






type pcap_packet: record {
	ts_sec: count;
	ts_usec: count;
	caplen: count;
	len: count;
	data: string;
	link_type: link_encap;
};




type geo_location: record {
	country_code: string &optional;
	region: string &optional;
	city: string &optional;
	latitude: double &optional;
	longitude: double &optional;
} &log;




type geo_autonomous_system: record {
	number: count &optional;
	organization: string &optional;
} &log;


const mmdb_dir: string = "" &redef;


const mmdb_city_db: string = "GeoLite2-City.mmdb" &redef;

const mmdb_country_db: string = "GeoLite2-Country.mmdb" &redef;

const mmdb_asn_db: string = "GeoLite2-ASN.mmdb" &redef;






const mmdb_dir_fallbacks: vector of string = vector(
	"/usr/share/GeoIP",
	"/var/lib/GeoIP",
	"/usr/local/share/GeoIP",
	"/usr/local/var/GeoIP",
) &redef;




const mmdb_stale_check_interval: interval = 5min &redef;







type entropy_test_result: record {
	entropy: double;
	chi_square: double;
	mean: double;
	monte_carlo_pi: double;
	serial_correlation: double;
};


function from_json_default_key_mapper(s: string): string
	{
	return s;
	}




type from_json_result: record {
	v: any &optional;
	valid: bool;
	err: string &optional;
};



const TCP_INACTIVE = 0;
const TCP_SYN_SENT = 1;
const TCP_SYN_ACK_SENT = 2;
const TCP_PARTIAL = 3;
const TCP_ESTABLISHED = 4;
const TCP_CLOSED = 5;
const TCP_RESET = 6;



const UDP_INACTIVE = 0;
const UDP_ACTIVE = 1;












const ignore_checksums = F &redef;






option ignore_checksums_nets: set[subnet] = set();



const partial_connection_ok = T &redef;



const tcp_SYN_ack_ok = T &redef;




const tcp_match_undelivered = T &redef;


const tcp_SYN_timeout = 5 secs &redef;



const tcp_session_timer = 6 secs &redef;




const tcp_connection_linger = 5 secs &redef;



const tcp_attempt_delay = 5 secs &redef;


const tcp_close_delay = 5 secs &redef;


const tcp_reset_delay = 5 secs &redef;




const tcp_partial_close_delay = 3 secs &redef;





const non_analyzed_lifetime = 0 secs &redef;





const tcp_inactivity_timeout = 5 min &redef;





const udp_inactivity_timeout = 1 min &redef;





const icmp_inactivity_timeout = 1 min &redef;





const unknown_ip_inactivity_timeout = 1 min &redef;








type connection_timing_out: hook(c: connection);






const tcp_storm_thresh = 1000 &redef;





const tcp_storm_interarrival_thresh = 1 sec &redef;






const tcp_max_initial_window = 16384 &redef;







const tcp_max_above_hole_without_any_acks = 16384 &redef;








const tcp_excessive_data_without_further_acks = 10 * 1024 * 1024 &redef;




const tcp_max_old_segments = 0 &redef;








const tcp_content_delivery_ports_orig: table[port] of bool = {} &redef;








const tcp_content_delivery_ports_resp: table[port] of bool = {} &redef;








const tcp_content_deliver_all_orig = F &redef;









const tcp_content_deliver_all_resp = F &redef;










const udp_content_delivery_ports_orig: table[port] of bool = {} &redef;









const udp_content_delivery_ports_resp: table[port] of bool = {} &redef;










option udp_content_ports: set[port] = {};





option udp_content_delivery_ports_use_resp = F;










const udp_content_deliver_all_orig = F &redef;










const udp_content_deliver_all_resp = F &redef;




const table_expire_interval = 10 secs &redef;





const table_incremental_step = 5000 &redef;





const table_expire_delay = 0.01 secs &redef;


const dns_session_timeout = 10 sec &redef;


const rpc_timeout = 24 sec &redef;








const rpc_max_pending_calls = 1000 &redef;



const frag_timeout = 5 min &redef;




const use_conn_size_analyzer = T &redef;


const ENDIAN_UNKNOWN = 0;
const ENDIAN_LITTLE = 1;
const ENDIAN_BIG = 2;
const ENDIAN_CONFUSED = 3;



const CONTENTS_NONE = 0;
const CONTENTS_ORIG = 1;
const CONTENTS_RESP = 2;
const CONTENTS_BOTH = 3;





const ICMP_UNREACH_NET = 0;
const ICMP_UNREACH_HOST = 1;
const ICMP_UNREACH_PROTOCOL = 2;
const ICMP_UNREACH_PORT = 3;
const ICMP_UNREACH_NEEDFRAG = 4;
const ICMP_UNREACH_ADMIN_PROHIB = 13;




const IPPROTO_IP = 0;
const IPPROTO_ICMP = 1;
const IPPROTO_IGMP = 2;
const IPPROTO_IPIP = 4;
const IPPROTO_TCP = 6;
const IPPROTO_UDP = 17;
const IPPROTO_IPV6 = 41;
const IPPROTO_ICMPV6 = 58;
const IPPROTO_RAW = 255;


const IPPROTO_HOPOPTS = 0;
const IPPROTO_ROUTING = 43;
const IPPROTO_FRAGMENT = 44;
const IPPROTO_ESP = 50;
const IPPROTO_AH = 51;
const IPPROTO_NONE = 59;
const IPPROTO_DSTOPTS = 60;
const IPPROTO_MOBILITY = 135;





type ip6_option: record {
	otype: count;
	len: count;
	data: string;
};


type ip6_options: vector of ip6_option;




type ip6_hopopts: record {


	nxt: count;

	len: count;

	options: ip6_options;
};




type ip6_dstopts: record {


	nxt: count;

	len: count;

	options: ip6_options;
};




type ip6_routing: record {


	nxt: count;

	len: count;

	rtype: count;

	segleft: count;

	data: string;
};




type ip6_fragment: record {


	nxt: count;

	rsv1: count;

	offset: count;

	rsv2: count;

	more: bool;

	id: count;
};




type ip6_ah: record {


	nxt: count;

	len: count;

	rsv: count;

	spi: count;

	seq: count &optional;

	data: string &optional;
};




type ip6_esp: record {

	spi: count;

	seq: count;
};




type ip6_mobility_brr: record {

	rsv: count;

	options: vector of ip6_option;
};




type ip6_mobility_hoti: record {

	rsv: count;

	cookie: count;

	options: vector of ip6_option;
};




type ip6_mobility_coti: record {

	rsv: count;

	cookie: count;

	options: vector of ip6_option;
};




type ip6_mobility_hot: record {

	nonce_idx: count;

	cookie: count;

	token: count;

	options: vector of ip6_option;
};




type ip6_mobility_cot: record {

	nonce_idx: count;

	cookie: count;

	token: count;

	options: vector of ip6_option;
};




type ip6_mobility_bu: record {

	seq: count;

	a: bool;

	h: bool;

	l: bool;

	k: bool;

	life: count;

	options: vector of ip6_option;
};




type ip6_mobility_back: record {

	status: count;

	k: bool;

	seq: count;

	life: count;

	options: vector of ip6_option;
};




type ip6_mobility_be: record {

	status: count;

	hoa: addr;

	options: vector of ip6_option;
};




type ip6_mobility_msg: record {

	id: count;

	brr: ip6_mobility_brr &optional;

	hoti: ip6_mobility_hoti &optional;

	coti: ip6_mobility_coti &optional;

	hot: ip6_mobility_hot &optional;

	cot: ip6_mobility_cot &optional;

	bu: ip6_mobility_bu &optional;

	back: ip6_mobility_back &optional;

	be: ip6_mobility_be &optional;
};




type ip6_mobility_hdr: record {


	nxt: count;

	len: count;

	mh_type: count;

	rsv: count;

	chksum: count;

	msg: ip6_mobility_msg;
};





type ip6_ext_hdr: record {


	id: count;

	hopopts: ip6_hopopts &optional;

	dstopts: ip6_dstopts &optional;

	routing: ip6_routing &optional;

	fragment: ip6_fragment &optional;

	ah: ip6_ah &optional;

	esp: ip6_esp &optional;

	mobility: ip6_mobility_hdr &optional;
};


type ip6_ext_hdr_chain: vector of ip6_ext_hdr;





type ip6_hdr: record {
	class: count;
	flow: count;
	len: count;
	nxt: count;


	hlim: count;
	src: addr;
	dst: addr;
	exts: ip6_ext_hdr_chain;
};




type ip4_hdr: record {
	hl: count;
	tos: count;
	len: count;
	id: count;
	DF: bool;
	MF: bool;
	offset: count;
	ttl: count;
	p: count;
	sum: count;
	src: addr;
	dst: addr;
};




const TH_FIN = 1;
const TH_SYN = 2;
const TH_RST = 4;
const TH_PUSH = 8;
const TH_ACK = 16;
const TH_URG = 32;
const TH_FLAGS = 63;




type tcp_hdr: record {
	sport: port;
	dport: port;
	seq: count;
	ack: count;
	hl: count;
	dl: count;
	reserved: count;
	flags: count;
	win: count;
};




type udp_hdr: record {
	sport: port;
	dport: port;
	ulen: count;
};




type icmp_hdr: record {
	icmp_type: count;
};




type pkt_hdr: record {
	ip: ip4_hdr &optional;
	ip6: ip6_hdr &optional;
	tcp: tcp_hdr &optional;
	udp: udp_hdr &optional;
	icmp: icmp_hdr &optional;
};




type l2_hdr: record {
	encap: link_encap;
	len: count;
	cap_len: count;
	src: string &optional;
	dst: string &optional;
	vlan: count &optional;
	vlan_pcp: count &optional;
	vlan_dei: bool &optional;
	inner_vlan: count &optional;
	inner_vlan_pcp: count &optional;
	inner_vlan_dei: bool &optional;
	eth_type: count &optional;
	proto: layer3_proto;
};





type raw_pkt_hdr: record {
	l2: l2_hdr;
	ip: ip4_hdr &optional;
	ip6: ip6_hdr &optional;
	tcp: tcp_hdr &optional;
	udp: udp_hdr &optional;
	icmp: icmp_hdr &optional;
};






type teredo_auth: record {
	id:      string;
	value:   string;


	nonce:   count;

	confirm: count;

};






type teredo_origin: record {
	p: port;
	a: addr;
};





type teredo_hdr: record {
	auth:   teredo_auth &optional;
	origin: teredo_origin &optional;
	hdr:    pkt_hdr;
};


type gtpv1_hdr: record {

	version:   count;

	pt_flag:   bool;

	rsv:       bool;



	e_flag:    bool;



	s_flag:    bool;



	pn_flag:   bool;

	msg_type:  count;


	length:    count;


	teid:      count;


	seq:       count &optional;

	n_pdu:     count &optional;


	next_type: count &optional;
};

type gtp_cause: count;
type gtp_imsi: count;
type gtp_teardown_ind: bool;
type gtp_nsapi: count;
type gtp_recovery: count;
type gtp_teid1: count;
type gtp_teid_control_plane: count;
type gtp_charging_id: count;
type gtp_charging_gateway_addr: addr;
type gtp_trace_reference: count;
type gtp_trace_type: count;
type gtp_tft: string;
type gtp_trigger_id: string;
type gtp_omc_id: string;
type gtp_reordering_required: bool;
type gtp_proto_config_options: string;
type gtp_charging_characteristics: count;
type gtp_selection_mode: count;
type gtp_access_point_name: string;
type gtp_msisdn: string;

type gtp_gsn_addr: record {



	ip: addr &optional;

	other: string &optional;
};

type gtp_end_user_addr: record {
	pdp_type_org: count;
	pdp_type_num: count;

	pdp_ip: addr &optional;

	pdp_other_addr: string &optional;
};

type gtp_rai: record {
	mcc: count;
	mnc: count;
	lac: count;
	rac: count;
};

type gtp_qos_profile: record {
	priority: count;
	data: string;
};

type gtp_private_extension: record {
	id: count;
	value: string;
};

type gtp_create_pdp_ctx_request_elements: record {
	imsi:             gtp_imsi &optional;
	rai:              gtp_rai &optional;
	recovery:         gtp_recovery &optional;
	select_mode:      gtp_selection_mode &optional;
	data1:            gtp_teid1;
	cp:               gtp_teid_control_plane &optional;
	nsapi:            gtp_nsapi;
	linked_nsapi:     gtp_nsapi &optional;
	charge_character: gtp_charging_characteristics &optional;
	trace_ref:        gtp_trace_reference &optional;
	trace_type:       gtp_trace_type &optional;
	end_user_addr:    gtp_end_user_addr &optional;
	ap_name:          gtp_access_point_name &optional;
	opts:             gtp_proto_config_options &optional;
	signal_addr:      gtp_gsn_addr;
	user_addr:        gtp_gsn_addr;
	msisdn:           gtp_msisdn &optional;
	qos_prof:         gtp_qos_profile;
	tft:              gtp_tft &optional;
	trigger_id:       gtp_trigger_id &optional;
	omc_id:           gtp_omc_id &optional;
	ext:              gtp_private_extension &optional;
};

type gtp_create_pdp_ctx_response_elements: record {
	cause:          gtp_cause;
	reorder_req:    gtp_reordering_required &optional;
	recovery:       gtp_recovery &optional;
	data1:          gtp_teid1 &optional;
	cp:             gtp_teid_control_plane &optional;
	charging_id:    gtp_charging_id &optional;
	end_user_addr:  gtp_end_user_addr &optional;
	opts:           gtp_proto_config_options &optional;
	cp_addr:        gtp_gsn_addr &optional;
	user_addr:      gtp_gsn_addr &optional;
	qos_prof:       gtp_qos_profile &optional;
	charge_gateway: gtp_charging_gateway_addr &optional;
	ext:            gtp_private_extension &optional;
};

type gtp_update_pdp_ctx_request_elements: record {
	imsi:          gtp_imsi &optional;
	rai:           gtp_rai &optional;
	recovery:      gtp_recovery &optional;
	data1:         gtp_teid1;
	cp:            gtp_teid_control_plane &optional;
	nsapi:         gtp_nsapi;
	trace_ref:     gtp_trace_reference &optional;
	trace_type:    gtp_trace_type &optional;
	cp_addr:       gtp_gsn_addr;
	user_addr:     gtp_gsn_addr;
	qos_prof:      gtp_qos_profile;
	tft:           gtp_tft &optional;
	trigger_id:    gtp_trigger_id &optional;
	omc_id:        gtp_omc_id &optional;
	ext:           gtp_private_extension &optional;
	end_user_addr: gtp_end_user_addr &optional;
};

type gtp_update_pdp_ctx_response_elements: record {
	cause:          gtp_cause;
	recovery:       gtp_recovery &optional;
	data1:          gtp_teid1 &optional;
	cp:             gtp_teid_control_plane &optional;
	charging_id:    gtp_charging_id &optional;
	cp_addr:        gtp_gsn_addr &optional;
	user_addr:      gtp_gsn_addr &optional;
	qos_prof:       gtp_qos_profile &optional;
	charge_gateway: gtp_charging_gateway_addr &optional;
	ext:            gtp_private_extension &optional;
};

type gtp_delete_pdp_ctx_request_elements: record {
	teardown_ind: gtp_teardown_ind &optional;
	nsapi:        gtp_nsapi;
	ext:          gtp_private_extension &optional;
};

type gtp_delete_pdp_ctx_response_elements: record {
	cause: gtp_cause;
	ext:   gtp_private_extension &optional;
};


@load base/bif/zeek.bif
@load base/bif/communityid.bif
@load base/bif/stats.bif
@load base/bif/reporter.bif
@load base/bif/strings.bif
@load base/bif/option.bif
@load base/frameworks/supervisor/api
@load base/bif/supervisor.bif
@load base/bif/packet_analysis.bif
@load base/bif/CPP-load.bif
@load base/bif/mmdb.bif


function add_interface(iold: string, inew: string): string
	{
	if ( iold == "" )
		return inew;
	else
		return fmt("%s %s", iold, inew);
	}



global interfaces = "" &add_func = add_interface;


function add_signature_file(sold: string, snew: string): string
	{
	if ( sold == "" )
		return snew;
	else
		return cat(sold, " ", snew);
	}





global signature_files = "" &add_func = add_signature_file;




global secondary_filters: table[string] of event(filter: string, pkt: pkt_hdr)
	&redef;





global discarder_maxlen = 128 &redef;















global discarder_check_ip: function(p: pkt_hdr): bool;

















global discarder_check_tcp: function(p: pkt_hdr, d: string): bool;

















global discarder_check_udp: function(p: pkt_hdr, d: string): bool;















global discarder_check_icmp: function(p: pkt_hdr): bool;


const watchdog_interval = 10 sec &redef;





const max_timer_expires = 300 &redef;






const LOGIN_STATE_AUTHENTICATE = 0;
const LOGIN_STATE_LOGGED_IN = 1;
const LOGIN_STATE_SKIP = 2;
const LOGIN_STATE_CONFUSED = 3;










function min_double(a: double, b: double): double { return a < b ? a : b; }







function max_double(a: double, b: double): double { return a > b ? a : b; }







function min_interval(a: interval, b: interval): interval { return a < b ? a : b; }







function max_interval(a: interval, b: interval): interval { return a > b ? a : b; }







function min_count(a: count, b: count): count { return a < b ? a : b; }







function max_count(a: count, b: count): count { return a > b ? a : b; }


global skip_authentication: set[string] &redef;


global direct_login_prompts: set[string] &redef;


global login_prompts: set[string] &redef;


global login_non_failure_msgs: set[string] &redef;


global login_failure_msgs: set[string] &redef;


global login_success_msgs: set[string] &redef;


global login_timeouts: set[string] &redef;




type mime_header_rec: record {
	original_name: string;
	name: string;
	value: string;
};




type mime_header_list: table[count] of mime_header_rec;





global mime_segment_length = 1024 &redef;



global mime_segment_overlap_length = 0 &redef;




type pm_mapping: record {
	program: count;
	version: count;
	p: port;
};




type pm_mappings: table[count] of pm_mapping;




type pm_port_request: record {
	program: count;
	version: count;
	is_tcp: bool;
};




type pm_callit_request: record {
	program: count;
	version: count;
	proc: count;
	arg_size: count;
};
















const RPC_status = {
	[RPC_SUCCESS] = "ok",
	[RPC_PROG_UNAVAIL] = "prog unavail",
	[RPC_PROG_MISMATCH] = "mismatch",
	[RPC_PROC_UNAVAIL] = "proc unavail",
	[RPC_GARBAGE_ARGS] = "garbage args",
	[RPC_SYSTEM_ERR] = "system err",
	[RPC_TIMEOUT] = "timeout",
	[RPC_AUTH_ERROR] = "auth error",
	[RPC_UNKNOWN_ERROR] = "unknown"
};





global profiling_file: file &redef;





const profiling_interval = 0 secs &redef;





const expensive_profiling_multiple = 0 &redef;




type pkt_profile_modes: enum {
	PKT_PROFILE_MODE_NONE,
	PKT_PROFILE_MODE_SECS,
	PKT_PROFILE_MODE_PKTS,
	PKT_PROFILE_MODE_BYTES,
};




const pkt_profile_mode = PKT_PROFILE_MODE_NONE &redef;




const pkt_profile_freq = 0.0 &redef;




global pkt_profile_file: file &redef;








type dns_msg: record {
	id: count;

	opcode: count;
	rcode: count;

	QR: bool;
	AA: bool;
	TC: bool;
	RD: bool;
	RA: bool;
	Z: count;
	AD: bool;
	CD: bool;

	num_queries: count;
	num_answers: count;
	num_auth: count;
	num_addl: count;

	is_netbios: bool;
};




type dns_soa: record {
	mname: string;
	rname: string;
	serial: count;
	refresh: interval;
	retry: interval;
	expire: interval;
	minimum: interval;
};




type dns_edns_additional: record {
	query: string;
	qtype: count;
	t: count;
	payload_size: count;
	extended_rcode: count;
	version: count;
	z_field: count;
	TTL: interval;
	is_query: count;
};




type dns_edns_ecs: record {
	family: string;
	source_prefix_len: count;
	scope_prefix_len: count;
	address: addr;
};




type dns_edns_tcp_keepalive: record {
	keepalive_timeout_omitted: bool;
	keepalive_timeout: count;
};




type dns_edns_cookie: record {
	client_cookie: string;
	server_cookie: string &default="";
};




type dns_tkey: record {
	query: string;
	qtype: count;
	alg_name: string;
	inception: time;
	expiration: time;
	mode: count;
	rr_error: count;
	key_data: string;
	is_query: count;
};




type dns_tsig_additional: record {
	query: string;
	qtype: count;
	alg_name: string;
	sig: string;
	time_signed: time;
	fudge: time;
	orig_id: count;
	rr_error: count;
	is_query: count;
};




type dns_rrsig_rr: record {
	query: string;
	answer_type: count;
	type_covered: count;
	algorithm: count;
	labels: count;
	orig_ttl: interval;
	sig_exp: time;
	sig_incep: time;
	key_tag: count;
	signer_name: string;
	signature: string;
	is_query: count;
};




type dns_dnskey_rr: record {
	query: string;
	answer_type: count;
	flags: count;
	protocol: count;
	algorithm: count;
	public_key: string;
	is_query: count;
};




type dns_nsec3_rr: record {
	query: string;
	answer_type: count;
	nsec_flags: count;
	nsec_hash_algo: count;
	nsec_iter: count;
	nsec_salt_len: count;
	nsec_salt: string;
	nsec_hlen: count;
	nsec_hash: string;
	bitmaps: string_vec;
	is_query: count;
};




type dns_nsec3param_rr: record {
	query: string;
	answer_type: count;
	nsec_flags: count;
	nsec_hash_algo: count;
	nsec_iter: count;
	nsec_salt_len: count;
	nsec_salt: string;
	is_query: count;
};




type dns_ds_rr: record {
	query: string;
	answer_type: count;
	key_tag: count;
	algorithm: count;
	digest_type: count;
	digest_val: string;
	is_query: count;
};




type dns_binds_rr: record {
	query: string;
	answer_type: count;
	algorithm: count;
	key_id: count;
	removal_flag: count;
	complete_flag: count;
	is_query: count;
};




type dns_loc_rr: record {
	query: string;
	answer_type: count;
	version: count;
	size: count;
	horiz_pre: count;
	vert_pre: count;
	latitude: count;
	longitude: count;
	altitude: count;
	is_query: count;
};




type dns_svcb_param: record {
	key: count;
	mandatory: vector of count &optional;
	alpn: vector of string &optional;
	p: count &optional;
	hint: vector of addr &optional;
	ech: string &optional;
	raw: string &optional;
};

type dns_svcb_param_vec: vector of dns_svcb_param;






type dns_svcb_rr: record {
	svc_priority: count;
	target_name: string;
	svc_params: dns_svcb_param_vec &optional;
};






type dns_naptr_rr: record {
	order: count;
	preference: count;
	flags: string;
	service: string;
	regexp: string;
	replacement: string;
};






const DNS_QUERY = 0;
const DNS_ANS = 1;
const DNS_AUTH = 2;
const DNS_ADDL = 3;
const DNS_PREREQUISITE = 4;
const DNS_UPDATE = 5;






type dns_answer: record {


	answer_type: count;
	query: string;
	qtype: count;
	qclass: count;
	TTL: interval;
};





global dns_skip_auth: set[addr] &redef;





global dns_skip_addl: set[addr] &redef;




global dns_skip_all_auth = T &redef;




global dns_skip_all_addl = T &redef;



global dns_max_queries = 25 &redef;



global dns_max_compression_chain_depth = 20 &redef;




type http_stats_rec: record {
	num_requests: count;
	num_replies: count;
	request_version: double;
	reply_version: double;
};




type http_message_stat: record {

	start: time;

	interrupted: bool;

	finish_msg: string;

	body_length: count;

	content_gap_length: count;

	header_length: count;
};




global http_entity_data_delivery_size = 1500 &redef;





const skip_http_data = F &redef;






const truncate_http_URI = -1 &redef;




type irc_join_info: record {
	nick: string;
	channel: string;
	password: string;
	usermode: string;
};




type irc_join_list: set[irc_join_info];




type signature_state: record {
	sig_id:       string;
	conn:         connection;
	is_orig:      bool;
	payload_size: count;
};




type bittorrent_peer: record {
	h: addr;
	p: port;
};




type bittorrent_peer_set: set[bittorrent_peer];





type bittorrent_benc_value: record {
	i: int &optional;
	s: string &optional;
	d: string &optional;
	l: string &optional;
};




type bittorrent_benc_dir: table[string] of bittorrent_benc_value;





type bt_tracker_headers: table[string] of string;



type ModbusCoils: vector of bool;



type ModbusRegisters: vector of count;

type ModbusHeaders: record {

	tid:           count;

	pid:           count;

	uid:           count;

	function_code: count;


	len:           count;
};

type ModbusFileRecordRequest: record {
	ref_type: count;
	file_num: count;
	record_num: count;
	record_len: count;
};

type ModbusFileRecordRequests: vector of ModbusFileRecordRequest;

type ModbusFileRecordResponse: record {
	file_len: count;
	ref_type: count;
	record_data: string;
};

type ModbusFileRecordResponses: vector of ModbusFileRecordResponse;

type ModbusFileReference: record {
	ref_type: count;
	file_num: count;
	record_num: count;
	record_len: count;
	record_data: string;
};

type ModbusFileReferences: vector of ModbusFileReference;

module Analyzer;

export {
















	type disabling_analyzer: hook(c: connection, atype: AllAnalyzers::Tag, aid: count) &redef;
}

module NFS3;

export {




	const return_data = F &redef;



	const return_data_max = 512 &redef;




	const return_data_first_only = T &redef;
















	type info_t: record {

		rpc_stat: rpc_status;

		nfs_stat: status_t;

		req_start: time;

		req_dur: interval;

		req_len: count;

		rep_start: time;

		rep_dur: interval;

		rep_len: count;

		rpc_uid: count;

		rpc_gid: count;

		rpc_stamp: count;

		rpc_machine_name: string;

		rpc_auxgids: index_vec;
	};




	type sattr_t: record {
		mode: count &optional;
		uid: count	&optional;
		gid: count	&optional;
		size: count &optional;
		atime: time_how_t &optional;
		mtime: time_how_t &optional;
	};




	type fattr_t: record {
		ftype: file_type_t;
		mode: count;
		nlink: count;
		uid: count;
		gid: count;
		size: count;
		used: count;
		rdev1: count;
		rdev2: count;
		fsid: count;
		fileid: count;
		atime: time;
		mtime: time;
		ctime: time;
	};




	type symlinkdata_t: record {
		symlink_attributes: sattr_t;
		nfspath: string &optional;
	};




	type diropargs_t : record {
		dirfh: string;
		fname: string;
	};




	type renameopargs_t : record {
		src_dirfh : string;
		src_fname : string;
		dst_dirfh : string;
		dst_fname : string;
	};




	type symlinkargs_t: record {
		link : diropargs_t;
		symlinkdata: symlinkdata_t;
	};




	type linkargs_t: record {
		fh : string;
		link : diropargs_t;
	};




	type sattrargs_t: record {
		fh : string;
		new_attributes: sattr_t;
	};






	type lookup_reply_t: record {
		fh: string &optional;
		obj_attr: fattr_t &optional;
		dir_attr: fattr_t &optional;
	};




	type readargs_t: record {
		fh: string;
		offset: count;
		size: count;
	};



	type read_reply_t: record {
		attr: fattr_t &optional;
		size: count &optional;
		eof: bool &optional;
		data: string &optional;
	};





	type readlink_reply_t: record {
		attr: fattr_t &optional;
		nfspath: string &optional;
	};




	type writeargs_t: record {
		fh: string;
		offset: count;
		size: count;
		stable: stable_how_t;
		data: string &optional;
	};




	type wcc_attr_t: record {
		size: count;
		atime: time;
		mtime: time;
	};




	type link_reply_t: record {
		post_attr: fattr_t &optional;
		preattr: wcc_attr_t &optional;
		postattr: fattr_t &optional;
	};




	type sattr_reply_t: record {
		dir_pre_attr: wcc_attr_t &optional;
		dir_post_attr: fattr_t &optional;
	};






	type write_reply_t: record {
		preattr: wcc_attr_t &optional;
		postattr: fattr_t &optional;
		size: count &optional;
		commited: stable_how_t &optional;
		verf: count &optional;
	};







	type newobj_reply_t: record {
		fh: string &optional;
		obj_attr: fattr_t &optional;
		dir_pre_attr: wcc_attr_t &optional;
		dir_post_attr: fattr_t &optional;
	};




	type delobj_reply_t: record {
		dir_pre_attr: wcc_attr_t &optional;
		dir_post_attr: fattr_t &optional;
	};




	type renameobj_reply_t: record {
		src_dir_pre_attr: wcc_attr_t;
		src_dir_post_attr: fattr_t;
		dst_dir_pre_attr: wcc_attr_t;
		dst_dir_post_attr: fattr_t;
	};




	type readdirargs_t: record {
		isplus: bool;
		dirfh: string;
		cookie: count;
		cookieverf: count;
		dircount: count;
		maxcount: count &optional;
	};





	type direntry_t: record {
		fileid: count;
		fname:  string;
		cookie: count;
		attr: fattr_t &optional;
		fh: string &optional;
	};




	type direntry_vec_t: vector of direntry_t;




	type readdir_reply_t: record {
		isplus: bool;
		dir_attr: fattr_t &optional;
		cookieverf: count &optional;
		entries: direntry_vec_t &optional;
		eof: bool;
	};


	type fsstat_t: record {
		attrs: fattr_t &optional;
		tbytes: double;
		fbytes: double;
		abytes: double;
		tfiles: double;
		ffiles: double;
		afiles: double;
		invarsec: interval;
	};
}

module MIME;

export {


	const max_depth = 100 &redef;



	const max_header_bytes = 65536 &redef;
}

module MOUNT3;

export {














	type info_t: record {

		rpc_stat: rpc_status;

		mnt_stat: status_t;

		req_start: time;

		req_dur: interval;

		req_len: count;

		rep_start: time;

		rep_dur: interval;

		rep_len: count;

		rpc_uid: count;

		rpc_gid: count;

		rpc_stamp: count;

		rpc_machine_name: string;

		rpc_auxgids: index_vec;
	};




	type dirmntargs_t : record {
		dirname: string;
	};





	type mnt_reply_t: record {
		dirfh: string &optional;
		auth_flavors: vector of auth_flavor_t &optional;
	};

}

module Log;

export {















	const flush_interval = 1.0sec &redef;










	const write_buffer_size = 1000 &redef;








	const max_log_record_size = 1024*1024*64 &redef;




	const default_max_field_string_bytes = 4096 &redef;




	const default_max_field_container_elements = 100 &redef;







	const default_max_total_string_bytes = 256000 &redef;






	const default_max_total_container_elements = 500 &redef;
}

module POP3;

export {




	const max_pending_commands = 10 &redef;





	const max_unknown_client_commands = 10 &redef;

}

module Threading;

export {



	const heartbeat_interval = 1.0 secs &redef;
}

module SSH;

export {


	type Algorithm_Prefs: record {

		client_to_server: vector of string &optional;

		server_to_client: vector of string &optional;
	};






	type Capabilities: record {

		kex_algorithms:             string_vec;

		server_host_key_algorithms: string_vec;

		encryption_algorithms:      Algorithm_Prefs;

		mac_algorithms:             Algorithm_Prefs;

		compression_algorithms:     Algorithm_Prefs;

		languages:                  Algorithm_Prefs &optional;

		is_server:                  bool;
	};











	const max_packet_length = 8 * 1024 * 1024 &redef;










	const max_string_length = 2 * 1024 * 1024 &redef;
}

module NTLM;

export {
	type NTLM::Version: record {

		major   : count;

		minor   : count;

		build   : count;

		ntlmssp : count;
	};

	type NTLM::NegotiateFlags: record {

		negotiate_56               : bool;

		negotiate_key_exch         : bool;

		negotiate_128              : bool;

		negotiate_version          : bool;


		negotiate_target_info      : bool;

		request_non_nt_session_key : bool;

		negotiate_identify         : bool;


		negotiate_extended_sessionsecurity : bool;

		target_type_server         : bool;

		target_type_domain         : bool;



		negotiate_always_sign              : bool;

		negotiate_oem_workstation_supplied : bool;

		negotiate_oem_domain_supplied      : bool;

		negotiate_anonymous_connection     : bool;

		negotiate_ntlm                     : bool;


		negotiate_lm_key       : bool;

		negotiate_datagram     : bool;


		negotiate_seal         : bool;


		negotiate_sign         : bool;

		request_target         : bool;


		negotiate_oem          : bool;

		negotiate_unicode      : bool;
	};

	type NTLM::Negotiate: record {

		flags       : NTLM::NegotiateFlags;

		domain_name : string &optional;

		workstation : string &optional;

		version     : NTLM::Version &optional;
	};

	type NTLM::AVs: record {

		nb_computer_name  : string;

		nb_domain_name    : string;

		dns_computer_name : string &optional;

		dns_domain_name   : string &optional;

		dns_tree_name     : string &optional;



		constrained_auth  : bool &optional;

		timestamp         : time &optional;



		single_host_id    : count &optional;


		target_name       : string &optional;
	};

	type NTLM::Challenge: record {

		flags       : NTLM::NegotiateFlags;

		challenge   : count;




		target_name : string &optional;

		version     : NTLM::Version &optional;

		target_info : NTLM::AVs &optional;
	};

	type NTLM::Authenticate: record {

		flags       : NTLM::NegotiateFlags;

		domain_name : string &optional;

		user_name   : string &optional;

		workstation : string &optional;

		session_key : string &optional;

		version     : NTLM::Version &optional;

		response    : string &optional;
	};
}

module SMB;

export {





	type SMB::MACTimes: record {

		modified 	: time &log;

		modified_raw: count;

		accessed 	: time &log;

		accessed_raw: count;

		created  	: time &log;

		created_raw : count;

		changed  	: time &log;

		changed_raw : count;
	};






	const SMB::pipe_filenames: set[string] &redef;









	const SMB::max_pending_messages = 1000 &redef;





	const max_dce_rpc_analyzers = 1000 &redef;
}

module SMB1;

export {


















	type SMB1::Header : record {
		command : count;
		status  : count;
		flags   : count;
		flags2  : count;
		tid     : count;
		pid     : count;
		uid     : count;
		mid     : count;
	};

	type SMB1::NegotiateRawMode: record {

		read_raw	: bool;

		write_raw	: bool;
	};

	type SMB1::NegotiateCapabilities: record {

		raw_mode	   : bool;

		mpx_mode	   : bool;

		unicode		   : bool;

		large_files	   : bool;

		nt_smbs		   : bool;


		rpc_remote_apis	   : bool;

		status32	   : bool;

		level_2_oplocks	   : bool;

		lock_and_read	   : bool;

		nt_find		   : bool;


		dfs		   : bool;

		infolevel_passthru : bool;

		large_readx	   : bool;

		large_writex	   : bool;

		unix		   : bool;



		bulk_transfer	   : bool;


		compressed_data	   : bool;

		extended_security  : bool;
	};

	type SMB1::NegotiateResponseSecurity: record {


		user_level	  : bool;



		challenge_response: bool;


		signatures_enabled: bool &optional;



		signatures_required: bool &optional;
	};

	type SMB1::NegotiateResponseCore: record {

		dialect_index	: count;
	};

	type SMB1::NegotiateResponseLANMAN: record {

		word_count	     : count;

		dialect_index	     : count;

		security_mode	     : SMB1::NegotiateResponseSecurity;

		max_buffer_size	     : count;

		max_mpx_count	     : count;



		max_number_vcs	     : count;

		raw_mode	     : SMB1::NegotiateRawMode;

		session_key	     : count;

		server_time	     : time;

		encryption_key	     : string;


		primary_domain	     : string;
	};

	type SMB1::NegotiateResponseNTLM: record {

		word_count	: count;

		dialect_index	: count;

		security_mode	: SMB1::NegotiateResponseSecurity;

		max_buffer_size	: count;

		max_mpx_count	: count;



		max_number_vcs	: count;

		max_raw_size	: count;

		session_key	: count;

		capabilities	: SMB1::NegotiateCapabilities;

		server_time	: time;



		encryption_key	: string &optional;


		domain_name	: string &optional;


		guid		: string &optional;


		security_blob	: string;
	};

	type SMB1::NegotiateResponse: record {


		core	: SMB1::NegotiateResponseCore 	&optional;


		lanman  : SMB1::NegotiateResponseLANMAN  &optional;

		ntlm	: SMB1::NegotiateResponseNTLM    &optional;
	};

	type SMB1::SessionSetupAndXCapabilities: record {

		unicode         : bool;

		large_files     : bool;


		nt_smbs         : bool;

		status32        : bool;

		level_2_oplocks : bool;

		nt_find		: bool;
	};

	type SMB1::SessionSetupAndXRequest: record {




		word_count		  : count;

		max_buffer_size		  : count;

		max_mpx_count		  : count;

		vc_number		  : count;

		session_key		  : count;


		native_os		  : string;

		native_lanman		  : string;


		account_name		  : string &optional;



		account_password	  : string &optional;


		primary_domain		  : string &optional;



		case_insensitive_password : string &optional;


		case_sensitive_password	  : string &optional;


		security_blob		  : string &optional;


		capabilities		  : SMB1::SessionSetupAndXCapabilities &optional;
	};

	type SMB1::SessionSetupAndXResponse: record {

		word_count	: count;

		is_guest	: bool &optional;

		native_os 	: string &optional;

		native_lanman	: string &optional;

		primary_domain	: string &optional;

		security_blob	: string &optional;
	};

	type SMB1::Trans2_Args: record {

	     total_param_count: count;

	     total_data_count: count;

	     max_param_count: count;

	     max_data_count: count;

	     max_setup_count: count;

	     flags: count;

	     trans_timeout: count;

	     param_count: count;

	     param_offset: count;

	     data_count: count;

	     data_offset: count;

	     setup_count: count;
	};

	type SMB1::Trans_Sec_Args: record {

	     total_param_count: count;

	     total_data_count: count;

	     param_count: count;

	     param_offset: count;

	     param_displacement: count;

	     data_count: count;

	     data_offset: count;

	     data_displacement: count;
	};

	type SMB1::Trans2_Sec_Args: record {

	     total_param_count: count;

	     total_data_count: count;

	     param_count: count;

	     param_offset: count;

	     param_displacement: count;

	     data_count: count;

	     data_offset: count;

	     data_displacement: count;

	     FID: count;
	};

	type SMB1::Find_First2_Request_Args: record {

		search_attrs		: count;

		search_count		: count;


		flags				: count;

		info_level			: count;

		search_storage_type	: count;

		file_name			: string;
	};

	type SMB1::Find_First2_Response_Args: record {

		sid				: count;

		search_count	: count;


		end_of_search	: bool;

		ext_attr_error	: string &optional;
	};


}

module SMB2;

export {











	type SMB2::Header: record {

		credit_charge : count;


		status        : count;

		command       : count;


		credits       : count;

		flags         : count;


		message_id    : count;

		process_id    : count;

		tree_id       : count;

		session_id    : count;


		signature     : string;
	};







	type SMB2::GUID: record {

		persistent: count;

		volatile: count;
	};






	type SMB2::FileAttrs: record {


		read_only: bool;

		hidden: bool;

		system: bool;

		directory: bool;


		archive: bool;

		normal: bool;


		temporary: bool;

		sparse_file: bool;

		reparse_point: bool;



		compressed: bool;



		offline: bool;

		not_content_indexed: bool;



		encrypted: bool;




		integrity_stream: bool;

		no_scrub_data: bool;
	};







	type SMB2::CloseResponse: record {

		alloc_size : count;

		eof        : count;

		times      : SMB::MACTimes;

		attrs      : SMB2::FileAttrs;
	};





	type SMB2::PreAuthIntegrityCapabilities: record {

		hash_alg_count : count;

		salt_length : count;

		hash_alg : vector of count;

		salt : string;
	};





	type SMB2::EncryptionCapabilities: record {

		cipher_count : count;

		ciphers : vector of count;
	};





	type SMB2::CompressionCapabilities: record {

		alg_count : count;

		algs : vector of count;
	};





	type SMB2::NegotiateContextValue: record {

		context_type : count;

		data_length : count;

		preauth_info : SMB2::PreAuthIntegrityCapabilities &optional;

		encryption_info : SMB2::EncryptionCapabilities &optional;

		compression_info : SMB2::CompressionCapabilities &optional;

		netname: string &optional;
	};

	type SMB2::NegotiateContextValues: vector of SMB2::NegotiateContextValue;







	type SMB2::NegotiateResponse: record {


		dialect_revision  : count;

		security_mode     : count;

		server_guid       : SMB2::GUID;

		system_time       : time;

		server_start_time : time;


		negotiate_context_count : count;

		negotiate_context_values 	  : SMB2::NegotiateContextValues;
	};







	type SMB2::SessionSetupRequest: record {

		security_mode: count;
	};







	type SMB2::SessionSetupFlags: record {

		guest: bool;

		anonymous: bool;

		encrypt: bool;
	};








	type SMB2::SessionSetupResponse: record {

		flags: SMB2::SessionSetupFlags;
	};







	type SMB2::TreeConnectResponse: record {

		share_type: count;
	};






	type SMB2::CreateRequest: record {

		filename       : string;

		disposition    : count;

		create_options : count;
	};







	type SMB2::CreateResponse: record {

		file_id       : SMB2::GUID;

		size          : count;

		times         : SMB::MACTimes;

		attrs         : SMB2::FileAttrs;

		create_action : count;
	};





	type SMB2::Fscontrol: record {

		free_space_start_filtering : int;

		free_space_threshold       : int;

		free_space_stop_filtering  : int;

		delete_quota_threshold     : count;

		default_quota_limit        : count;

		fs_control_flags           : count;
	};





	type SMB2::FileEA: record {

		ea_name  : string;

		ea_value : string;
	};





	type SMB2::FileEAs: vector of SMB2::FileEA;












	type SMB2::Transform_header: record {

		signature     : string;

		nonce         : string;

		orig_msg_size : count;

		flags         : count;

		session_id    : count;
	};
}

module DHCP;

export {




	type DHCP::Addrs: vector of addr;




	type DHCP::Msg: record {
		op: count;
		m_type: count;
		xid: count;


		secs: interval;
		flags: count;
		ciaddr: addr;
		yiaddr: addr;
		siaddr: addr;
		giaddr: addr;
		chaddr: string;
		sname:  string &default="";
		file_n: string &default="";
	};




	type DHCP::ClientID: record {
		hwtype: count;
		hwaddr: string;
	};


	type DHCP::ClientFQDN: record {

		flags: count;

		rcode1: count;

		rcode2: count;


		domain_name: string;
	};




	type DHCP::SubOpt: record {
		code: count;
		value: string;
	};

	type DHCP::SubOpts: vector of DHCP::SubOpt;

	type DHCP::Options: record {

		options:         index_vec &optional;


		subnet_mask:     addr &optional;


		routers:         DHCP::Addrs &optional;


		dns_servers:     DHCP::Addrs &optional;


		host_name:       string &optional;


		domain_name:     string &optional;


		forwarding:      bool &optional;


		broadcast:       addr &optional;



		vendor:          string &optional;


		nbns:            DHCP::Addrs &optional;


		addr_request:    addr &optional;


		lease:           interval &optional;



		serv_addr:       addr &optional;


		param_list:      index_vec &optional;


		message:         string &optional;


		max_msg_size:    count &optional;




		renewal_time:    interval &optional;




		rebinding_time:  interval &optional;




		vendor_class:    string &optional;


		client_id:       DHCP::ClientID &optional;


		user_class:      string &optional;


		client_fqdn:     DHCP::ClientFQDN &optional;


		sub_opt:         DHCP::SubOpts &optional;



		auto_config:     bool &optional;


		auto_proxy_config: string &optional;


		time_offset:     int &optional;



		time_servers:    DHCP::Addrs &optional;


		name_servers:    DHCP::Addrs &optional;



		ntp_servers:     DHCP::Addrs &optional;
	};
}

module PE;

export {
	type PE::DOSHeader: record {

		signature                : string;

		used_bytes_in_last_page  : count;

		file_in_pages            : count;

		num_reloc_items          : count;

		header_in_paragraphs     : count;

		min_extra_paragraphs     : count;

		max_extra_paragraphs     : count;

		init_relative_ss         : count;

		init_sp                  : count;

		checksum                 : count;

		init_ip                  : count;

		init_relative_cs         : count;

		addr_of_reloc_table      : count;


		overlay_num              : count;

		oem_id                   : count;

		oem_info                 : count;

		addr_of_new_exe_header   : count;
	};

	type PE::FileHeader: record {

		machine              : count;

		ts                   : time;

		sym_table_ptr        : count;

		num_syms             : count;

		optional_header_size : count;

		characteristics      : set[count];
	};

	type PE::OptionalHeader: record {

		magic                   : count;

		major_linker_version    : count;

		minor_linker_version    : count;

		size_of_code            : count;

		size_of_init_data       : count;

		size_of_uninit_data     : count;

		addr_of_entry_point     : count;

		base_of_code            : count;

		base_of_data            : count &optional;

		image_base              : count;

		section_alignment       : count;

		file_alignment          : count;

		os_version_major        : count;

		os_version_minor        : count;

		major_image_version     : count;

		minor_image_version     : count;

		major_subsys_version    : count;

		minor_subsys_version    : count;

		size_of_image           : count;

		size_of_headers         : count;

		checksum                : count;

		subsystem               : count;

		dll_characteristics     : set[count];



		table_sizes             : vector of count;

	};


	type PE::SectionHeader: record {

		name             : string;

		virtual_size     : count;

		virtual_addr     : count;


		size_of_raw_data : count;


		ptr_to_raw_data  : count;


		ptr_to_relocs    : count;


		ptr_to_line_nums : count;

		num_of_relocs    : count;

		num_of_line_nums : count;

		characteristics  : set[count];
	};
}

module SSL;

export {
	type SignatureAndHashAlgorithm: record {
		HashAlgorithm: count;
		SignatureAlgorithm: count;
	};

	type PSKIdentity: record {
		identity: string;
		obfuscated_ticket_age: count;
	};





	const SSL::dtls_max_version_errors = 10 &redef;


	const SSL::dtls_max_reported_version_errors = 1 &redef;




	const SSL::max_alerts_per_record = 10 &redef;
}

module GLOBAL;






type signature_and_hashalgorithm_vec: vector of SSL::SignatureAndHashAlgorithm;

type psk_identity_vec: vector of SSL::PSKIdentity;

module X509;

export {
	type Certificate: record {
		version: count &log;
		serial: string &log;
		subject: string &log;
		issuer: string &log;
		cn: string &optional;
		not_valid_before: time &log;
		not_valid_after: time &log;
		key_alg: string &log;
		sig_alg: string &log;
		key_type: string &optional &log;
		key_length: count &optional &log;
		exponent: string &optional &log;
		curve: string &optional &log;
		tbs_sig_alg: string;
	};

	type Extension: record {
		name: string;
		short_name: string &optional;
		oid: string;
		critical: bool;
		value: string;
	};

	type BasicConstraints: record {
		ca: bool;
		path_len: count &optional;
	} &log;

	type SubjectAlternativeName: record {
		dns: string_vec &optional &log;
		uri: string_vec &optional &log;
		email: string_vec &optional &log;
		ip: addr_vec &optional &log;
		other_fields: bool;
	};


	type Result: record {

		result:	int;

		result_string: string;

		chain_certs: vector of opaque of x509 &optional;
	};
}

module SOCKS;

export {


	type Address: record {
		host: addr   &optional;
		name: string &optional;
	} &log;
}

module RADIUS;

export {
	type RADIUS::AttributeList: vector of string;
	type RADIUS::Attributes: table[count] of RADIUS::AttributeList;

	type RADIUS::Message: record {

		code          : count;

		trans_id      : count;

		authenticator : string;

		attributes    : RADIUS::Attributes &optional;
	};
}

module RDP;

export {
	type RDP::EarlyCapabilityFlags: record {
		support_err_info_pdu:       bool;
		want_32bpp_session:         bool;
		support_statusinfo_pdu:     bool;
		strong_asymmetric_keys:     bool;
		support_monitor_layout_pdu: bool;
		support_netchar_autodetect: bool;
		support_dynvc_gfx_protocol: bool;
		support_dynamic_time_zone:  bool;
		support_heartbeat_pdu:      bool;
	};

	type RDP::ClientCoreData: record {
		version_major:          count;
		version_minor:          count;
		desktop_width:          count;
		desktop_height:         count;
		color_depth:            count;
		sas_sequence:           count;
		keyboard_layout:        count;
		client_build:           count;
		client_name:            string;
		keyboard_type:          count;
		keyboard_sub:           count;
		keyboard_function_key:  count;
		ime_file_name:          string;
		post_beta2_color_depth: count  &optional;
		client_product_id:      count  &optional;
		serial_number:          count  &optional;
		high_color_depth:       count  &optional;
		supported_color_depths: count  &optional;
		ec_flags:               RDP::EarlyCapabilityFlags &optional;
		dig_product_id:         string &optional;
	};



	type RDP::ClientSecurityData: record {







		encryption_methods:	count;


		ext_encryption_methods:	count;
	};


	type RDP::ClientChannelDef: record {

		name:           string;

		options:	count;


		initialized:    bool;

		encrypt_rdp:    bool;

		encrypt_sc:     bool;

		encrypt_cs:     bool;

		pri_high:       bool;

		pri_med:        bool;

		pri_low:        bool;

		compress_rdp:   bool;

		compress:       bool;

		show_protocol:  bool;

		persistent:     bool;
	};




	type RDP::ClientClusterData: record {

		flags:                          count;



		redir_session_id:               count;




		redir_supported:                bool;

		svr_session_redir_version_mask: count;


		redir_sessionid_field_valid:    bool;

		redir_smartcard:                bool;
	};


	type RDP::ClientChannelList: vector of ClientChannelDef;
}

@load base/bif/plugins/Zeek_SNMP.types.bif

module SNMP;

export {


	type SNMP::HeaderV1: record {
		community: string;
	};



	type SNMP::HeaderV2: record {
		community: string;
	};




	type SNMP::ScopedPDU_Context: record {
		engine_id: string;
		name:      string;
	};




	type SNMP::UserSecurityParameters: record {

		AuthoritativeEngineID: string;

		AuthoritativeEngineBoots: int;

		AuthoritativeEngineTime: int;

		UserName: string;

		AuthenticationParameters: string;

		PrivacyParameters: string;
	};



	type SNMP::HeaderV3: record {
		id:              count;
		max_size:        count;
		flags:           count;
		auth_flag:       bool;
		priv_flag:       bool;
		reportable_flag: bool;
		security_model:  count;
		security_params: string;
		pdu_context:     SNMP::ScopedPDU_Context &optional;
		user_security_parameters: SNMP::UserSecurityParameters &optional;
	};




	type SNMP::Header: record {
		version: count;
		v1:      SNMP::HeaderV1 &optional;
		v2:      SNMP::HeaderV2 &optional;
		v3:      SNMP::HeaderV3 &optional;
	};










	type SNMP::ObjectValue: record {
		tag:      count;
		oid:      string &optional;
		signed:   int    &optional;
		unsigned: count  &optional;
		address:  addr   &optional;
		octets:   string &optional;
	};





	const SNMP::OBJ_INTEGER_TAG       : count = 0x02;
	const SNMP::OBJ_OCTETSTRING_TAG   : count = 0x04;
	const SNMP::OBJ_UNSPECIFIED_TAG   : count = 0x05;
	const SNMP::OBJ_OID_TAG           : count = 0x06;
	const SNMP::OBJ_IPADDRESS_TAG     : count = 0x40;
	const SNMP::OBJ_COUNTER32_TAG     : count = 0x41;
	const SNMP::OBJ_UNSIGNED32_TAG    : count = 0x42;
	const SNMP::OBJ_TIMETICKS_TAG     : count = 0x43;
	const SNMP::OBJ_OPAQUE_TAG        : count = 0x44;
	const SNMP::OBJ_COUNTER64_TAG     : count = 0x46;
	const SNMP::OBJ_NOSUCHOBJECT_TAG  : count = 0x80;
	const SNMP::OBJ_NOSUCHINSTANCE_TAG: count = 0x81;
	const SNMP::OBJ_ENDOFMIBVIEW_TAG  : count = 0x82;



	type SNMP::Binding: record {
		oid:   string;
		value: SNMP::ObjectValue;
	};



	type SNMP::Bindings: vector of SNMP::Binding;


	type SNMP::PDU: record {
		request_id:   int;
		error_status: int;
		error_index:  int;
		bindings:     SNMP::Bindings;
	};


	type SNMP::TrapPDU: record {
		enterprise:    string;
		agent:         addr;
		generic_trap:  int;
		specific_trap: int;
		time_stamp:    count;
		bindings:      SNMP::Bindings;
	};


	type SNMP::BulkPDU: record {
		request_id:      int;
		non_repeaters:   count;
		max_repetitions: count;
		bindings:        SNMP::Bindings;
	};
}

@load base/bif/plugins/Zeek_KRB.types.bif

module KRB;

export {

	const keytab = "" &redef;

	type KRB::KDC_Options: record {

		forwardable		: bool;

		forwarded		: bool;

		proxiable		: bool;

		proxy			: bool;

		allow_postdate		: bool;

		postdated		: bool;

		renewable		: bool;

		opt_hardware_auth	: bool;



		disable_transited_check	: bool;


		renewable_ok		: bool;


		enc_tkt_in_skey		: bool;

		renew			: bool;

		validate		: bool;
	};


	type KRB::AP_Options: record {

		use_session_key	: bool;

		mutual_required	: bool;
	};



	type KRB::Type_Value: record {

		data_type	: count;

		val 		: string;
	};

	type KRB::Type_Value_Vector: vector of KRB::Type_Value;

	type KRB::Encrypted_Data: record {

		kvno		: count &optional;

		cipher		: count;

		ciphertext	: string;
	};


	type KRB::Host_Address: record {

		ip	: addr &log &optional;

		netbios : string &log &optional;

		unknown : KRB::Type_Value &optional;
	};

	type KRB::Host_Address_Vector: vector of KRB::Host_Address;


	type KRB::SAFE_Msg: record {

		pvno		: count;

		msg_type	: count;


		data		: string;

		timestamp	: time &optional;

		seq		: count &optional;

		sender		: Host_Address &optional;

		recipient    	: Host_Address &optional;
	};


	type KRB::Error_Msg: record {

		pvno		: count &optional;

		msg_type	: count &optional;

		client_time	: time &optional;

		server_time	: time &optional;

		error_code	: count;

		client_realm	: string &optional;

		client_name	: string &optional;

		service_realm	: string &optional;

		service_name	: string &optional;

		error_text	: string &optional;

		pa_data		: vector of KRB::Type_Value &optional;
	};


	type KRB::Ticket: record {

		pvno		: count;

		realm		: string;

		service_name	: string;

		cipher		: count;

		ciphertext  : string &optional;

		authenticationinfo: string &optional;
	};

	type KRB::Ticket_Vector: vector of KRB::Ticket;


	type KRB::KDC_Request: record {

		pvno			: count;

		msg_type		: count;

		pa_data			: vector of KRB::Type_Value &optional;

		kdc_options		: KRB::KDC_Options &optional;

		client_name		: string &optional;


		service_realm		: string &optional;

		service_name		: string &optional;

		from			: time &optional;

		till			: time &optional;

		rtime			: time &optional;


		nonce			: count &optional;

		encryption_types	: vector of count &optional;

		host_addrs		: vector of KRB::Host_Address &optional;

		additional_tickets	: vector of KRB::Ticket &optional;
	};


	type KRB::KDC_Response: record {

		pvno			: count;

		msg_type		: count;

		pa_data			: vector of KRB::Type_Value &optional;

		client_realm		: string &optional;

		client_name		: string;


		ticket			: KRB::Ticket;

		enc_part		: KRB::Encrypted_Data;
	};
}

module JSON;

export {
	type TimestampFormat: enum {


		TS_EPOCH,




		TS_MILLIS,




		TS_MILLIS_UNSIGNED,




		TS_ISO8601,
	};


	type StringEscapePolicy: enum {




		STRING_ESCAPE_POLICY_HEX,





		STRING_ESCAPE_POLICY_PUA,






		STRING_ESCAPE_POLICY_TSV,
	};
}

module Reporter;

export {



	const info_to_stderr = T &redef;




	const warnings_to_stderr = T &redef;




	const errors_to_stderr = T &redef;
}

module Pcap;

export {

	const snaplen = 9216 &redef;



	const bufsize = 128 &redef;




	const bufsize_offline_bytes = 128 * 1024 &redef;

























	const non_fd_timeout = 20usec &redef;


	type Interface: record {

		name: string;

		description: string &optional;

		addrs: set[addr];


		is_loopback: bool;


		is_up: bool &optional;

		is_running: bool &optional;
	};

	type Interfaces: set[Pcap::Interface];


	type filter_state: enum {
		ok,
		fatal,
		warning
	};
}

module AF_Packet;

export {

	const buffer_size = 128 * 1024 * 1024 &redef;

	const block_size = 4096 * 8 &redef;

	const block_timeout = 10msec &redef;

	const enable_hw_timestamping = F &redef;

	const enable_fanout = T &redef;

	const enable_defrag = F &redef;

	const fanout_mode = FANOUT_HASH &redef;

	const fanout_id = 23 &redef;

	const link_type = 1 &redef;

	const checksum_validation_mode: ChecksumMode = CHECKSUM_ON &redef;
}

module DCE_RPC;

export {



	const max_cmd_reassembly = 20 &redef;




	const max_frag_data = 30000 &redef;
}

module NCP;

export {

	const max_frame_size = 65536 &redef;
}

module NTP;

export {



	type NTP::StandardMessage: record {











		stratum:            count;

		poll:               interval;

		precision:          interval;

		root_delay:         interval;

		root_disp:          interval;


		kiss_code:          string &optional;



		ref_id:             string &optional;





		ref_addr:           addr &optional;


		ref_time:           time;


		org_time:           time;


		rec_time:           time;


		xmt_time:           time;

		key_id:             count &optional;


		digest:             string &optional;

		num_exts:           count &default=0;
	};




	type NTP::ControlMessage: record {











		op_code:            count;

		resp_bit:           bool;


		err_bit:            bool;

		more_bit:           bool;

		sequence:           count;


		status:             count;

		association_id:     count;

		data:               string &optional;


		key_id:             count &optional;

		crypto_checksum:    string &optional;
	};








	type NTP::Mode7Message: record {



		req_code:       count;

		auth_bit:       bool;




		sequence:       count;





		implementation: count;












		err:            count;

		data:           string &optional;
	};




	type NTP::Message: record {

		version:        count;









		mode:           count;


		std_msg:        NTP::StandardMessage &optional;


		control_msg:    NTP::ControlMessage &optional;







		mode7_msg: NTP::Mode7Message &optional;
	};
}

module MQTT;

export {
	type MQTT::ConnectMsg: record {

		protocol_name    : string;

		protocol_version : count;


		client_id        : string;



		keep_alive       : interval;



		clean_session    : bool;


		will_retain      : bool;

		will_qos         : count;

		will_topic       : string &optional;

		will_msg         : string &optional;


		username         : string &optional;

		password         : string &optional;
	};

	type MQTT::ConnectAckMsg: record {

		return_code: count;





		session_present: bool;
	};

	type MQTT::PublishMsg: record {

		dup     : bool;


		qos     : count;




		retain  : bool;


		topic   : string;


		payload : string;




		payload_len : count;
	};




	option max_payload_size = 100;
}

module Gnutella;

export {


	const max_line_length = 8192 &redef;



	const max_header_length = 32768 &redef;
}

module Finger;

export {


	option max_line_length = 1024;
}

module Cluster;

export {
	type Cluster::Pool: record {};


	const backend = Cluster::CLUSTER_BACKEND_NONE &redef;




	const event_serializer = Cluster::EVENT_SERIALIZER_BROKER_BIN_V1 &redef;




	const log_serializer = Cluster::LOG_SERIALIZER_ZEEK_BIN_V1 &redef;


	option default_table_publish_on_change_max_batch_size = 10;


	option default_table_publish_on_change_max_batch_delay = 10msec;


	type PublishOnChangeAttr: record {

		changes: set[TableChange];


		topic: any &optional;


		max_batch_size: count &default=default_table_publish_on_change_max_batch_size;


		max_batch_delay: interval &default=default_table_publish_on_change_max_batch_delay;
	};



	type TableChangeInfo: record {

		change: TableChange;

		ts: time;



		index: vector of any;


		value: any &optional;


		previous_value: any &optional;
	};


	type TableChangeInfos: vector of TableChangeInfo;




	type TableChangeHeader: record {

		id: string;

		ts: time;

		node_id: string;
	};






	global table_change_infos: event(tcheader: TableChangeHeader, tcinfos: TableChangeInfos);










	global forward_table_change_infos: event(tcheader: TableChangeHeader, tcinfos: TableChangeInfos, to_topic: string);










	global apply_table_change_infos_policy: hook(tcheader: TableChangeHeader, tcinfos: TableChangeInfos);
}

module Weird;

export {

	option sampling_whitelist: set[string] = {};


	option sampling_global_list: set[string] = {};




	option sampling_threshold : count = 25;





	option sampling_rate : count = 1000;












	option sampling_duration = 10min;
}

module UnknownProtocol;

export {


	const sampling_threshold : count = 3 &redef;





	const sampling_rate : count = 100000 &redef;




	const sampling_duration = 1hr &redef;



	const first_bytes_count = 10 &redef;
}

module BinPAC;

export {


	const flowbuffer_capacity_max = 10 * 1024 * 1024 &redef;




	const flowbuffer_capacity_min = 512 &redef;







	const flowbuffer_contract_threshold = 2 * 1024 * 1024 &redef;
}

@load base/bif/telemetry_functions.bif
@load base/bif/telemetry_types.bif

module Telemetry;

export {

	type MetricOpts: record {



		prefix: string;





		name: string;





		unit: string &optional;


		help_text: string &optional;











		label_names: vector of string &default=vector();




		is_total: bool &optional;



		bounds: vector of double &optional;






		metric_type: MetricType &optional;
	};


	type Metric: record {

		opts: MetricOpts;







		label_names: vector of string &default=vector();


		label_values: vector of string &optional;





		value: double &optional;
	};


	type HistogramMetric: record {

		opts: MetricOpts;







		label_names: vector of string &default=vector();


		label_values: vector of string &optional;



		values: vector of double;


		observations: double;


		sum: double;
	};














	global sync: hook();

	type MetricVector : vector of Metric;
	type HistogramMetricVector : vector of HistogramMetric;



	const callback_timeout: interval = 5sec &redef;


	const civetweb_threads: count = 2 &redef;
}

module IP;

export {

	const protocol_names: table[count] of string = {
		[0] = "hopopt",
		[1] = "icmp",
		[2] = "igmp",
		[3] = "ggp",
		[4] = "ip-in-ip",
		[5] = "st",
		[6] = "tcp",
		[7] = "cbt",
		[8] = "egp",
		[9] = "igp",
		[10] = "bbc-rcc-mon",
		[11] = "nvp-ii",
		[12] = "pup",
		[13] = "argus",
		[14] = "emcon",
		[15] = "xnet",
		[16] = "chaos",
		[17] = "udp",
		[18] = "mux",
		[19] = "dcn-meas",
		[20] = "hmp",
		[21] = "prm",
		[22] = "xns-idp",
		[23] = "trunk-1",
		[24] = "trunk-2",
		[25] = "leaf-1",
		[26] = "leaf-2",
		[27] = "rdp",
		[28] = "irtp",
		[29] = "iso-tp4",
		[30] = "netblt",
		[31] = "mfe-nsp",
		[32] = "merit-inp",
		[33] = "dccp",
		[34] = "3pc",
		[35] = "idpr",
		[36] = "xtp",
		[37] = "ddp",
		[38] = "idpr-cmtp",
		[39] = "tp++",
		[40] = "il",
		[41] = "ipv6",
		[42] = "sdrp",
		[43] = "ipv6-route",
		[44] = "ipv6-frag",
		[45] = "idrp",
		[46] = "rsvp",
		[47] = "gre",
		[48] = "dsr",
		[49] = "bna",
		[50] = "esp",
		[51] = "ah",
		[52] = "i-nlsp",
		[53] = "swipe",
		[54] = "narp",
		[55] = "mobile",
		[56] = "tlsp",
		[57] = "skip",
		[58] = "ipv6-icmp",
		[59] = "ipv6-nonxt",
		[60] = "ipv6-opts",
		[61] = "host-protocol",
		[62] = "cftp",
		[63] = "local-network",
		[64] = "sat-expak",
		[65] = "kryptolan",
		[66] = "rvd",
		[67] = "ippc",
		[68] = "distributed-files",
		[69] = "sat-on",
		[70] = "visa",
		[71] = "ipcu",
		[72] = "cpnx",
		[73] = "cphb",
		[74] = "wsn",
		[75] = "pvp",
		[76] = "br-sat-mon",
		[77] = "sun-and",
		[78] = "wb-mon",
		[79] = "wb-expak",
		[80] = "iso-ip",
		[81] = "vmtp",
		[82] = "secure-vmtp",
		[83] = "vines",
		[84] = "ttp or iptm",
		[85] = "nsfnet-igp",
		[86] = "dgp",
		[87] = "tcf",
		[88] = "eigrp",
		[89] = "ospf",
		[90] = "sprite-rpc",
		[91] = "larp",
		[92] = "mtp",
		[93] = "ax.25",
		[94] = "os",
		[95] = "micp",
		[96] = "scc-sp",
		[97] = "etherip",
		[98] = "encap",
		[99] = "private-encryption",
		[100] = "gtmp",
		[101] = "ifmp",
		[102] = "pnni",
		[103] = "pim",
		[104] = "aris",
		[105] = "scps",
		[106] = "qnx",
		[107] = "a/n",
		[108] = "ipcomp",
		[109] = "snp",
		[110] = "compaq-peer",
		[111] = "ipx-in-ip",
		[112] = "vrrp",
		[113] = "pgm",
		[114] = "zero-hop",
		[115] = "l2tp",
		[116] = "ddx",
		[117] = "iatp",
		[118] = "stp",
		[119] = "srp",
		[120] = "uti",
		[121] = "smp",
		[122] = "sm",
		[123] = "ptp",
		[124] = "is-is-over-ipv4",
		[125] = "fire",
		[126] = "crtp",
		[127] = "crudp",
		[128] = "sccopmce",
		[129] = "iplt",
		[130] = "sps",
		[131] = "pipe",
		[132] = "sctp",
		[133] = "fc",
		[134] = "rsvp-e2e-ignore",
		[135] = "mobility-header",
		[136] = "udplite",
		[137] = "mpls-in-ip",
		[138] = "manet",
		[139] = "hip",
		[140] = "shim6",
		[141] = "wesp",
		[142] = "rohc",
		[143] = "ethernet",
		[144] = "aggfrag",
		[145] = "nsh",
		[146] = "homa"
	} &redef &default=function(c: count): string {
		return fmt("unknown-ip-proto-%d", c);
	};
}

module Storage;

export {



	const expire_interval = 15.0secs &redef;



	type ReturnCode: enum {

		SUCCESS,


		VAL_TYPE_MISMATCH,


		KEY_TYPE_MISMATCH,

		NOT_CONNECTED,

		TIMEOUT,

		CONNECTION_LOST,

		OPERATION_FAILED,

		KEY_NOT_FOUND,

		KEY_EXISTS,


		CONNECTION_FAILED,

		DISCONNECTION_FAILED,

		INITIALIZATION_FAILED,


		IN_PROGRESS,
	} &redef;


	type OperationResult: record {

		code: ReturnCode;


		error_str: string &optional;




		value: any &optional;
	};
}

module ConnThreshold;

export {






	const generic_packet_thresholds: set[count] = {} &redef;
}

module ZAM::Prof;

export {

	type Profile: record {



		num_bodies: count &default=0;


		num_calls: count &optional;



		num_inst: count &default=0;











		CPU: interval &optional;




		mem: count &optional;
	};
}

module GLOBAL;

@load base/bif/event.bif

global done_with_network = F;
event net_done(t: time)
	{
	done_with_network = T;
	}








@if ( __init_primary_bifs() )
@endif

@load base/packet-protocols

@if ( have_spicy() )
@load base/frameworks/spicy/init-bare
@endif
