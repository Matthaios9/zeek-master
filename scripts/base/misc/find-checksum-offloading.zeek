




@load base/frameworks/notice

module ChecksumOffloading;

export {


	const check_interval = 10secs &redef;
}


global bad_ip_checksums  = 0;
global bad_tcp_checksums = 0;
global bad_udp_checksums = 0;


global done = F;

event ChecksumOffloading::check()
	{
	if ( done )
		return;

	local pkts_recvd = get_net_stats()$pkts_recvd;
	local bad_ip_checksum_pct = (pkts_recvd != 0) ? (bad_ip_checksums*1.0 / pkts_recvd*1.0) : 0;
	local bad_tcp_checksum_pct = (pkts_recvd != 0) ? (bad_tcp_checksums*1.0 / pkts_recvd*1.0) : 0;
	local bad_udp_checksum_pct = (pkts_recvd != 0) ? (bad_udp_checksums*1.0 / pkts_recvd*1.0) : 0;

	if ( bad_ip_checksum_pct  > 0.05 ||
	     bad_tcp_checksum_pct > 0.05 ||
	     bad_udp_checksum_pct > 0.05 )
		{
		local packet_src = reading_traces() ? "trace file likely has" : "interface is likely receiving";
		local bad_checksum_msg = (bad_ip_checksum_pct > 0.0) ? "IP" : "";
		if ( bad_tcp_checksum_pct > 0.0 )
			{
			if ( |bad_checksum_msg| > 0 )
				bad_checksum_msg += " and ";
			bad_checksum_msg += "TCP";
			}
		if ( bad_udp_checksum_pct > 0.0 )
			{
			if ( |bad_checksum_msg| > 0 )
				bad_checksum_msg += " and ";
			bad_checksum_msg += "UDP";
			}

		local message = fmt("Your %s invalid %s checksums, most likely from NIC checksum offloading.  By default, packets with invalid checksums are discarded by Zeek unless using the -C command-line option or toggling the 'ignore_checksums' variable.  Alternatively, disable checksum offloading by the network adapter to ensure Zeek analyzes the actual checksums that are transmitted.", packet_src, bad_checksum_msg);
		Reporter::warning(message);
		done = T;
		}
	else if ( pkts_recvd < 20 )
		{


		schedule check_interval { ChecksumOffloading::check() };
		}
	}

event zeek_init()
	{
	schedule check_interval { ChecksumOffloading::check() };
	}

event net_weird(name: string, addl: string)
	{
	if ( name == "bad_IP_checksum" )
		++bad_ip_checksums;
	}

event conn_weird(name: string, c: connection, addl: string)
	{
	if ( name == "bad_TCP_checksum" )
		++bad_tcp_checksums;
	else if ( name == "bad_UDP_checksum" )
		++bad_udp_checksums;
	}

event zeek_done()
	{
	event ChecksumOffloading::check();
	}
