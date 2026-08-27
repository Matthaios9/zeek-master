

















@load base/protocols/ssl
@load base/files/x509

module DisableX509Events;



redef X509::certificate_cache_max_entries = 100000;

type CacheIndex: record {

	ip: addr;

	sni: string &optional;

	sha256: string;
};

redef record SSL::Info += {

	always_raise_x509_events: bool &default=F;
};

redef record X509::Info += {

	always_raise_x509_events: bool &default=F;
};

global certificate_replay_tracking: set[CacheIndex] &read_expire=X509::certificate_cache_minimum_eviction_interval;

hook X509::x509_certificate_cache_replay(f: fa_file, e: X509::Info, sha256: string) &priority=5
	{

	if ( f$info?$x509 || e$always_raise_x509_events )
		return;

	local raise_events = F;


	if ( |f$conns| == 0 )
		return;

	for ( c in f$conns )
		{
		if ( ! f$conns[c]?$ssl )
			return;

		local test = CacheIndex($ip=f$conns[c]$id$resp_h, $sha256=sha256);
		if ( f$conns[c]$ssl?$server_name )
			test$sni = f$conns[c]$ssl$server_name;

		if ( test !in certificate_replay_tracking || f$conns[c]$ssl$always_raise_x509_events )
			{
			raise_events = T;
			add certificate_replay_tracking[test];
			}
		}

	if ( ! raise_events )
		{



		f$info$x509 = e;
		}
	}
