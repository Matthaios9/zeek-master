
@load base/frameworks/files
@load base/files/hash
@load base/frameworks/cluster

module X509;

export {
	redef enum Log::ID += { LOG };

	global log_policy: Log::PolicyHook;



	option hash_function: function(cert: string): string = sha256_hash;




	option log_x509_in_files_log: bool = F;



	type LogCertHash: record {

		fingerprint: string;

		host_cert: bool;

		client_cert: bool;
	};


	type Info: record {

		ts: time &log;

		fingerprint: string &log;

		certificate: X509::Certificate &log;


		handle: opaque of x509;

		extensions: vector of X509::Extension &default=vector();

		san: X509::SubjectAlternativeName &optional &log;

		basic_constraints: X509::BasicConstraints &optional &log;



		extensions_cache: vector of any &default=vector();

		host_cert: bool &log &default=F;

		client_cert: bool &log &default=F;

		deduplication_index: LogCertHash &optional;
	};


	global create_deduplication_index: hook(c: X509::Info);



	type SctInfo: record {

		version: count;

		logid: string;




		timestamp: count;

		hash_alg: count;

		sig_alg: count;

		signature: string;
	};







	option relog_known_certificates_after = 1day;



	global known_log_certs: set[LogCertHash] &create_expire=relog_known_certificates_after;


	option known_log_certs_maximum_size = 1000000;








	global known_log_certs_use_broker: bool = T &deprecated="Remove in v9.1: Replaced with known_log_certs_enable_publish";





	const known_log_certs_enable_publish: bool = T &redef;





	const known_log_certs_enable_node_up_publish: bool = T &redef;


	global log_x509: event(rec: Info);






	const default_max_field_string_bytes = Log::default_max_field_string_bytes &redef;






	const default_max_field_container_elements = 500 &redef;








	const default_max_total_container_elements = 1500 &redef;
}

@pragma push ignore-deprecations
global known_log_certs_with_broker: set[LogCertHash] &create_expire=relog_known_certificates_after &backend=Broker::MEMORY;
@pragma pop

redef record Files::Info += {


	x509: X509::Info &optional;
};

event zeek_init() &priority=5
	{


	Log::create_stream(X509::LOG, Log::Stream($columns=Info, $ev=log_x509, $path="x509", $policy=log_policy,
	                                          $max_field_string_bytes=X509::default_max_field_string_bytes,
	                                          $max_field_container_elements=X509::default_max_field_container_elements,
	                                          $max_total_container_elements=X509::default_max_total_container_elements));






	Files::register_for_mime_type(Files::ANALYZER_X509, "application/x-x509-user-cert");
	Files::register_for_mime_type(Files::ANALYZER_X509, "application/x-x509-ca-cert");
	Files::register_for_mime_type(Files::ANALYZER_X509, "application/pkix-cert");



	Files::register_for_mime_type(Files::ANALYZER_MD5, "application/x-x509-user-cert");
	Files::register_for_mime_type(Files::ANALYZER_MD5, "application/x-x509-ca-cert");
	Files::register_for_mime_type(Files::ANALYZER_MD5, "application/pkix-cert");
	Files::register_for_mime_type(Files::ANALYZER_SHA1, "application/x-x509-user-cert");
	Files::register_for_mime_type(Files::ANALYZER_SHA1, "application/x-x509-ca-cert");
	Files::register_for_mime_type(Files::ANALYZER_SHA1, "application/pkix-cert");



	Files::register_for_mime_type(Files::ANALYZER_SHA256, "application/x-x509-user-cert");
	Files::register_for_mime_type(Files::ANALYZER_SHA256, "application/x-x509-ca-cert");
	Files::register_for_mime_type(Files::ANALYZER_SHA256, "application/pkix-cert");

@if ( Cluster::is_enabled() )
@pragma push ignore-deprecations
	if ( known_log_certs_use_broker && ! known_log_certs_enable_publish )
		known_log_certs = known_log_certs_with_broker;
@pragma pop
@endif
	}

hook Files::log_policy(rec: Files::Info, id: Log::ID, filter: Log::Filter) &priority=5
	{
	if ( ( log_x509_in_files_log == F ) && ( "X509" in rec$analyzers ) )
		break;
	}

hook create_deduplication_index(i: X509::Info)
	{
	if ( i?$deduplication_index || relog_known_certificates_after == 0secs )
		return;

	i$deduplication_index = LogCertHash($fingerprint=i$fingerprint, $host_cert=i$host_cert, $client_cert=i$client_cert);
	}

event x509_certificate(f: fa_file, cert_ref: opaque of x509, cert: X509::Certificate) &priority=5
	{
	local der_cert = x509_get_certificate_string(cert_ref);
	local fp = hash_function(der_cert);
	f$info$x509 = X509::Info($ts=f$info$ts, $fingerprint=fp, $certificate=cert, $handle=cert_ref);
	if ( f$info$mime_type == "application/x-x509-user-cert" )
		f$info$x509$host_cert = T;
	if ( f$is_orig )
		f$info$x509$client_cert = T;
	}

event x509_extension(f: fa_file, ext: X509::Extension) &priority=5
	{
	if ( f$info?$x509 )
		{
		f$info$x509$extensions += ext;
		f$info$x509$extensions_cache += ext;
		}
	}

event x509_ext_basic_constraints(f: fa_file, ext: X509::BasicConstraints) &priority=5
	{
	if ( f$info?$x509 )
		{
		f$info$x509$basic_constraints = ext;
		f$info$x509$extensions_cache += ext;
		}
	}

event x509_ext_subject_alternative_name(f: fa_file, ext: X509::SubjectAlternativeName) &priority=5
	{
	if ( f$info?$x509 )
		{
		f$info$x509$san = ext;
		f$info$x509$extensions_cache += ext;
		}
	}

event x509_ocsp_ext_signed_certificate_timestamp(f: fa_file, version: count, logid: string, timestamp: count, hash_algorithm: count, signature_algorithm: count, signature: string) &priority=5
	{
	if ( f$info?$x509 )
		f$info$x509$extensions_cache += SctInfo($version=version, $logid=logid, $timestamp=timestamp, $hash_alg=hash_algorithm, $sig_alg=signature_algorithm, $signature=signature);
	}



event X509::log_cert_hashes_internal(lchs: set[LogCertHash])
	{
	for (lch in lchs)
		if ( |known_log_certs| < known_log_certs_maximum_size )
			add X509::known_log_certs[lch];



	if ( Cluster::local_node_type() == Cluster::MANAGER )
		Cluster::publish(Cluster::worker_topic, X509::log_cert_hashes_internal, lchs);
	}


@if ( Cluster::local_node_type() == Cluster::MANAGER )








event Cluster::node_up(name: string, id: string)
	{
	if ( ! known_log_certs_enable_publish || ! known_log_certs_enable_node_up_publish )
		return;

	if ( name !in Cluster::nodes || Cluster::nodes[name]$node_type != Cluster::WORKER )
		return;

	if ( |known_log_certs| == 0 )
		return;

	Cluster::publish(Cluster::node_topic(name), X509::log_cert_hashes_internal, known_log_certs);
	}
@endif



function publish_x509_log_cert_hash(lch: LogCertHash)
	{
	Cluster::publish(Cluster::manager_topic, X509::log_cert_hashes_internal, set(lch));
	}

event file_state_remove(f: fa_file) &priority=5
	{
	if ( ! f$info?$x509 )
		return;

	if ( ! f$info$x509?$deduplication_index )
		hook create_deduplication_index(f$info$x509);

	if ( f$info$x509?$deduplication_index )
		{
		local lch = f$info$x509$deduplication_index;
		if ( lch in known_log_certs )
			return;
		else if ( |known_log_certs| < known_log_certs_maximum_size )
			{
			add known_log_certs[lch];



			if ( known_log_certs_enable_publish )
				publish_x509_log_cert_hash(lch);
			}
		}

	Log::write(LOG, f$info$x509);
	}
