




@load base/frameworks/cluster
@load base/frameworks/notice
@load base/protocols/ssl

module SSL;

export {
	redef enum Notice::Type += {



		Invalid_Server_Cert
	};

	redef record Info += {

		validation_status: string &log &optional;


		validation_code: int &optional;

		valid_chain: vector of opaque of x509 &optional;
	};




	global recently_validated_certs: table[string] of X509::Result = table()
		&read_expire=5mins &redef;











	global ssl_cache_intermediate_ca: bool = T &redef;




	global ssl_store_valid_chain: bool = F &redef;



	global intermediate_add: event(key: string, value: vector of opaque of x509);



	global new_intermediate: event(key: string, value: vector of opaque of x509);
}

global intermediate_cache: table[string] of vector of opaque of x509;

function add_to_cache(key: string, value: vector of opaque of x509)
	{
	intermediate_cache[key] = value;
@if ( Cluster::is_enabled() )
	Cluster::publish(Cluster::manager_topic, SSL::new_intermediate, key, value);
@endif
	}

event SSL::intermediate_add(key: string, value: vector of opaque of x509)
	{
	intermediate_cache[key] = value;
	}

event SSL::new_intermediate(key: string, value: vector of opaque of x509)
	{
	if ( key in intermediate_cache )
		return;

	intermediate_cache[key] = value;
	Cluster::publish(Cluster::worker_topic, SSL::intermediate_add, key, value);
	}

function cache_validate(chain: vector of opaque of x509): X509::Result
	{
	local chain_hash: vector of string = vector();

	for ( i in chain )
		chain_hash[i] = sha1_hash(x509_get_certificate_string(chain[i]));

	local chain_id = join_string_vec(chain_hash, ".");


	if ( chain_id in recently_validated_certs )
		return recently_validated_certs[chain_id];

	local result = x509_verify(chain, root_certs);
	if ( ! ssl_store_valid_chain && result?$chain_certs )
		recently_validated_certs[chain_id] = X509::Result($result=result$result, $result_string=result$result_string);
	else
		recently_validated_certs[chain_id] = result;



	if ( ssl_cache_intermediate_ca &&
	     result$result_string == "ok" &&
		   result?$chain_certs &&
		   |result$chain_certs| > 2 )
		{
		local result_chain = result$chain_certs;
		local isnh = x509_subject_name_hash(result_chain[1], 4);
		if ( isnh !in intermediate_cache )
			{
			local cachechain: vector of opaque of x509;
			for ( i in result_chain )
				{
				if ( i >=1 && i<=|result_chain|-2 )
					cachechain[i-1] = result_chain[i];
				}
			add_to_cache(isnh, cachechain);
			}
		}

	return result;
	}

hook ssl_finishing(c: connection) &priority=20
	{

	if ( ! c$ssl?$cert_chain || |c$ssl$cert_chain| == 0 ||
	     ! c$ssl$cert_chain[0]?$x509 )
		return;

	local intermediate_chain: vector of opaque of x509 = vector();
	local issuer_name_hash = x509_issuer_name_hash(c$ssl$cert_chain[0]$x509$handle, 4);
	local hash = c$ssl$cert_chain[0]$sha1;
	local result: X509::Result;




	if ( ssl_cache_intermediate_ca && issuer_name_hash in intermediate_cache )
		{
		intermediate_chain[0] = c$ssl$cert_chain[0]$x509$handle;
		for ( i in intermediate_cache[issuer_name_hash] )
			intermediate_chain[i+1] = intermediate_cache[issuer_name_hash][i];

		result = cache_validate(intermediate_chain);
		if ( result$result_string == "ok" )
			{
			c$ssl$validation_status = result$result_string;
			c$ssl$validation_code = result$result;
			if ( result?$chain_certs )
				c$ssl$valid_chain = result$chain_certs;
			return;
			}
		}




	local chain: vector of opaque of x509 = vector();
	for ( i in c$ssl$cert_chain )
		{
		if ( c$ssl$cert_chain[i]?$x509 )
			chain[i] = c$ssl$cert_chain[i]$x509$handle;
		}

	result = cache_validate(chain);
	c$ssl$validation_status = result$result_string;
	c$ssl$validation_code = result$result;
	if ( result?$chain_certs )
		c$ssl$valid_chain = result$chain_certs;

	if ( result$result_string != "ok" )
		{
		local message = fmt("SSL certificate validation failed with (%s)", c$ssl$validation_status);
		NOTICE(Notice::Info($note=Invalid_Server_Cert, $msg=message,
		                    $sub=c$ssl$cert_chain[0]$x509$certificate$subject, $conn=c,
		                    $fuid=c$ssl$cert_chain[0]$fuid,
		                    $identifier=cat(c$id$resp_h,c$id$resp_p,hash,c$ssl$validation_code)));
		}
	}
