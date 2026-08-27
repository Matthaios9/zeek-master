


@load base/protocols/ssl
@load protocols/ssl/validate-certs



redef SSL::ssl_store_valid_chain = T;

module SSL;

export {


	type SctSource: enum {


		SCT_X509_EXT,


		SCT_TLS_EXT,


		SCT_OCSP_EXT
	};



	type SctInfo: record {

		version: count;

		logid: string;




		timestamp: count;

		sig_alg: count;

		hash_alg: count;

		signature: string;

		source: SctSource;

		valid: bool &optional;
	};

	redef record Info += {

		valid_scts: count &optional;

		invalid_scts: count &optional;

		valid_ct_logs: count &log &optional;

		valid_ct_operators: count &log &optional;

		valid_ct_operators_list: set[string] &optional;

		ct_proofs: vector of SctInfo &default=vector();
	};
}


global recently_validated_scts: table[string] of bool = table()
	&read_expire=5mins &redef;

event zeek_init()
	{
	Files::register_for_mime_type(Files::ANALYZER_OCSP_REPLY, "application/ocsp-response");
	}

event ssl_extension_signed_certificate_timestamp(c: connection, is_client: bool, version: count, logid: string, timestamp: count, signature_and_hashalgorithm: SSL::SignatureAndHashAlgorithm, signature: string) &priority=5
	{
	c$ssl$ct_proofs += SctInfo($version=version, $logid=logid, $timestamp=timestamp, $sig_alg=signature_and_hashalgorithm$SignatureAlgorithm, $hash_alg=signature_and_hashalgorithm$HashAlgorithm, $signature=signature, $source=SCT_TLS_EXT);
	}

event x509_ocsp_ext_signed_certificate_timestamp(f: fa_file, version: count, logid: string, timestamp: count, hash_algorithm: count, signature_algorithm: count, signature: string) &priority=5
	{
	local src: SctSource;
	if ( ! f?$info )
		return;

	if ( f$source == "SSL" && f$info$mime_type == "application/ocsp-response" )
		src = SCT_OCSP_EXT;
	else if ( f$source == "SSL" && f$info$mime_type == "application/x-x509-user-cert" )
		src = SCT_X509_EXT;
	else
		return;

	if ( |f$conns| != 1 )
		return;

	local c: connection &is_assigned;

	for ( _, c in f$conns )
		{
		if ( ! c?$ssl )
			return;
		}

	c$ssl$ct_proofs += SctInfo($version=version, $logid=logid, $timestamp=timestamp, $sig_alg=signature_algorithm, $hash_alg=hash_algorithm, $signature=signature, $source=src);
	}


hook ssl_finishing(c: connection) &priority=19
	{
	if ( ! c$ssl?$cert_chain || |c$ssl$cert_chain| == 0 || ! c$ssl$cert_chain[0]?$x509 )
		return;

	local cert = c$ssl$cert_chain[0]$x509$handle;
	local certhash = c$ssl$cert_chain[0]$sha1;
	local issuer_name_hash = x509_issuer_name_hash(cert, 4);
	local valid_proofs = 0;
	local invalid_proofs = 0;
	c$ssl$valid_ct_operators_list = string_set();
	local valid_logs = string_set();
	local issuer_key_hash = "";

	for ( i in c$ssl$ct_proofs )
		{
		local proof = c$ssl$ct_proofs[i];
		if ( proof$logid !in SSL::ct_logs )
			{

			proof$valid = F;
			next;
			}
		local log = SSL::ct_logs[proof$logid];

		local valid = F;
		local found_cache = F;

		local validatestring = cat(certhash,proof$logid,proof$timestamp,proof$hash_alg,proof$signature,proof$source);
		if ( proof$source == SCT_X509_EXT && c$ssl?$validation_code )
			validatestring = cat(validatestring, c$ssl$validation_code);
		local validate_hash = sha1_hash(validatestring);
		if ( validate_hash in recently_validated_scts )
			{
			valid = recently_validated_scts[validate_hash];
			found_cache = T;
			}

		if ( found_cache == F && ( proof$source == SCT_TLS_EXT || proof$source == SCT_OCSP_EXT ) )
			{
			valid = sct_verify(cert, proof$logid, log$key, proof$signature, proof$timestamp, proof$hash_alg);
			}
		else if ( found_cache == F )
			{





			if ( issuer_key_hash != "" )
				{
				valid = sct_verify(cert, proof$logid, log$key, proof$signature, proof$timestamp, proof$hash_alg, issuer_key_hash);
				}


			if ( ! valid && issuer_name_hash in intermediate_cache )
				{
				issuer_key_hash = x509_spki_hash(intermediate_cache[issuer_name_hash][0], 4);
				valid = sct_verify(cert, proof$logid, log$key, proof$signature, proof$timestamp, proof$hash_alg, issuer_key_hash);
				}
			if ( ! valid && c$ssl?$valid_chain && |c$ssl$valid_chain| >= 2 )
				{
				issuer_key_hash = x509_spki_hash(c$ssl$valid_chain[1], 4);
				valid = sct_verify(cert, proof$logid, log$key, proof$signature, proof$timestamp, proof$hash_alg, issuer_key_hash);
				}



			if ( !valid )
				for ( i in c$ssl$cert_chain )
					{
					if ( i == 0 )
						next;
					if ( ! c$ssl$cert_chain[i]?$x509 || ! c$ssl$cert_chain[i]$x509?$handle )
						next;

					issuer_key_hash = x509_spki_hash(c$ssl$cert_chain[i]$x509$handle, 4);
					valid = sct_verify(cert, proof$logid, log$key, proof$signature, proof$timestamp, proof$hash_alg, issuer_key_hash);
					if ( valid )
						break;
					}
			}

		if ( ! found_cache )
			recently_validated_scts[validate_hash] = valid;

		proof$valid = valid;

		if ( valid )
			{
			++valid_proofs;
			add c$ssl$valid_ct_operators_list[log$operator];
			add valid_logs[proof$logid];
			}
		else
			++invalid_proofs;
		}

	c$ssl$valid_scts = valid_proofs;
	c$ssl$invalid_scts = invalid_proofs;
	c$ssl$valid_ct_operators = |c$ssl$valid_ct_operators_list|;
	c$ssl$valid_ct_logs = |valid_logs|;
	}
