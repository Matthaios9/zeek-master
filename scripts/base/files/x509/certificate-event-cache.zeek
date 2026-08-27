









@load ./main

module X509;

export {


	option caching_required_encounters : count = 10;


	option caching_required_encounters_interval : interval = 62 secs;



	option certificate_cache_minimum_eviction_interval : interval = 62 secs;


	option certificate_cache_max_entries : count = 10000;






	global x509_certificate_cache_replay: hook(f: fa_file, e: X509::Info, sha256: string);
}



global certificates_encountered: table[string] of count &create_expire=caching_required_encounters_interval;




global certificate_cache: table[string] of X509::Info &read_expire=certificate_cache_minimum_eviction_interval;

event zeek_init() &priority=5
	{
	x509_set_certificate_cache(certificate_cache);
	x509_set_certificate_cache_hit_callback(x509_certificate_cache_replay);
	}

hook x509_certificate_cache_replay(f: fa_file, e: X509::Info, sha256: string)
	{





	if ( f$info?$x509 )
		return;

	event x509_certificate(f, e$handle, e$certificate);
	for ( i in e$extensions_cache )
		{
		local ext = e$extensions_cache[i];

		if ( ext is X509::Extension )
			event x509_extension(f, (ext as X509::Extension));
		else if ( ext is X509::BasicConstraints )
			event x509_ext_basic_constraints(f, (ext as X509::BasicConstraints));
		else if ( ext is X509::SubjectAlternativeName )
			event x509_ext_subject_alternative_name(f, (ext as X509::SubjectAlternativeName));
		else if ( ext is X509::SctInfo )
			{
			local s = ( ext as X509::SctInfo);
			event x509_ocsp_ext_signed_certificate_timestamp(f, s$version, s$logid, s$timestamp, s$hash_alg, s$sig_alg, s$signature);
			}
		else
			Reporter::error(fmt("Encountered unknown extension while replaying certificate with fuid %s", f$id));
		}
	}

event file_state_remove(f: fa_file) &priority=5
	{
	if ( ! f$info?$x509 )
		return;

	if ( f$info?$sha256 && f$info$sha256 !in certificate_cache &&
		caching_required_encounters > 0 &&
		f$info$sha256 in certificates_encountered &&
		certificates_encountered[f$info$sha256] >= caching_required_encounters &&
		|certificate_cache| < certificate_cache_max_entries )
		{
		delete certificates_encountered[f$info$sha256];
		certificate_cache[f$info$sha256] = f$info$x509;
		}
	}

event file_hash(f: fa_file, kind: string, hash: string)
	{
	if ( ! f?$info || "X509" !in f$info$analyzers || kind != "sha256" )
		return;

	if ( caching_required_encounters == 0 || hash in certificate_cache )
		return;

	if ( hash !in certificates_encountered )
		certificates_encountered[hash] = 1;
	else
		certificates_encountered[hash] += 1;
	}
