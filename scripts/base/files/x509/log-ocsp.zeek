

module OCSP;

export {
	redef enum Log::ID += { LOG };

	global log_policy: Log::PolicyHook;


	type Info: record {

		ts: time &log;

		id: string &log;

		hashAlgorithm: string &log;

		issuerNameHash: string &log;

		issuerKeyHash: string &log;

		serialNumber: string &log;

		certStatus: string &log;

		revoketime: time &log &optional;

		revokereason: string &log &optional;

		thisUpdate: time &log;

		nextUpdate: time &log &optional;
	};



	global log_ocsp: event(rec: Info);
}

event zeek_init() &priority=5
	{
	Log::create_stream(LOG, Log::Stream($columns=Info, $ev=log_ocsp, $path="ocsp", $policy=log_policy));
	Files::register_for_mime_type(Files::ANALYZER_OCSP_REPLY, "application/ocsp-response");
	}

event ocsp_response_certificate(f: fa_file, hashAlgorithm: string, issuerNameHash: string, issuerKeyHash: string, serialNumber: string, certStatus: string, revoketime: time, revokereason: string, thisUpdate: time, nextUpdate: time)
	{
	local wr = OCSP::Info($ts=f$info$ts, $id=f$id, $hashAlgorithm=hashAlgorithm, $issuerNameHash=issuerNameHash,
			      $issuerKeyHash=issuerKeyHash, $serialNumber=serialNumber, $certStatus=certStatus,
			      $thisUpdate=thisUpdate);

	if ( revokereason != "" )
		wr$revokereason = revokereason;
	if ( revoketime as double != 0 )
		wr$revoketime = revoketime;
	if ( nextUpdate as double != 0 )
		wr$nextUpdate = nextUpdate;

	Log::write(LOG, wr);
	}
