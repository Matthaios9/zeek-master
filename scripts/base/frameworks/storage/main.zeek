

module Storage;

export {

	const default_forced_sync: bool = F &redef;





	type BackendOptions: record {

		serializer: Storage::Serializer &default=Storage::STORAGE_SERIALIZER_JSON;




		forced_sync : bool &default=Storage::default_forced_sync;
	};



	type PutArgs: record {

		key: any;


		value: any;



		overwrite: bool &default=T;



		expire_time: interval &default=0sec;
	};


	const latency_metric_bounds: vector of double = { 0.001, 0.01, 0.1, 1.0, } &redef;
}
