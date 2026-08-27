module ZIP;

export {
	type File: record {

		global_: bool;


		fid: string &optional;

		filename: string;

		time_: time;

		comment: string;

		compression: ZIP::CompressionMethod;

		encrypted: bool;
	};
}







event ZIP::file(f: fa_file, meta: ZIP::File)
	{
	if ( meta$global_ || ! meta?$fid )
		return;


	local fid = meta$fid;
	if ( ! Files::file_exists(fid) )
		return;

	local meta_f = Files::lookup_file(meta$fid);


	if ( ! meta_f?$info )
		return;

	meta_f$info$filename = meta$filename;
	}
