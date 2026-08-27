

module LogNone;

export {


	const debug = F &redef;
}

function default_rotation_postprocessor_func(info: Log::RotationInfo) : bool
	{
	return T;
	}

redef Log::default_rotation_postprocessors += { [Log::WRITER_NONE] = default_rotation_postprocessor_func };
