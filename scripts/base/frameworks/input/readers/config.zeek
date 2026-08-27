

module InputConfig;

export {


	const set_separator = Input::set_separator &redef;




	const empty_field = "" &redef;














	const fail_on_file_problem = F &redef;














	global new_value: event(name: string, source: string, id: string, value: any);
}
