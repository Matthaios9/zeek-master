












































@load base/frameworks/notice
@load base/protocols/http
@load frameworks/software/vulnerable



module ZeekygenExample;



redef enum Notice::Type += {


	Zeekygen_One,
	Zeekygen_Two,

	Zeekygen_Three,

	Zeekygen_Four,
};




redef enum Log::ID += { LOG };



export {



	type SimpleEnum: enum {


		ONE,
		TWO,
		THREE,
	};



	redef enum SimpleEnum  += {
		FOUR,

		FIVE
	};




	type SimpleRecord: record {

		field1: count;
		field2: bool;
	};


	redef record SimpleRecord += {

		field_ext: string &optional;
	};


	type ComplexRecord: record {
		field1: count;
		field2: bool;
		field3: SimpleRecord;


		msg: string &default="blah";
	} &redef;






	type Info: record {
		ts:       time       &log;
		uid:      string     &log;
		status:   count      &log &optional;
	};



	const an_option: set[addr, addr, string] &redef;


	const option_with_init = 0.01 secs &redef;




	global a_var: bool;


	global var_without_explicit_type = "this works";




	global summary_test: string;












    global a_function: function(tag: string, msg: string): string;









    global an_event: event(name: string);
}



function function_without_proto(tag: string): string &is_used
    {





    return "blah";
    }





type PrivateRecord: record {
    field1: bool;
    field2: count;
};



event zeek_init()
    {
    }
