

@load ./main
@load base/bif/data.bif

module Broker;

export {



	const default_clone_resync_interval = 10sec &redef;





	const default_clone_stale_interval = 5min &redef;







	const default_clone_mutation_buffer_interval = 2min &redef;





	const table_store_master = T &redef;



	const table_store_db_directory = "." &redef;


	type QueryStatus: enum {
		SUCCESS,
		FAILURE,
	};


	type QueryResult: record {

		status: Broker::QueryStatus;



		result: Broker::Data;
	};


	type BackendType: enum {
		MEMORY,
		SQLITE,
	};



	type SQLiteFailureMode: enum {
		SQLITE_FAILURE_MODE_FAIL,
		SQLITE_FAILURE_MODE_DELETE,
	};


	type SQLiteSynchronous: enum {
		SQLITE_SYNCHRONOUS_OFF,
		SQLITE_SYNCHRONOUS_NORMAL,
		SQLITE_SYNCHRONOUS_FULL,
		SQLITE_SYNCHRONOUS_EXTRA,
	};


	type SQLiteJournalMode: enum {
		SQLITE_JOURNAL_MODE_DELETE,
		SQLITE_JOURNAL_MODE_WAL,
	};


	type SQLiteOptions: record {



		path: string &default = "";





		synchronous: SQLiteSynchronous &optional;






		journal_mode: SQLiteJournalMode &optional;







		failure_mode: SQLiteFailureMode &default=SQLITE_FAILURE_MODE_FAIL;







		integrity_check: bool &default=F;
	};


	type BackendOptions: record {
		sqlite: SQLiteOptions &default = SQLiteOptions();
	};












	global create_master: function(name: string, b: BackendType &default = MEMORY,
	                               options: BackendOptions &default = BackendOptions()): opaque of Broker::Store
	                               &deprecated="Remove in v9.1. Broker stores have been deprecated. To distribute state across cluster nodes, use the new &publish_on_change attribute for global sets/tables, or leverage explicit remote events with Cluster::publish(). For state persistence, use the storage framework.";

































	global create_clone: function(name: string,
	                              resync_interval: interval &default = default_clone_resync_interval,
	                              stale_interval: interval &default = default_clone_stale_interval,
	                              mutation_buffer_interval: interval &default = default_clone_mutation_buffer_interval): opaque of Broker::Store
	                              &deprecated="Remove in v9.1. Broker stores have been deprecated. To distribute state across cluster nodes, use the new &publish_on_change attribute for global sets/tables, or leverage explicit remote events with Cluster::publish(). For state persistence, use the storage framework.";







	global close: function(h: opaque of Broker::Store): bool;




	global is_closed: function(h: opaque of Broker::Store): bool;




	global store_name: function(h: opaque of Broker::Store): string;








	global exists: function(h: opaque of Broker::Store, k: any): QueryResult;








	global get: function(h: opaque of Broker::Store, k: any): QueryResult;















	global put_unique: function(h: opaque of Broker::Store,
	                            k: any, v: any, e: interval &default=0sec): QueryResult;














	global get_index_from_value: function(h: opaque of Broker::Store,
	                                      k: any, i: any): QueryResult;












	global put: function(h: opaque of Broker::Store,
	                     k: any, v: any, e: interval &default=0sec) : bool;








	global erase: function(h: opaque of Broker::Store, k: any) : bool;















	global increment: function(h: opaque of Broker::Store, k: any,
	                           a: any &default = 1,
	                           e: interval &default=0sec) : bool;















	global decrement: function(h: opaque of Broker::Store, k: any,
	                           a: any &default = 1,
	                           e: interval &default=0sec) : bool;














	global append: function(h: opaque of Broker::Store, k: any, s: string,
	                        e: interval &default=0sec) : bool;














	global insert_into_set: function(h: opaque of Broker::Store,
	                                 k: any, i: any,
	                                 e: interval &default=0sec) : bool;
















	global insert_into_table: function(h: opaque of Broker::Store,
	                                   k: any, i: any, v: any,
	                                   e: interval &default=0sec) : bool;














	global remove_from: function(h: opaque of Broker::Store,
	                             k: any, i: any,
	                             e: interval &default=0sec) : bool;














	global push: function(h: opaque of Broker::Store,
	                      k: any, v: any,
	                      e: interval &default=0sec) : bool;












	global pop: function(h: opaque of Broker::Store,
	                     k: any,
	                     e: interval &default=0sec) : bool;









	global keys: function(h: opaque of Broker::Store): QueryResult;




	global clear: function(h: opaque of Broker::Store) : bool;
















	global data: function(d: any): Broker::Data;








	global data_type: function(d: Broker::Data): Broker::DataType;


	global set_create: function(): Broker::Data;






	global set_clear: function(s: Broker::Data) : bool;






	global set_size: function(s: Broker::Data): count;








	global set_contains: function(s: Broker::Data, key: any) : bool;








	global set_insert: function(s: Broker::Data, key: any) : bool;








	global set_remove: function(s: Broker::Data, key: any) : bool;







	global set_iterator: function(s: Broker::Data): opaque of Broker::SetIterator;







	global set_iterator_last: function(it: opaque of Broker::SetIterator) : bool;








	global set_iterator_next: function(it: opaque of Broker::SetIterator) : bool;






	global set_iterator_value: function(it: opaque of Broker::SetIterator): Broker::Data;


	global table_create: function(): Broker::Data;






	global table_clear: function(t: Broker::Data) : bool;






	global table_size: function(t: Broker::Data): count;








	global table_contains: function(t: Broker::Data, key: any) : bool;











	global table_insert: function(t: Broker::Data, key: any, val: any): Broker::Data;









	global table_remove: function(t: Broker::Data, key: any): Broker::Data;









	global table_lookup: function(t: Broker::Data, key: any): Broker::Data;







	global table_iterator: function(t: Broker::Data): opaque of Broker::TableIterator;







	global table_iterator_last: function(it: opaque of Broker::TableIterator) : bool;








	global table_iterator_next: function(it: opaque of Broker::TableIterator) : bool;






	global table_iterator_value: function(it: opaque of Broker::TableIterator): Broker::TableItem;


	global vector_create: function(): Broker::Data;






	global vector_clear: function(v: Broker::Data) : bool;






	global vector_size: function(v: Broker::Data): count;












	global vector_insert: function(v: Broker::Data, idx: count, d: any) : bool;











	global vector_replace: function(v: Broker::Data, idx: count, d: any): Broker::Data;









	global vector_remove: function(v: Broker::Data, idx: count): Broker::Data;









	global vector_lookup: function(v: Broker::Data, idx: count): Broker::Data;







	global vector_iterator: function(v: Broker::Data): opaque of Broker::VectorIterator;







	global vector_iterator_last: function(it: opaque of Broker::VectorIterator) : bool;








	global vector_iterator_next: function(it: opaque of Broker::VectorIterator) : bool;






	global vector_iterator_value: function(it: opaque of Broker::VectorIterator): Broker::Data;






	global record_create: function(sz: count): Broker::Data;






	global record_size: function(r: Broker::Data): count;










	global record_assign: function(r: Broker::Data, idx: count, d: any) : bool;










	global record_lookup: function(r: Broker::Data, idx: count): Broker::Data;







	global record_iterator: function(r: Broker::Data): opaque of Broker::RecordIterator;







	global record_iterator_last: function(it: opaque of Broker::RecordIterator) : bool;








	global record_iterator_next: function(it: opaque of Broker::RecordIterator) : bool;






	global record_iterator_value: function(it: opaque of Broker::RecordIterator): Broker::Data;
}

@load base/bif/store.bif

module Broker;

function create_master(name: string, b: BackendType &default = MEMORY,
                       options: BackendOptions &default = BackendOptions()): opaque of Broker::Store
	{
	if ( Cluster::backend != Cluster::CLUSTER_BACKEND_BROKER && Cluster::backend != Cluster::CLUSTER_BACKEND_NONE )
		Reporter::fatal(fmt("Call to Broker::create_master() with non-Broker backend %s selected", Cluster::backend));

@pragma push ignore-deprecations
	return __create_master(name, b, options);
@pragma pop
	}

function create_clone(name: string,
                      resync_interval: interval &default = default_clone_resync_interval,
                      stale_interval: interval &default = default_clone_stale_interval,
                      mutation_buffer_interval: interval &default = default_clone_mutation_buffer_interval): opaque of Broker::Store
	{
	if ( Cluster::backend != Cluster::CLUSTER_BACKEND_BROKER && Cluster::backend != Cluster::CLUSTER_BACKEND_NONE )
		Reporter::fatal(fmt("Call to Broker::create_clone() with non-Broker backend %s selected", Cluster::backend));

@pragma push ignore-deprecations
	return __create_clone(name, resync_interval, stale_interval,
	                      mutation_buffer_interval);
@pragma pop
	}

function close(h: opaque of Broker::Store): bool
	{
	return __close(h);
	}

function is_closed(h: opaque of Broker::Store): bool
	{
	return __is_closed(h);
	}

function store_name(h: opaque of Broker::Store): string
	{
	return __store_name(h);
	}

function exists(h: opaque of Broker::Store, k: any): QueryResult
	{
	return __exists(h, k);
	}

function get(h: opaque of Broker::Store, k: any): QueryResult
	{
	return __get(h, k);
	}

function put_unique(h: opaque of Broker::Store, k: any, v: any,
             e: interval &default=0sec): QueryResult
    {
    return __put_unique(h, k, v, e);
    }

function get_index_from_value(h: opaque of Broker::Store, k: any, i: any): QueryResult
	{
	return __get_index_from_value(h, k, i);
	}

function keys(h: opaque of Broker::Store): QueryResult
	{
	return __keys(h);
	}

function put(h: opaque of Broker::Store, k: any, v: any, e: interval) : bool
	{
	return __put(h, k, v, e);
	}

function erase(h: opaque of Broker::Store, k: any) : bool
	{
	return __erase(h, k);
	}

function increment(h: opaque of Broker::Store, k: any, a: any, e: interval) : bool
	{
	return __increment(h, k, a, e);
	}

function decrement(h: opaque of Broker::Store, k: any, a: any, e: interval) : bool
	{
	return __decrement(h, k, a, e);
	}

function append(h: opaque of Broker::Store, k: any, s: string, e: interval) : bool
	{
	return __append(h, k, s, e);
	}

function insert_into_set(h: opaque of Broker::Store, k: any, i: any, e: interval) : bool
	{
	return __insert_into_set(h, k, i, e);
	}

function insert_into_table(h: opaque of Broker::Store, k: any, i: any, v: any, e: interval) : bool
	{
	return __insert_into_table(h, k, i, v, e);
	}

function remove_from(h: opaque of Broker::Store, k: any, i: any, e: interval) : bool
	{
	return __remove_from(h, k, i, e);
	}

function push(h: opaque of Broker::Store, k: any, v: any, e: interval) : bool
	{
	return __push(h, k, v, e);
	}

function pop(h: opaque of Broker::Store, k: any, e: interval) : bool
	{
	return __pop(h, k, e);
	}

function clear(h: opaque of Broker::Store) : bool
	{
	return __clear(h);
	}

function data_type(d: Broker::Data): Broker::DataType
	{
	return __data_type(d);
	}

function data(d: any): Broker::Data
	{
	return __data(d);
	}

function set_create(): Broker::Data
	{
	return __set_create();
	}

function set_clear(s: Broker::Data) : bool
	{
	return __set_clear(s);
	}

function set_size(s: Broker::Data): count
	{
	return __set_size(s);
	}

function set_contains(s: Broker::Data, key: any) : bool
	{
	return __set_contains(s, key);
	}

function set_insert(s: Broker::Data, key: any) : bool
	{
	return __set_insert(s, key);
	}

function set_remove(s: Broker::Data, key: any) : bool
	{
	return __set_remove(s, key);
	}

function set_iterator(s: Broker::Data): opaque of Broker::SetIterator
	{
	return __set_iterator(s);
	}

function set_iterator_last(it: opaque of Broker::SetIterator) : bool
	{
	return __set_iterator_last(it);
	}

function set_iterator_next(it: opaque of Broker::SetIterator) : bool
	{
	return __set_iterator_next(it);
	}

function set_iterator_value(it: opaque of Broker::SetIterator): Broker::Data
	{
	return __set_iterator_value(it);
	}

function table_create(): Broker::Data
	{
	return __table_create();
	}

function table_clear(t: Broker::Data) : bool
	{
	return __table_clear(t);
	}

function table_size(t: Broker::Data): count
	{
	return __table_size(t);
	}

function table_contains(t: Broker::Data, key: any) : bool
	{
	return __table_contains(t, key);
	}

function table_insert(t: Broker::Data, key: any, val: any): Broker::Data
	{
	return __table_insert(t, key, val);
	}

function table_remove(t: Broker::Data, key: any): Broker::Data
	{
	return __table_remove(t, key);
	}

function table_lookup(t: Broker::Data, key: any): Broker::Data
	{
	return __table_lookup(t, key);
	}

function table_iterator(t: Broker::Data): opaque of Broker::TableIterator
	{
	return __table_iterator(t);
	}

function table_iterator_last(it: opaque of Broker::TableIterator) : bool
	{
	return __table_iterator_last(it);
	}

function table_iterator_next(it: opaque of Broker::TableIterator) : bool
	{
	return __table_iterator_next(it);
	}

function table_iterator_value(it: opaque of Broker::TableIterator): Broker::TableItem
	{
	return __table_iterator_value(it);
	}

function vector_create(): Broker::Data
	{
	return __vector_create();
	}

function vector_clear(v: Broker::Data) : bool
	{
	return __vector_clear(v);
	}

function vector_size(v: Broker::Data): count
	{
	return __vector_size(v);
	}

function vector_insert(v: Broker::Data, idx: count, d: any) : bool
	{
	return __vector_insert(v, idx, d);
	}

function vector_replace(v: Broker::Data, idx: count, d: any): Broker::Data
	{
	return __vector_replace(v, idx, d);
	}

function vector_remove(v: Broker::Data, idx: count): Broker::Data
	{
	return __vector_remove(v, idx);
	}

function vector_lookup(v: Broker::Data, idx: count): Broker::Data
	{
	return __vector_lookup(v, idx);
	}

function vector_iterator(v: Broker::Data): opaque of Broker::VectorIterator
	{
	return __vector_iterator(v);
	}

function vector_iterator_last(it: opaque of Broker::VectorIterator) : bool
	{
	return __vector_iterator_last(it);
	}

function vector_iterator_next(it: opaque of Broker::VectorIterator) : bool
	{
	return __vector_iterator_next(it);
	}

function vector_iterator_value(it: opaque of Broker::VectorIterator): Broker::Data
	{
	return __vector_iterator_value(it);
	}

function record_create(sz: count): Broker::Data
	{
	return __record_create(sz);
	}

function record_size(r: Broker::Data): count
	{
	return __record_size(r);
	}

function record_assign(r: Broker::Data, idx: count, d: any) : bool
	{
	return __record_assign(r, idx, d);
	}

function record_lookup(r: Broker::Data, idx: count): Broker::Data
	{
	return __record_lookup(r, idx);
	}

function record_iterator(r: Broker::Data): opaque of Broker::RecordIterator
	{
	return __record_iterator(r);
	}

function record_iterator_last(it: opaque of Broker::RecordIterator) : bool
	{
	return __record_iterator_last(it);
	}

function record_iterator_next(it: opaque of Broker::RecordIterator) : bool
	{
	return __record_iterator_next(it);
	}

function record_iterator_value(it: opaque of Broker::RecordIterator): Broker::Data
	{
	return __record_iterator_value(it);
	}
