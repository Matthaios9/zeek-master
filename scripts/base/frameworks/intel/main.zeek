




@load base/frameworks/notice

module Intel;

export {
	redef enum Log::ID += { LOG };

	global log_policy: Log::PolicyHook;


	type Type: enum {

		ADDR,

		SUBNET,

		URL,

		SOFTWARE,

		EMAIL,

		DOMAIN,

		USER_NAME,

		CERT_HASH,


		PUBKEY_HASH,
	};


	type TypeSet: set[Type];


	type MetaData: record {



		source:      string;

		desc:        string      &optional;

		url:         string      &optional;
	};


	type Item: record {

		indicator:      string;


		indicator_type: Type;



		meta:           MetaData;
	};



	type Where: enum {

		IN_ANYWHERE,
	};


	type Seen: record {

		indicator:       string        &log &optional;


		indicator_type:  Type          &log &optional;



		host:            addr          &optional;


		where:           Where         &log;


		node:            string        &optional &log;



		conn:            connection    &optional;





		uid:             string        &optional;
	};



	type Info: record {

		ts:       time           &log;



		uid:      string         &log &optional;


		id:       conn_id        &log &optional;


		seen:     Seen           &log;

		matched:  TypeSet        &log;

		sources:  set[string]    &log &default=string_set();
	};





	global insert: function(item: Item);



	global remove: function(item: Item, purge_indicator: bool &default = F);



	global seen: function(s: Seen);










	global match: event(s: Seen, items: set[Item]);













	global extend_match: hook(info: Info, s: Seen, items: set[Item]);




















	global seen_policy: hook(s: Seen, found: bool);





	const item_expiration = -1 min &redef;












	global item_expired: hook(indicator: string, indicator_type: Type, metas: set[MetaData]);







	global filter_item: hook(item: Intel::Item);















	global indicator_inserted: hook(indicator: string, indiator_type: Type);












	global indicator_removed: hook(indicator: string, indiator_type: Type);

	global log_intel: event(rec: Info);
}


global match_remote: event(s: Seen);


global new_item: event(item: Item);
global remove_item: event(item: Item, purge_indicator: bool);
global remove_indicator: event(item: Item);



const have_full_data = T &redef;


type MetaDataTable: table[string] of MetaData;


global expire_host_data: function(data: table[addr] of MetaDataTable, idx: addr): interval;
global expire_subnet_data: function(data: table[subnet] of MetaDataTable, idx: subnet): interval;
global expire_string_data: function(data: table[string, Type] of MetaDataTable, idx: any): interval;


type DataStore: record {
	host_data:    table[addr] of MetaDataTable &write_expire=item_expiration &expire_func=expire_host_data;
	subnet_data:  table[subnet] of MetaDataTable &write_expire=item_expiration &expire_func=expire_subnet_data;
	string_data:  table[string, Type] of MetaDataTable &write_expire=item_expiration &expire_func=expire_string_data;
};
global data_store: DataStore &redef;




type MinDataStore: record {
	host_data:    set[addr];
	subnet_data:  set[subnet];
	string_data:  set[string, Type];
};
global min_data_store: MinDataStore &redef;


event zeek_init() &priority=5
	{
	Log::create_stream(LOG, Log::Stream($columns=Info, $ev=log_intel, $path="intel", $policy=log_policy));
	}


function expire_item(indicator: string, indicator_type: Type, metas: set[MetaData]): interval
	{
	if ( hook item_expired(indicator, indicator_type, metas) )
		return item_expiration;
	else
		remove(Item($indicator=indicator, $indicator_type=indicator_type, $meta=MetaData($source="")), T);
	return 0 sec;
	}


function expire_host_data(data: table[addr] of MetaDataTable, idx: addr): interval
	{
	local meta_tbl: MetaDataTable = data[idx];
	local metas: set[MetaData];
	for ( _, md in meta_tbl )
		add metas[md];

	return expire_item(cat(idx), ADDR, metas);
	}

function expire_subnet_data(data: table[subnet] of MetaDataTable, idx: subnet): interval
	{
	local meta_tbl: MetaDataTable = data[idx];
	local metas: set[MetaData];
	for ( _, md in meta_tbl )
		add metas[md];

	return expire_item(cat(idx), SUBNET, metas);
	}

function expire_string_data(data: table[string, Type] of MetaDataTable, idx: any): interval
	{
	local indicator: string;
	local indicator_type: Type;
	[indicator, indicator_type] = idx;

	local meta_tbl: MetaDataTable = data[indicator, indicator_type];
	local metas: set[MetaData];
	for ( _, md in meta_tbl )
		add metas[md];

	return expire_item(indicator, indicator_type, metas);
	}


function find(s: Seen): bool
	{
	if ( s?$host )
		{
		if ( have_full_data )
			return ((s$host in data_store$host_data) ||
			        (|matching_subnets(s$host as subnet, data_store$subnet_data)| > 0));
		else
			return ((s$host in min_data_store$host_data) ||
			        (|matching_subnets(s$host as subnet, min_data_store$subnet_data)| > 0));
		}
	else
		{
		if ( have_full_data )
			return ([to_lower(s$indicator), s$indicator_type] in data_store$string_data);
		else
			return ([to_lower(s$indicator), s$indicator_type] in min_data_store$string_data);
		}
	}



function get_items(s: Seen): set[Item]
	{
	local return_data: set[Item];
	local mt: MetaDataTable;

	if ( ! have_full_data )
		{
		Reporter::warning(fmt("Intel::get_items was called from a host (%s) that doesn't have the full data.",
			peer_description));
		return return_data;
		}

	if ( s?$host )
		{

		if ( s$host in data_store$host_data )
			{
			mt = data_store$host_data[s$host];
			for ( _, md in mt )
				{
				add return_data[Item($indicator=cat(s$host), $indicator_type=ADDR, $meta=md)];
				}
			}

		local nets: table[subnet] of MetaDataTable;
		nets = filter_subnet_table(s$host as subnet, data_store$subnet_data);
		for ( n, mt in nets )
			{
				for ( _, md in mt )
					{
					add return_data[Item($indicator=cat(n), $indicator_type=SUBNET, $meta=md)];
					}
			}
		}
	else
		{
		local lower_indicator = to_lower(s$indicator);

		if ( [lower_indicator, s$indicator_type] in data_store$string_data )
			{
			mt = data_store$string_data[lower_indicator, s$indicator_type];
			for ( m, md in mt )
				{
				add return_data[Item($indicator=s$indicator, $indicator_type=s$indicator_type, $meta=md)];
				}
			}
		}

	return return_data;
	}

function Intel::seen(s: Seen)
	{
	local found = find(s);

	if ( ! hook Intel::seen_policy(s, found) )
		return;

	if ( ! found )
		return;

	if ( s?$host )
		{
		s$indicator = cat(s$host);
		s$indicator_type = Intel::ADDR;
		}

	if ( ! s?$node )
		s$node = peer_description;

	if ( have_full_data )
		{
		local items = get_items(s);
		event Intel::match(s, items);
		}
	else
		{
		event Intel::match_remote(s);
		}
	}

event Intel::match(s: Seen, items: set[Item]) &priority=5
	{
	local info = Info($ts=network_time(), $seen=s, $matched=TypeSet());

	if ( hook extend_match(info, s, items) )
		Log::write(Intel::LOG, info);
	}

hook extend_match(info: Info, s: Seen, items: set[Item]) &priority=5
	{

	if ( s?$conn )
		{
		s$uid = s$conn$uid;
		info$id  = s$conn$id;
		}

	if ( s?$uid )
		info$uid = s$uid;

	for ( item in items )
		{
		add info$sources[item$meta$source];
		add info$matched[item$indicator_type];
		}
	}



function insert_meta_data(item: Item): bool
	{

	local meta = item$meta;
	local meta_tbl: table [string] of MetaData;
	local is_new: bool = T;


	local lower_indicator = to_lower(item$indicator);

	switch ( item$indicator_type )
		{
		case ADDR:
			local host = item$indicator as addr;

			if ( host !in data_store$host_data )
				data_store$host_data[host] = table();
			else
				{
				is_new = F;

				data_store$host_data[host] = data_store$host_data[host];
				}

			meta_tbl = data_store$host_data[host];
			break;
		case SUBNET:
			local net = to_subnet(item$indicator);

			if ( !check_subnet(net, data_store$subnet_data) )
				data_store$subnet_data[net] = table();
			else
				{
				is_new = F;

				data_store$subnet_data[net] = data_store$subnet_data[net];
				}

			meta_tbl = data_store$subnet_data[net];
			break;
		default:
			if ( [lower_indicator, item$indicator_type] !in data_store$string_data )
				data_store$string_data[lower_indicator, item$indicator_type] = table();
			else
				{
				is_new = F;

				data_store$string_data[lower_indicator, item$indicator_type] =
					data_store$string_data[lower_indicator, item$indicator_type];
				}

			meta_tbl = data_store$string_data[lower_indicator, item$indicator_type];
			break;
		}


	meta_tbl[meta$source] = meta;

	return is_new;
	}



function _insert(item: Item, first_dispatch: bool &default = T)
	{





	local is_new: bool = T &is_used;


	local lower_indicator = to_lower(item$indicator);






	local inserted = F;
	local inserted_value = "";


	switch ( item$indicator_type )
		{
		case ADDR:
			local host = item$indicator as addr;
			if ( host !in min_data_store$host_data )
				{
				inserted = T;
				inserted_value = cat(host);
				}

			add min_data_store$host_data[host];
			break;
		case SUBNET:
			local net = to_subnet(item$indicator);
			if ( net !in min_data_store$subnet_data )
				{
				inserted = T;
				inserted_value = cat(net);
				}

			add min_data_store$subnet_data[net];
			break;
		default:
			if ( [lower_indicator, item$indicator_type] !in min_data_store$string_data )
				{
				inserted = T;
				inserted_value = lower_indicator;
				}

			add min_data_store$string_data[lower_indicator, item$indicator_type];
			break;
		}

	if ( have_full_data )
		{

		is_new = insert_meta_data(item);
		}

	if ( first_dispatch && is_new )


		event Intel::new_item(item);

	if ( inserted )
		hook Intel::indicator_inserted(inserted_value, item$indicator_type);
	}

function insert(item: Item)
	{
	if ( hook filter_item(item) )
		{

		_insert(item, T);
		}
	}


function item_exists(item: Item): bool
	{
	switch ( item$indicator_type )
		{
		case ADDR:
			return have_full_data ? item$indicator as addr in data_store$host_data :
			                        item$indicator as addr in min_data_store$host_data;
		case SUBNET:
			return have_full_data ? to_subnet(item$indicator) in data_store$subnet_data :
			                        to_subnet(item$indicator) in min_data_store$subnet_data;
		default:
			return have_full_data ? [to_lower(item$indicator), item$indicator_type] in data_store$string_data :
			                        [to_lower(item$indicator), item$indicator_type] in min_data_store$string_data;
		}
	}



function remove_meta_data(item: Item): bool
	{
	if ( ! have_full_data )
		{
		Reporter::warning(fmt("Intel::remove_meta_data was called from a host (%s) that doesn't have the full data.",
			peer_description));
		return F;
		}

	switch ( item$indicator_type )
		{
		case ADDR:
			local host = item$indicator as addr;
			delete data_store$host_data[host][item$meta$source];
			return (|data_store$host_data[host]| == 0);
		case SUBNET:
			local net = to_subnet(item$indicator);
			delete data_store$subnet_data[net][item$meta$source];
			return (|data_store$subnet_data[net]| == 0);
		default:
			delete data_store$string_data[to_lower(item$indicator), item$indicator_type][item$meta$source];
			return (|data_store$string_data[to_lower(item$indicator), item$indicator_type]| == 0);
		}
	}

function remove(item: Item, purge_indicator: bool)
	{

	if ( ! item_exists(item) )
		{
		Reporter::info(fmt("Tried to remove non-existing item '%s' (%s).",
			item$indicator, item$indicator_type));
		return;
		}


	if ( !have_full_data )
		{
		event Intel::remove_item(item, purge_indicator);
		return;
		}


	local no_meta_data = remove_meta_data(item);

	if ( no_meta_data || purge_indicator )
		{
		switch ( item$indicator_type )
			{
			case ADDR:
				local host = item$indicator as addr;
				delete data_store$host_data[host];
				break;
			case SUBNET:
				local net = to_subnet(item$indicator);
				delete data_store$subnet_data[net];
				break;
			default:
				delete data_store$string_data[to_lower(item$indicator), item$indicator_type];
				break;
			}

		event Intel::remove_indicator(item);
		}
	}


event remove_indicator(item: Item)
	{
	local removed = F;
	local removed_value = "";

	switch ( item$indicator_type )
		{
		case ADDR:
			local host = item$indicator as addr;
			if ( host in min_data_store$host_data )
				{
				removed = T;
				removed_value = cat(host);
				}

			delete min_data_store$host_data[host];
			break;
		case SUBNET:
			local net = to_subnet(item$indicator);
			if ( net in min_data_store$subnet_data )
				{
				removed = T;
				removed_value = cat(net);
				}

			delete min_data_store$subnet_data[net];
			break;
		default:
			local indicator_value = to_lower(item$indicator);
			if ( [indicator_value, item$indicator_type] in min_data_store$string_data )
				{
				removed = T;
				removed_value = indicator_value;
				}

			delete min_data_store$string_data[indicator_value, item$indicator_type];
			break;
		}

	if ( removed )
		hook Intel::indicator_removed(removed_value, item$indicator_type);
	}
