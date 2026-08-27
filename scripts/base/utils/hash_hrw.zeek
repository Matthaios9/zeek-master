



module HashHRW;

export {


	type Site: record {


		id: count;

		user_data: any &optional;
	};


	type SiteTable: table[count] of Site;


	type Pool: record {
		sites: SiteTable &default=SiteTable();
	};




	global add_site: function(pool: Pool, site: Site): bool;




	global rem_site: function(pool: Pool, site: Site): bool;


	global get_site: function(pool: Pool, key: any): Site;
}

function add_site(pool: Pool, site: Site): bool
	{
	if ( site$id in pool$sites )
		return F;

	pool$sites[site$id] = site;
	return T;
	}

function rem_site(pool: Pool, site: Site): bool
	{
	if ( site$id !in pool$sites )
		return F;

	delete pool$sites[site$id];
	return T;
	}

function get_site(pool: Pool, key: any): Site
	{
    local best_site_id = 0;
    local best_weight = -1;
    local d = fnv1a32(key);

    for ( site_id in pool$sites )
        {
        local w = hrw_weight(d, site_id);

        if ( w > best_weight || (w == best_weight && site_id > best_site_id) )
            {
            best_weight = w;
            best_site_id = site_id;
            }
        }

    return pool$sites[best_site_id];
	}
