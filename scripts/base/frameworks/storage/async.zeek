

@load ./main

module Storage::Async;

export {




















	global open_backend: function(btype: Storage::Backend, options: Storage::BackendOptions,
	    key_type: any, val_type: any): Storage::OperationResult;








	global close_backend: function(backend: opaque of Storage::BackendHandle)
	    : Storage::OperationResult;











	global put: function(backend: opaque of Storage::BackendHandle,
	    args: Storage::PutArgs): Storage::OperationResult;












	global get: function(backend: opaque of Storage::BackendHandle, key: any)
	    : Storage::OperationResult;










	global erase: function(backend: opaque of Storage::BackendHandle, key: any)
	    : Storage::OperationResult;
}

function open_backend(btype: Storage::Backend, options: Storage::BackendOptions,
    key_type: any, val_type: any): Storage::OperationResult
	{
	if ( options$forced_sync )
		return Storage::Sync::__open_backend(btype, options, key_type, val_type);
	else
		return Storage::Async::__open_backend(btype, options, key_type, val_type);
	}

function close_backend(backend: opaque of Storage::BackendHandle)
    : Storage::OperationResult
	{
	if ( Storage::is_forced_sync(backend) )
		return Storage::Sync::__close_backend(backend);
	else
		return Storage::Async::__close_backend(backend);
	}

function put(backend: opaque of Storage::BackendHandle, args: Storage::PutArgs)
    : Storage::OperationResult
	{
	if ( Storage::is_forced_sync(backend) )
		return Storage::Sync::__put(backend, args$key, args$value, args$overwrite,
		    args$expire_time);
	else
		return Storage::Async::__put(backend, args$key, args$value, args$overwrite,
		    args$expire_time);
	}

function get(backend: opaque of Storage::BackendHandle, key: any)
    : Storage::OperationResult
	{
	if ( Storage::is_forced_sync(backend) )
		return Storage::Sync::__get(backend, key);
	else
		return Storage::Async::__get(backend, key);
	}

function erase(backend: opaque of Storage::BackendHandle, key: any)
    : Storage::OperationResult
	{
	if ( Storage::is_forced_sync(backend) )
		return Storage::Sync::__erase(backend, key);
	else
		return Storage::Async::__erase(backend, key);
	}
