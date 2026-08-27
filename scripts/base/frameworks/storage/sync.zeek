

@load ./main

module Storage::Sync;

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
	return Storage::Sync::__open_backend(btype, options, key_type, val_type);
	}

function close_backend(backend: opaque of Storage::BackendHandle)
    : Storage::OperationResult
	{
	return Storage::Sync::__close_backend(backend);
	}

function put(backend: opaque of Storage::BackendHandle, args: Storage::PutArgs)
    : Storage::OperationResult
	{
	return Storage::Sync::__put(backend, args$key, args$value, args$overwrite,
	    args$expire_time);
	}

function get(backend: opaque of Storage::BackendHandle, key: any)
    : Storage::OperationResult
	{
	return Storage::Sync::__get(backend, key);
	}

function erase(backend: opaque of Storage::BackendHandle, key: any)
    : Storage::OperationResult
	{
	return Storage::Sync::__erase(backend, key);
	}
