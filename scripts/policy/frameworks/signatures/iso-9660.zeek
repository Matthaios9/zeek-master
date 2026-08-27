

@load-sigs ./iso-9660


@if ( default_file_bof_buffer_size < (16 + 1) * 2048 )
redef default_file_bof_buffer_size = (16 + 1) * 2048;
@endif
