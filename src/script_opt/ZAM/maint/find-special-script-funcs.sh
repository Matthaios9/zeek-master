#! /bin/sh





grep -h -r -w find_func $* |


    sed 's,.*find_func,,' |


    grep '"' |



    grep -v '\\"' |


    sed 's,^[^"]*",,;s,"[^"]*$,,' |


    sort -u
