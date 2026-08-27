
module Spicy;

export {


    const available = T;


    const enable_print = F &redef;


    const enable_profiling = F &redef;


    const abort_on_exceptions = F &redef;


    const show_backtraces = F &redef;


    const max_file_depth: count = 5 &redef;





    type ResourceUsage: record {
        user_time : interval;
        system_time :interval;
        memory_heap : count;
        num_fibers : count;
        max_fibers: count;
        max_fiber_stack_size: count;
        cached_fibers: count;
    };

}
