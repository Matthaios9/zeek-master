




#pragma once

namespace zeek::detail {

class StmtOptInfo {
public:

    int stmt_num = -1;




    int block_level = -1;



    bool contains_branch_beyond = false;



    bool is_free_of_conditionals = true;


    int num_stmts = 0;
    int num_exprs = 0;
};

}
