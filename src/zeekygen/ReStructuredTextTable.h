

#pragma once

#include <string>
#include <vector>

namespace zeek::zeekygen::detail {




class ReStructuredTextTable {
public:




    explicit ReStructuredTextTable(size_t arg_num_cols);





    void AddRow(const std::vector<std::string>& new_row);







    static std::string MakeBorder(const std::vector<size_t>& col_sizes, char border);





    std::string AsString(char border) const;

private:
    size_t num_cols;
    std::vector<std::vector<std::string>> rows;
    std::vector<size_t> longest_row_in_column;
};

}
