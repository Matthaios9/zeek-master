

#include "zeek/SmithWaterman.h"

#include <algorithm>
#include <cctype>

#include "zeek/Reporter.h"
#include "zeek/Val.h"
#include "zeek/Var.h"
#include "zeek/util.h"

namespace zeek::detail {

Substring::Substring(const Substring& bst) : String(bst), _num(), _new(bst._new) {
    for ( const auto& align : bst._aligns )
        _aligns.push_back(align);
}

const Substring& Substring::operator=(const Substring& bst) {
    String::operator=(bst);

    _aligns.clear();

    for ( const auto& align : bst._aligns )
        _aligns.push_back(align);

    _new = bst._new;

    return *this;
}

void Substring::AddAlignment(const String* str, int index) { _aligns.emplace_back(str, index); }

bool Substring::DoesCover(const Substring* bst) const {
    if ( _aligns.size() != bst->_aligns.size() )
        return false;

    auto it_bst = bst->_aligns.begin();

    for ( auto it = _aligns.begin(); it != _aligns.end(); ++it, ++it_bst ) {
        const BSSAlign& a = *it;
        const BSSAlign& a_bst = *it_bst;

        if ( a.index > a_bst.index || a.index + Len() < a_bst.index + bst->Len() )
            return false;
    }

    return true;
}

VectorVal* Substring::VecToPolicy(Vec* vec) {
    static auto sw_substring_type = id::find_type<RecordType>("sw_substring");
    static auto sw_align_type = id::find_type<RecordType>("sw_align");
    static auto sw_align_vec_type = id::find_type<VectorType>("sw_align_vec");
    static auto sw_substring_vec_type = id::find_type<VectorType>("sw_substring_vec");

    auto result = make_intrusive<VectorVal>(sw_substring_vec_type);

    if ( vec ) {
        for ( size_t i = 0; i < vec->size(); ++i ) {
            Substring* bst = (*vec)[i];

            auto st_val = make_intrusive<RecordVal>(sw_substring_type);
            st_val->Assign(0, new String(*bst));

            auto aligns = make_intrusive<VectorVal>(sw_align_vec_type);

            for ( unsigned int j = 0; j < bst->GetNumAlignments(); ++j ) {
                const BSSAlign& align = (bst->GetAlignments())[j];

                auto align_val = make_intrusive<RecordVal>(sw_align_type);
                align_val->Assign(0, new String(*align.string));
                align_val->Assign(1, align.index);

                aligns->Assign(j, std::move(align_val));
            }

            st_val->Assign(1, std::move(aligns));
            st_val->Assign(2, bst->IsNewAlignment());
            result->Assign(i, std::move(st_val));
        }
    }

    return result.release();
}

Substring::Vec* Substring::VecFromPolicy(VectorVal* vec) {
    Vec* result = new Vec();

    for ( unsigned int i = 0; i < vec->Size(); ++i ) {
        auto v = vec->RecordValAt(i);
        if ( ! v )
            continue;

        const String* str = v->GetFieldAs<StringVal>(0);
        auto* substr = new Substring(*str);

        const VectorVal* aligns = v->GetFieldAs<VectorVal>(1);
        for ( unsigned int j = 1; j <= aligns->Size(); ++j ) {
            const RecordVal* align = aligns->AsVectorVal()->RecordValAt(j);
            const String* str = align->GetFieldAs<StringVal>(0);
            int index = align->GetFieldAs<CountVal>(1);
            substr->AddAlignment(str, index);
        }

        bool new_alignment = v->GetFieldAs<BoolVal>(2);
        substr->MarkNewAlignment(new_alignment);

        result->push_back(substr);
    }

    return result;
}

char* Substring::VecToString(Vec* vec) {
    std::string result("[");

    for ( const auto& ss : *vec ) {
        result += ss->CheckString();
        result += ',';
    }

    result += ']';
    return strdup(result.c_str());
}

String::IdxVec* Substring::GetOffsetsVec(const Vec* vec, unsigned int index) {
    String::IdxVec* result = new String::IdxVec();

    for ( const auto& bst : *vec ) {
        if ( bst->_aligns.size() <= index )
            continue;

        const BSSAlign& align = bst->_aligns[index];
        int start = align.index;
        int end = start + bst->Len();

        result->push_back(start);
        result->push_back(end);
    }

    return result;
}

bool SubstringCmp::operator()(const Substring* bst1, const Substring* bst2) const {
    if ( _index >= bst1->GetNumAlignments() || _index >= bst2->GetNumAlignments() ) {
        reporter->Warning("SubstringCmp::operator(): invalid index for input strings.\n");
        return false;
    }

    return (bst1->GetAlignments()[_index].index < bst2->GetAlignments()[_index].index);
}







struct SWNode {

    int id;

    u_char swn_byte;
    bool swn_byte_assigned;
    bool swn_visited;



    int swn_score;


    SWNode* swn_prev;
};



class SWNodeMatrix {
public:
    SWNodeMatrix(const String* s1, const String* s2) : _s1(s1), _s2(s2), _rows(s1->Len() + 1), _cols(s2->Len() + 1) {
        _nodes = new SWNode[_cols * _rows];
        memset(_nodes, 0, sizeof(SWNode) * _cols * _rows);
    }

    ~SWNodeMatrix() { delete[] _nodes; }

    SWNode* operator()(int row, int col) {

        if ( row < 0 || static_cast<size_t>(row) >= _rows )
            return nullptr;
        if ( col < 0 || static_cast<size_t>(col) >= _cols )
            return nullptr;

        return &(_nodes[row * _cols + col]);
    }

    const String* GetRowsString() const { return _s1; }
    const String* GetColsString() const { return _s2; }

    int GetHeight() const { return _rows; }
    int GetWidth() const { return _cols; }




    void GetNodeIndices(SWNode* node, int& row, int& col) {
        SWNode* base = &_nodes[0];
        int offset = (node - base);
        col = (offset % _cols);
        row = (offset / _cols);
    }

private:
    const String* _s1;
    const String* _s2;

    size_t _rows, _cols;
    SWNode* _nodes;
};







static void sw_collect_single(Substring::Vec* result, SWNodeMatrix& matrix, SWNode* node, SWParams& params) {
    std::string substring("");
    int row = 0;
    int col = 0;

    while ( node ) {

        node->swn_visited = true;





        if ( node->swn_byte_assigned ) {
            matrix.GetNodeIndices(node, row, col);
            substring += node->swn_byte;

        }
        else {

            if ( substring.size() >= params._min_toklen ) {
                std::ranges::reverse(substring);
                auto* bst = new Substring(substring);
                bst->AddAlignment(matrix.GetRowsString(), row - 1);
                bst->AddAlignment(matrix.GetColsString(), col - 1);
                result->push_back(bst);
            }

            substring = "";
        }

        node = node->swn_prev;
    }




    if ( ! substring.empty() ) {
        std::ranges::reverse(substring);
        auto* bst = new Substring(substring);
        bst->AddAlignment(matrix.GetRowsString(), row - 1);
        bst->AddAlignment(matrix.GetColsString(), col - 1);
        result->push_back(bst);
    }

    if ( ! result->empty() )
        result->back()->MarkNewAlignment(true);
}










static void sw_collect_multiple(Substring::Vec* result, SWNodeMatrix& matrix, SWParams& params) {
    std::vector<Substring::Vec*> als;

    for ( int i = matrix.GetHeight() - 1; i > 0; --i ) {
        for ( int j = matrix.GetWidth() - 1; j > 0; --j ) {
            SWNode* node = matrix(i, j);

            if ( ! (node->swn_byte_assigned && ! node->swn_visited) )
                continue;

            auto* new_al = new Substring::Vec();
            sw_collect_single(new_al, matrix, node, params);

            for ( auto& old_al : als ) {
                if ( old_al == nullptr )
                    continue;

                for ( const auto& old_ss : *old_al ) {
                    for ( const auto& new_ss : *new_al ) {
                        if ( old_ss->DoesCover(new_ss) ) {
                            util::delete_each(new_al);
                            delete new_al;
                            new_al = nullptr;
                            goto end_loop;
                        }

                        if ( new_ss->DoesCover(old_ss) ) {
                            util::delete_each(old_al);
                            delete old_al;
                            old_al = nullptr;
                            goto end_loop;
                        }
                    }
                }
            }

        end_loop:
            if ( new_al )
                als.push_back(new_al);
        }
    }

    for ( const auto& al : als ) {
        if ( al == nullptr )
            continue;

        for ( const auto& bst : *al )
            result->push_back(bst);

        delete al;
    }
}



Substring::Vec* smith_waterman(const String* s1, const String* s2, SWParams& params) {
    auto* result = new Substring::Vec();

    if ( ! s1 || s1->Len() < static_cast<int>(params._min_toklen) || ! s2 ||
         s2->Len() < static_cast<int>(params._min_toklen) )
        return result;




    int len1 = s1->Len() + 1;
    int len2 = s2->Len() + 1;

    int row = 0;
    int col = 0;

    byte_vec string1 = s1->Bytes();
    byte_vec string2 = s2->Bytes();

    SWNodeMatrix matrix(s1, s2);
    SWNode* node_max = nullptr;
    SWNode* node_br_max = nullptr;






    int matrix_max = 1;
    int br_max_r = 0;
    int br_max_b = 0;






    int counter = 1;

    for ( int i = 1; i < len1; ++i )
        for ( int j = 1; j < len2; ++j )
            matrix(i, j)->id = counter++;



    for ( int i = 1; i < len1; ++i ) {
        for ( int j = 1; j < len2; ++j ) {


            SWNode* current = matrix(i, j);
            SWNode* node_tl = matrix(i - 1, j - 1);
            SWNode* node_l = matrix(i, j - 1);
            SWNode* node_t = matrix(i - 1, j);



            int score_t = node_t->swn_score;
            int score_l = node_l->swn_score;
            int score_tl = node_tl->swn_score;






            if ( string1[i - 1] == string2[j - 1] ) {


                score_tl += 1;





                if ( node_tl->swn_byte_assigned )
                    score_tl += 99;




                current->swn_byte = string1[i - 1];
                current->swn_byte_assigned = true;
            }




            if ( current->swn_byte_assigned )
                current->swn_score = score_tl;
            else
                current->swn_score = std::max({score_t, score_l, score_tl});




            if ( current->swn_score == score_tl && current->swn_byte_assigned ) {



                if ( i >= br_max_b && j >= br_max_r ) {
                    node_br_max = current;
                    br_max_b = i;
                    br_max_r = j;
                }

                current->swn_prev = node_tl;
            }
            else if ( current->swn_score == score_t )
                current->swn_prev = node_t;
            else
                current->swn_prev = node_l;






            if ( current->swn_score > matrix_max ) {
                node_max = current;
                matrix_max = current->swn_score;
            }

#if 0
			printf("%4i/%.5i%c/%.5i[%c%c] ",
				current->swn_score,
		 		current->id,
				current->swn_byte_assigned ? '*' : ' ',
		 		current->swn_prev ? current->swn_prev->id : 0,
			       string1[i-1], string2[j-1]);
#endif

        }

#if 0
		printf("\n");
#endif
    }








    if ( params._sw_variant == SW_MULTIPLE )
        sw_collect_multiple(result, matrix, params);
    else
        sw_collect_single(result, matrix, node_max, params);

    if ( len1 > len2 )
        std::ranges::sort(*result, SubstringCmp(0));
    else
        std::ranges::sort(*result, SubstringCmp(1));

    return result;
}

}
