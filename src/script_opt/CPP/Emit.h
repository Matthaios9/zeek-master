






friend class CPP_BasicConstInitsInfo;
friend class CPP_CompoundInitsInfo;
friend class IndicesManager;




void StartBlock();
void EndBlock(bool needs_semi = false);

void IndentUp() { ++block_level; }
void IndentDown() { --block_level; }




void Emit(const std::string& str) const {
    Indent();
    fprintf(write_file, "%s", str.c_str());
    NL();
}

void Emit(const std::string& fmt, const std::string& arg, bool do_NL = true) const {
    Indent();
    fprintf(write_file, fmt.c_str(), arg.c_str());
    if ( do_NL )
        NL();
}

void Emit(const std::string& fmt, const std::string& arg1, const std::string& arg2) const {
    Indent();
    fprintf(write_file, fmt.c_str(), arg1.c_str(), arg2.c_str());
    NL();
}

void Emit(const std::string& fmt, const std::string& arg1, const std::string& arg2, const std::string& arg3) const {
    Indent();
    fprintf(write_file, fmt.c_str(), arg1.c_str(), arg2.c_str(), arg3.c_str());
    NL();
}

void Emit(const std::string& fmt, const std::string& arg1, const std::string& arg2, const std::string& arg3,
          const std::string& arg4) const {
    Indent();
    fprintf(write_file, fmt.c_str(), arg1.c_str(), arg2.c_str(), arg3.c_str(), arg4.c_str());
    NL();
}

void Emit(const std::string& fmt, const std::string& arg1, const std::string& arg2, const std::string& arg3,
          const std::string& arg4, const std::string& arg5) const {
    Indent();
    fprintf(write_file, fmt.c_str(), arg1.c_str(), arg2.c_str(), arg3.c_str(), arg4.c_str(), arg5.c_str());
    NL();
}

void Emit(const std::string& fmt, const std::string& arg1, const std::string& arg2, const std::string& arg3,
          const std::string& arg4, const std::string& arg5, const std::string& arg6) const {
    Indent();
    fprintf(write_file, fmt.c_str(), arg1.c_str(), arg2.c_str(), arg3.c_str(), arg4.c_str(), arg5.c_str(),
            arg6.c_str());
    NL();
}

void Emit(const std::string& fmt, const std::string& arg1, const std::string& arg2, const std::string& arg3,
          const std::string& arg4, const std::string& arg5, const std::string& arg6, const std::string& arg7) const {
    Indent();
    fprintf(write_file, fmt.c_str(), arg1.c_str(), arg2.c_str(), arg3.c_str(), arg4.c_str(), arg5.c_str(), arg6.c_str(),
            arg7.c_str());
    NL();
}

void NL() const { fputc('\n', write_file); }


void Indent() const;


FILE* write_file;


int block_level = 0;
