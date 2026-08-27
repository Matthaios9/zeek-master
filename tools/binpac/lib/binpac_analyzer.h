

#ifndef binpac_an_h
#define binpac_an_h

namespace binpac {




class ConnectionAnalyzer {
public:
    virtual ~ConnectionAnalyzer() = default;
    virtual void NewData(bool is_orig, const unsigned char* begin_of_data, const unsigned char* end_of_data) = 0;
};


class FlowAnalyzer {
public:
    virtual ~FlowAnalyzer() = default;
    virtual void NewData(const unsigned char* begin_of_data, const unsigned char* end_of_data) = 0;
};

}

#endif
