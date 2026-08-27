

#include "pac_cstr.h"

#include <exception>

#include "pac_dbg.h"
#include "pac_exception.h"

namespace {

class EscapeException : public std::exception {
public:
    explicit EscapeException(const string& s) { msg_ = s; }

    [[deprecated("Remove in v9.1. Use what().")]]
    const string& msg() const {
        return msg_;
    }
    const char* what() const noexcept override { return msg_.c_str(); }

private:
    string msg_;
};


int expand_escape(const char*& s) {
    switch ( *(s++) ) {
        case 'b': return '\b';
        case 'f': return '\f';
        case 'n': return '\n';
        case 'r': return '\r';
        case 't': return '\t';
        case 'a': return '\a';
        case 'v': return '\v';

        case '0':
        case '1':
        case '2':
        case '3':
        case '4':
        case '5':
        case '6':
        case '7': {
            --s;
            const char* start = s;









            for ( int len = 0; len < 3 && isascii(*s) && isdigit(*s); ++s, ++len )
                ;

            unsigned int result;
            if ( sscanf(start, "%3o", &result) != 1 )
                throw EscapeException(strfmt("bad octal escape: \"%s", start));


            return static_cast<int>(result);
        }

        case 'x': {
            const char* start = s;


            for ( int len = 0; len < 2 && isascii(*s) && isxdigit(*s); ++s, ++len )
                ;

            unsigned int result;
            if ( sscanf(start, "%2x", &result) != 1 )
                throw EscapeException(strfmt("bad hexadecimal escape: \"%s", start));


            return static_cast<int>(result);
        }

        default: return s[-1];
    }
}

}

ConstString::ConstString(string s) : str_(std::move(s)) {

    try {
        const char* text = str_.c_str();
        int len = strlen(text) + 1;
        int i = 0;

        char* new_s = new char[len];


        for ( ++text; *text; ++text ) {
            if ( *text == '\\' ) {
                ++text;
                new_s[i++] = expand_escape(text);
                --text;
            }
            else {
                new_s[i++] = *text;
            }
        }
        ASSERT(i < len);


        ASSERT(new_s[i - 1] == '"');
        new_s[i - 1] = '\0';

        unescaped_ = new_s;
        delete[] new_s;
    } catch ( EscapeException const& e ) {

        throw Exception(this, e.what());
    }
}
