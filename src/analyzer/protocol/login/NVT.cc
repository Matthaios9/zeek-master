

#include "zeek/analyzer/protocol/login/NVT.h"

#include <cstdlib>

#include "zeek/Reporter.h"
#include "zeek/ZeekString.h"
#include "zeek/analyzer/protocol/login/events.bif.h"
#include "zeek/analyzer/protocol/tcp/TCP.h"

constexpr bool IS_3_BYTE_OPTION(unsigned int code) { return code >= 251 && code <= 254; }

static constexpr uint8_t TELNET_OPT_SB = 250;
static constexpr uint8_t TELNET_OPT_SE = 240;

static constexpr uint8_t TELNET_OPT_IS = 0;
static constexpr uint8_t TELNET_OPT_SEND = 1;

static constexpr uint8_t TELNET_OPT_WILL = 251;
static constexpr uint8_t TELNET_OPT_WONT = 252;
static constexpr uint8_t TELNET_OPT_DO = 253;
static constexpr uint8_t TELNET_OPT_DONT = 254;

static constexpr uint8_t TELNET_IAC = 255;

namespace zeek::analyzer::login {

TelnetOption::TelnetOption(NVT_Analyzer* arg_endp, unsigned int arg_code) : endp(arg_endp), code(arg_code) {}

void TelnetOption::RecvOption(unsigned int type) {
    TelnetOption* peer = endp->FindPeerOption(code);

    if ( ! peer ) {
        reporter->AnalyzerError(endp, "option peer missing in TelnetOption::RecvOption");
        return;
    }


    switch ( type ) {
        case TELNET_OPT_WILL:
            if ( SaidDont() || peer->SaidWont() || peer->IsActive() )
                InconsistentOption(type);

            peer->SetWill();

            if ( SaidDo() )
                peer->SetActive(true);
            break;

        case TELNET_OPT_WONT:
            if ( peer->SaidWill() && ! SaidDont() )
                InconsistentOption(type);

            peer->SetWont();

            if ( SaidDont() )
                peer->SetActive(false);
            break;

        case TELNET_OPT_DO:
            if ( SaidWont() || peer->SaidDont() || IsActive() )
                InconsistentOption(type);

            peer->SetDo();

            if ( SaidWill() )
                SetActive(true);
            break;

        case TELNET_OPT_DONT:
            if ( peer->SaidDo() && ! SaidWont() )
                InconsistentOption(type);

            peer->SetDont();

            if ( SaidWont() )
                SetActive(false);
            break;

        default: reporter->AnalyzerError(endp, "bad option type in TelnetOption::RecvOption"); return;
    }
}

void TelnetOption::RecvSubOption(u_char* , int ) {}

void TelnetOption::SetActive(bool is_active) { active = is_active; }

void TelnetOption::InconsistentOption(unsigned int ) { endp->Event(inconsistent_option); }

void TelnetOption::BadOption() { endp->Event(bad_option); }

namespace detail {

void TelnetTerminalOption::RecvSubOption(u_char* data, int len) {
    if ( len <= 0 ) {
        BadOption();
        return;
    }

    if ( data[0] == TELNET_OPT_SEND )
        return;

    if ( data[0] != TELNET_OPT_IS ) {
        BadOption();
        return;
    }

    endp->SetTerminal(data + 1, len - 1);
}

enum EncryptOptions : uint8_t {
    ENCRYPT_SET_ALGORITHM = 0,
    ENCRYPT_SUPPORT_ALGORITHM = 1,
    ENCRYPT_REPLY = 2,
    ENCRYPT_STARTING_TO_ENCRYPT = 3,
    ENCRYPT_NO_LONGER_ENCRYPTING = 4,
    ENCRYPT_REQUEST_START_TO_ENCRYPT = 5,
    ENCRYPT_REQUEST_NO_LONGER_ENCRYPT = 6,
    ENCRYPT_ENCRYPT_KEY = 7,
    ENCRYPT_DECRYPT_KEY = 8,
};

void TelnetEncryptOption::RecvSubOption(u_char* data, int len) {
    if ( ! active ) {
        InconsistentOption(0);
        return;
    }

    if ( len <= 0 ) {
        BadOption();
        return;
    }

    unsigned int opt = data[0];

    if ( opt == ENCRYPT_REQUEST_START_TO_ENCRYPT )
        ++did_encrypt_request;

    else if ( opt == ENCRYPT_STARTING_TO_ENCRYPT ) {
        TelnetEncryptOption* peer = static_cast<TelnetEncryptOption*>(endp->FindPeerOption(code));

        if ( ! peer ) {
            reporter->AnalyzerError(endp, "option peer missing in TelnetEncryptOption::RecvSubOption");
            return;
        }

        if ( peer->DidRequest() || peer->DoingEncryption() || peer->Endpoint()->AuthenticationHasBeenAccepted() ) {
            endp->SetEncrypting(1);
            ++doing_encryption;
        }
        else
            InconsistentOption(0);
    }
}

enum AuthOptions : uint8_t {
    HERE_IS_AUTHENTICATION = 0,
    SEND_ME_AUTHENTICATION = 1,
    AUTHENTICATION_STATUS = 2,
    AUTHENTICATION_NAME = 3,
};

constexpr int AUTH_REJECT = 1;
constexpr int AUTH_ACCEPT = 2;

void TelnetAuthenticateOption::RecvSubOption(u_char* data, int len) {
    if ( len <= 0 ) {
        BadOption();
        return;
    }

    switch ( data[0] ) {
        case HERE_IS_AUTHENTICATION: {
            TelnetAuthenticateOption* peer = static_cast<TelnetAuthenticateOption*>(endp->FindPeerOption(code));

            if ( ! peer ) {
                reporter->AnalyzerError(endp, "option peer missing in TelnetAuthenticateOption::RecvSubOption");
                return;
            }

            if ( ! peer->DidRequestAuthentication() )
                InconsistentOption(0);
        } break;

        case SEND_ME_AUTHENTICATION: ++authentication_requested; break;

        case AUTHENTICATION_STATUS:
            if ( len <= 1 ) {
                BadOption();
                return;
            }

            if ( data[1] == AUTH_REJECT )
                endp->AuthenticationRejected();
            else if ( data[1] == AUTH_ACCEPT )
                endp->AuthenticationAccepted();
            else {


            }
            break;

        case AUTHENTICATION_NAME: {
            char* auth_name = new char[len];
            util::safe_strncpy(auth_name, reinterpret_cast<char*>(data) + 1, len);
            endp->SetAuthName(auth_name);
        } break;

        default: BadOption();
    }
}

constexpr uint8_t ENVIRON_IS = 0;
constexpr uint8_t ENVIRON_SEND = 1;
constexpr uint8_t ENVIRON_INFO = 2;

constexpr uint8_t ENVIRON_VAR = 0;
constexpr uint8_t ENVIRON_VAL = 1;
constexpr uint8_t ENVIRON_ESC = 2;
constexpr uint8_t ENVIRON_USERVAR = 3;

void TelnetEnvironmentOption::RecvSubOption(u_char* data, int len) {
    if ( len <= 0 ) {
        BadOption();
        return;
    }

    if ( data[0] == ENVIRON_SEND )

        return;

    if ( data[0] != ENVIRON_IS && data[0] != ENVIRON_INFO ) {
        BadOption();
        return;
    }

    --len;
    ++data;

    while ( len > 0 ) {
        int code1;
        int code2;
        char* var_name = ExtractEnv(data, len, code1);
        char* var_val = ExtractEnv(data, len, code2);

        if ( ! var_name || ! var_val || (code1 != ENVIRON_VAR && code1 != ENVIRON_USERVAR) || code2 != ENVIRON_VAL ) {

            delete[] var_name;
            delete[] var_val;

            BadOption();
            break;
        }

        static_cast<analyzer::tcp::TCP_ApplicationAnalyzer*>(endp->Parent())->SetEnv(endp->IsOrig(), var_name, var_val);
    }
}

char* TelnetEnvironmentOption::ExtractEnv(u_char*& data, int& len, int& code) {
    if ( len <= 0 )
        return nullptr;

    code = data[0];

    if ( code != ENVIRON_VAR && code != ENVIRON_VAL && code != ENVIRON_USERVAR )
        return nullptr;


    --len;
    ++data;


    u_char* data_end = data + len;
    u_char* d;
    for ( d = data; d < data_end; ++d ) {
        if ( *d == ENVIRON_VAR || *d == ENVIRON_VAL || *d == ENVIRON_USERVAR )
            break;

        if ( *d == ENVIRON_ESC ) {
            ++d;
            if ( d >= data_end )
                return nullptr;
            break;
        }
    }

    int size = d - data;
    char* env = new char[size + 1];


    int d_ind = 0;
    int i;
    for ( i = 0; i < size; ++i ) {
        if ( data[d_ind] == ENVIRON_ESC )
            ++d_ind;

        env[i] = data[d_ind];
        ++d_ind;
    }

    env[i] = '\0';

    data = d;
    len -= size;

    return env;
}

void TelnetBinaryOption::SetActive(bool is_active) {
    endp->SetBinaryMode(is_active);
    active = is_active;
}

void TelnetBinaryOption::InconsistentOption(unsigned int ) {



}

}

NVT_Analyzer::NVT_Analyzer(Connection* conn, bool orig) : analyzer::tcp::ContentLine_Analyzer("NVT", conn, orig) {}

NVT_Analyzer::~NVT_Analyzer() {
    for ( int i = 0; i < num_options; ++i )
        delete options[i];

    delete[] auth_name;
}

TelnetOption* NVT_Analyzer::FindOption(unsigned int code) {
    int i;
    for ( i = 0; i < num_options; ++i )
        if ( options[i]->Code() == code )
            return options[i];

    TelnetOption* opt = nullptr;
    if ( i < NUM_TELNET_OPTIONS ) {
        switch ( code ) {
            case TELNET_OPTION_BINARY: opt = new detail::TelnetBinaryOption(this); break;

            case TELNET_OPTION_TERMINAL: opt = new detail::TelnetTerminalOption(this); break;

            case TELNET_OPTION_ENCRYPT: opt = new detail::TelnetEncryptOption(this); break;

            case TELNET_OPTION_AUTHENTICATE: opt = new detail::TelnetAuthenticateOption(this); break;

            case TELNET_OPTION_ENVIRON: opt = new detail::TelnetEnvironmentOption(this); break;

            default: break;
        }
    }

    if ( opt )
        options[num_options++] = opt;

    return opt;
}

TelnetOption* NVT_Analyzer::FindPeerOption(unsigned int code) {
    assert(peer);
    return peer->FindOption(code);
}

void NVT_Analyzer::AuthenticationAccepted() {
    authentication_has_been_accepted = true;
    Event(authentication_accepted, PeerAuthName());
}

void NVT_Analyzer::AuthenticationRejected() {
    authentication_has_been_accepted = false;
    Event(authentication_rejected, PeerAuthName());
}

const char* NVT_Analyzer::PeerAuthName() const {
    assert(peer);
    return peer->AuthName();
}

void NVT_Analyzer::SetTerminal(const u_char* terminal, int len) {
    if ( login_terminal )
        EnqueueConnEvent(login_terminal, ConnVal(), make_intrusive<StringVal>(new String(terminal, len, false)));
}

void NVT_Analyzer::SetEncrypting(int mode) {
    encrypting_mode = mode;
    SetSkipDeliveries(mode);
    if ( mode )
        Event(activating_encryption);
}

constexpr int MAX_DELIVER_UNIT = 128;

void NVT_Analyzer::DoDeliver(int len, const u_char* data) {
    while ( len > 0 ) {
        if ( pending_IAC )
            ScanOption(len, data);
        else
            DeliverChunk(len, data);
    }
}

void NVT_Analyzer::DeliverChunk(int& len, const u_char*& data) {





    for ( ; len > 0; --len, ++data ) {
        if ( offset >= buf_len ) {
            if ( ! InitBufferSafe(buf_len * 2) ) {
                LimitReachedWeird("nvt_line_size_exceeded", buf_len);



                buf[buf_len - 1] = '\0';
                ForwardStream(buf_len - 1, buf, IsOrig());
                offset = 0;


                continue;
            }
        }

        int c = data[0];

        if ( binary_mode && c != TELNET_IAC )
            c &= 0x7f;

        switch ( c ) {
            case '\r':
                if ( CRLFAsEOL() & tcp::CR_as_EOL ) {
                    buf[offset] = '\0';
                    ForwardStream(offset, buf, IsOrig());
                    offset = 0;
                }
                else
                    buf[offset++] = c;
                break;

            case '\n':
                if ( last_char == '\r' ) {
                    if ( CRLFAsEOL() & tcp::CR_as_EOL )

                        ;
                    else {
                        --offset;
                        buf[offset] = '\0';
                        ForwardStream(offset, buf, IsOrig());
                        offset = 0;
                    }
                }

                else if ( CRLFAsEOL() & tcp::LF_as_EOL ) {
                    buf[offset] = '\0';
                    ForwardStream(offset, buf, IsOrig());
                    offset = 0;
                }

                else {
                    if ( Conn()->FlagEvent(SINGULAR_LF) )
                        Weird("line_terminated_with_single_LF");
                    buf[offset++] = c;
                }
                break;

            case '\0':
                if ( last_char == '\r' )



                    ;

                else if ( flag_NULs )
                    CheckNUL();

                else
                    buf[offset++] = c;
                break;

            case TELNET_IAC:
                pending_IAC = true;
                IAC_pos = offset;
                is_suboption = false;
                buf[offset++] = c;
                --len;
                ++data;
                ScanOption(len, data);
                return;

            default: buf[offset++] = c; break;
        }

        if ( ! (CRLFAsEOL() & tcp::CR_as_EOL) && last_char == '\r' && c != '\n' && c != '\0' ) {
            if ( Conn()->FlagEvent(SINGULAR_CR) )
                Weird("line_terminated_with_single_CR");
        }

        last_char = c;
    }
}

void NVT_Analyzer::ScanOption(int& len, const u_char*& data) {
    if ( len <= 0 )
        return;

    if ( IAC_pos == offset - 1 ) {
        unsigned int code = data[0];

        if ( code == TELNET_IAC ) {


            pending_IAC = false;
            last_char = code;
        }

        else if ( code == TELNET_OPT_SB ) {
            is_suboption = true;
            last_was_IAC = false;

            if ( offset >= buf_len )
                InitBuffer(offset + 1);

            buf[offset++] = code;
        }

        else if ( IS_3_BYTE_OPTION(code) ) {
            is_suboption = false;

            if ( offset >= buf_len )
                InitBuffer(offset + 1);

            buf[offset++] = code;
        }

        else {

            SawOption(code);


            --offset;
            pending_IAC = false;
        }

        --len;
        ++data;
        return;
    }

    if ( ! is_suboption ) {

        SawOption(static_cast<u_char>(buf[offset - 1]), data[0]);


        offset -= 2;
        pending_IAC = false;

        --len;
        ++data;
        return;
    }


    for ( ; len > 0; --len, ++data ) {
        if ( offset >= buf_len ) {
            if ( ! InitBufferSafe(buf_len * 2) ) {
                LimitReachedWeird("nvt_option_size_exceeded", buf_len);


                pending_IAC = false;
                is_suboption = false;
                offset = 0;
                return;
            }
        }

        unsigned int code = data[0];

        if ( last_was_IAC ) {
            last_was_IAC = false;

            if ( code == TELNET_IAC ) {


                continue;
            }

            if ( code != TELNET_OPT_SE )




                BadOptionTermination(code);

            int opt_start = IAC_pos + 2;
            int opt_stop = offset - 1;
            int opt_len = opt_stop - opt_start;
            SawSubOption(reinterpret_cast<const char*>(&buf[opt_start]), opt_len);


            offset = IAC_pos;
            pending_IAC = is_suboption = false;

            if ( code == TELNET_OPT_SE ) {
                --len;
                ++data;
            }
            else {

                pending_IAC = true;
                IAC_pos = offset;
                buf[offset++] = TELNET_IAC;
            }
            return;
        }

        else {
            buf[offset++] = code;
            last_was_IAC = (code == TELNET_IAC);
        }
    }
}

void NVT_Analyzer::SawOption(unsigned int ) {}

void NVT_Analyzer::SawOption(unsigned int code, unsigned int subcode) {
    TelnetOption* opt = FindOption(subcode);
    if ( opt )
        opt->RecvOption(code);
}

void NVT_Analyzer::SawSubOption(const char* subopt, int len) {
    unsigned int subcode = static_cast<u_char>(subopt[0]);

    ++subopt;
    --len;

    TelnetOption* opt = FindOption(subcode);
    if ( opt )
        opt->RecvSubOption(const_cast<u_char*>(reinterpret_cast<const u_char*>(subopt)), len);
}

void NVT_Analyzer::BadOptionTermination(unsigned int ) { Event(bad_option_termination); }

}
