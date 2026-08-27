

#ifndef binpac_buffer_h
#define binpac_buffer_h

#include <sys/types.h>

#include "binpac.h"

namespace binpac {

class FlowBuffer {
public:
    struct Policy {
        int max_capacity;
        int min_capacity;
        int contract_threshold;
    };

    enum LineBreakStyle : uint8_t {
        CR_OR_LF,
        STRICT_CRLF,
        CR_LF_NUL,
        LINE_BREAKER,
    };

    FlowBuffer(LineBreakStyle linebreak_style = CR_OR_LF);
    virtual ~FlowBuffer();

    void NewData(const_byteptr begin, const_byteptr end);
    void NewGap(int length);






    void BufferData(const_byteptr data, const_byteptr end);
    void FinishBuffer();


    void DiscardData();


    bool ready() const { return message_complete_ || mode_ == UNKNOWN_MODE; }

    inline const_byteptr begin() const {
        BINPAC_ASSERT(ready());
        return (buffer_n_ == 0) ? orig_data_begin_ : buffer_;
    }

    inline const_byteptr end() const {
        BINPAC_ASSERT(ready());
        if ( buffer_n_ == 0 ) {
            BINPAC_ASSERT(frame_length_ >= 0);
            const_byteptr end = orig_data_begin_ + frame_length_;
            BINPAC_ASSERT(end <= orig_data_end_);
            return end;
        }
        else
            return buffer_ + buffer_n_;
    }

    inline int data_length() const {
        if ( buffer_n_ > 0 )
            return buffer_n_;

        if ( frame_length_ < 0 || orig_data_begin_ + frame_length_ > orig_data_end_ )
            return orig_data_end_ - orig_data_begin_;
        else
            return frame_length_;
    }

    inline bool data_available() const { return buffer_n_ > 0 || orig_data_end_ > orig_data_begin_; }

    void SetLineBreaker(unsigned char* lbreaker);
    void UnsetLineBreaker();
    void NewLine();

    void NewFrame(int frame_length, bool chunked_);
    void GrowFrame(int new_frame_length);

    int data_seq() const {
        int data_seq_at_orig_data_begin = data_seq_at_orig_data_end_ - (orig_data_end_ - orig_data_begin_);
        if ( buffer_n_ > 0 )
            return data_seq_at_orig_data_begin;
        else
            return data_seq_at_orig_data_begin + data_length();
    }
    bool eof() const { return eof_; }
    void set_eof();

    bool have_pending_request() const { return have_pending_request_; }

    static void init(Policy p) { policy = p; }

protected:

    void NewMessage();

    void ClearPreviousData();




    void ExpandBuffer(int length);






    void ContractBuffer();


    void ResetLineState();

    void AppendToBuffer(const_byteptr data, int len);






    void MarkOrCopy();
    void MarkOrCopyLine();
    void MarkOrCopyFrame();

    void MarkOrCopyLine_CR_OR_LF();
    void MarkOrCopyLine_STRICT_CRLF();
    void MarkOrCopyLine_LINEBREAK();

    int buffer_n_;
    int buffer_length_;
    unsigned char* buffer_;
    bool message_complete_;
    int frame_length_;
    bool chunked_;
    const_byteptr orig_data_begin_, orig_data_end_;

    LineBreakStyle linebreak_style_;
    LineBreakStyle linebreak_style_default;
    unsigned char linebreaker_;

    enum : uint8_t {
        UNKNOWN_MODE,
        LINE_MODE,
        FRAME_MODE,
    } mode_;

    enum : uint8_t {
        CR_OR_LF_0,
        CR_OR_LF_1,
        STRICT_CRLF_0,
        STRICT_CRLF_1,
        FRAME_0,
    } state_;

    int data_seq_at_orig_data_end_;
    bool eof_;
    bool have_pending_request_;

    static Policy policy;
};

using flow_buffer_t = FlowBuffer*;

}

#endif
