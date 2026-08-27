

#ifndef pac_withinput_h
#define pac_withinput_h

#include "pac_datadep.h"
#include "pac_decl.h"
#include "pac_field.h"

class WithInputField : public Field, public Evaluatable {
public:
    WithInputField(ID* id, Type* type, InputBuffer* input);
    ~WithInputField() override;

    InputBuffer* input() const { return input_; }

    void Prepare(Env* env) override;







    void GenParseCode(Output* out, Env* env);


    void GenEval(Output* out, Env* env) override;

    bool RequiresAnalyzerContext() const override;

protected:
    bool DoTraverse(DataDepVisitor* visitor) override;

protected:
    InputBuffer* input_;
};

#endif
