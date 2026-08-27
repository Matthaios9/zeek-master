

#pragma once

#include <vector>

#include "zeek/ZeekList.h"

namespace zeek {

class VectorVal;
class RecordType;
template<class T>
class IntrusivePtr;

using ValPtr = IntrusivePtr<Val>;
using VectorValPtr = IntrusivePtr<VectorVal>;
using RecordTypePtr = IntrusivePtr<RecordType>;

using Args = std::vector<ValPtr>;









VectorValPtr MakeCallArgumentVector(const Args& vals, const RecordTypePtr& types);






VectorValPtr MakeEmptyCallArgumentVector();

}
