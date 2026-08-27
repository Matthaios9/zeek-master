






void OptimizeInsts();



template<typename T>
void TallySwitchTargets(const CaseMapsI<T>& switches);


bool RemoveDeadCode();


bool InvertConditionalsAroundGotos();


bool CollapseGoTos();



bool PruneUnused();





void ComputeFrameLifetimes();



void ReMapFrame();



void ReMapInterpreterFrame();



void ReMapVar(const IDPtr& id, int slot, zeek_uint_t inst);



void CheckSlotAssignment(int slot, const ZInstI* inst);


void SetLifetimeStart(int slot, const ZInstI* inst);



void CheckSlotUse(int slot, const ZInstI* inst);


void ExtendLifetime(int slot, const ZInstI* inst);






const ZInstI* BeginningOfLoop(const ZInstI* inst, int depth) const;
const ZInstI* EndOfLoop(const ZInstI* inst, int depth) const;


bool VarIsUsed(int slot) const;









ZInstI* FirstLiveInst(ZInstI* i, bool follow_gotos = false);
zeek_uint_t FirstLiveInst(zeek_uint_t i, bool follow_gotos = false);


ZInstI* NextLiveInst(ZInstI* i, bool follow_gotos = false) {
    if ( i->inst_num == static_cast<int>(insts1.size()) - 1 )
        return nullptr;
    return FirstLiveInst(insts1[i->inst_num + 1], follow_gotos);
}
zeek_uint_t NextLiveInst(int i, bool follow_gotos = false) { return FirstLiveInst(i + 1, follow_gotos); }





void KillInst(ZInstI* i) { KillInst(i->inst_num); }
void KillInst(zeek_uint_t i);



void BackPropagateCFT(int inst_num, ControlFlowType cf_type);



void KillInsts(ZInstI* i) { KillInsts(i->inst_num); }
void KillInsts(zeek_uint_t i);
