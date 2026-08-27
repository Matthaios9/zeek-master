





#include "zeek/Desc.h"
#include "zeek/Reporter.h"
#include "zeek/input.h"
#include "zeek/script_opt/Reduce.h"
#include "zeek/script_opt/ScriptOpt.h"
#include "zeek/script_opt/ZAM/Compile.h"

namespace zeek::detail {









std::unordered_map<const Func*, int> remapped_intrp_frame_sizes;

void finalize_functions(const std::vector<FuncInfo>& funcs) {








    std::unordered_set<const Func*> leave_alone;

    for ( auto& f : funcs )
        if ( f.Body() && f.Body()->Tag() != STMT_ZAM )


            leave_alone.insert(f.Func());

    for ( auto& f : funcs ) {
        auto func = f.Func();

        if ( leave_alone.contains(func) )
            continue;

        if ( ! remapped_intrp_frame_sizes.contains(func) )

            continue;

        auto& ft = func->GetType();
        auto& params = ft->Params();
        func->SetFrameSize(params->NumFields());


        leave_alone.insert(func);
    }
}



static bool dump_intermediaries = false;

void ZAMCompiler::OptimizeInsts() {

    for ( auto& i : insts1 ) {
        if ( i->target && i->target->live )
            ++(i->target->num_labels);
    }

    TallySwitchTargets(int_casesI);
    TallySwitchTargets(uint_casesI);
    TallySwitchTargets(double_casesI);
    TallySwitchTargets(str_casesI);

    for ( unsigned int i = 0; i < insts1.size(); ++i )
        if ( insts1[i]->op == OP_NOP )

            KillInst(i);

    if ( analysis_options.dump_ZAM ) {
        printf("Original ZAM code for %s:\n", func->GetName().c_str());
        DumpInsts1(nullptr);
    }

    bool something_changed;
    int num_rounds = 0;

    do {
        something_changed = false;

        if ( dump_intermediaries ) {
            printf("\nStarting point, round %d:\n", ++num_rounds);
            DumpInsts1(nullptr);
        }

        while ( RemoveDeadCode() ) {
            something_changed = true;

            if ( dump_intermediaries ) {
                printf("\nRemoved some dead code:\n");
                DumpInsts1(nullptr);
            }
        }

        while ( InvertConditionalsAroundGotos() ) {
            something_changed = true;

            if ( dump_intermediaries ) {
                printf("\nDid some conditional inversions:\n");
                DumpInsts1(nullptr);
            }
        }

        while ( CollapseGoTos() ) {
            something_changed = true;

            if ( dump_intermediaries ) {
                printf("\nDid some collapsing:\n");
                DumpInsts1(nullptr);
            }
        }

        ComputeFrameLifetimes();

        if ( PruneUnused() ) {
            something_changed = true;

            if ( dump_intermediaries ) {
                printf("\nDid some pruning:\n");
                DumpInsts1(nullptr);
            }
        }
    } while ( something_changed );

    ReMapFrame();
    ReMapInterpreterFrame();
}

template<typename T>
void ZAMCompiler::TallySwitchTargets(const CaseMapsI<T>& switches) {
    for ( auto& targs : switches )
        for ( auto& targ : targs )
            ++(targ.second->num_labels);
}

bool ZAMCompiler::RemoveDeadCode() {
    if ( analysis_options.no_ZAM_control_flow_opt )
        return false;

    if ( insts1.empty() )
        return false;

    bool did_removal = false;


    for ( unsigned int i = 0; i < insts1.size() - 1; ++i ) {
        auto& i0 = insts1[i];
        if ( ! i0->live )
            continue;

        auto i1 = NextLiveInst(i0);


        auto t = i0->target;

        if ( t == pending_inst && ! i1 ) {


            KillInst(i0);
            did_removal = true;
            continue;
        }

        if ( t && t->inst_num > i0->inst_num && (! i1 || t->inst_num <= i1->inst_num) ) {




            if ( ! i0->IsLoopIterationAdvancement() ) {
                KillInst(i0);
                did_removal = true;
                continue;
            }
        }

        if ( i0->DoesNotContinue() && i1 && i1->num_labels == 0 ) {


            KillInsts(i1);
            did_removal = true;
        }
    }

    return did_removal;
}

bool ZAMCompiler::InvertConditionalsAroundGotos() {
    if ( analysis_options.no_ZAM_control_flow_opt )
        return false;

    if ( insts1.empty() )
        return false;

    bool did_change = false;


    for ( unsigned int i = 0; i < insts1.size() - 1; ++i ) {
        auto& i0 = insts1[i];
        auto target = i0->target;
        if ( ! i0->live || ! target || ! ZOP_has_inverse(i0->op) )
            continue;

        auto i1 = NextLiveInst(i0);
        if ( ! i1 )

            continue;

        if ( ! i1->IsUnconditionalBranch() )
            continue;

        if ( i1->num_labels > 0 )

            continue;

        auto after_branch_ind = NextLiveInst(i1->inst_num);
        auto target_ind = FirstLiveInst(target->inst_num);

        if ( target_ind != after_branch_ind )
            continue;



        auto goto_target = FirstLiveInst(i1->target);

        i0->target = goto_target ? goto_target : pending_inst;
        i0->op = inverse_ZOP(i0->op);

        if ( goto_target )
            ++(goto_target->num_labels);

        --(insts1[target_ind]->num_labels);

        KillInst(i1);

        did_change = true;
    }

    return did_change;
}

bool ZAMCompiler::CollapseGoTos() {
    if ( analysis_options.no_ZAM_control_flow_opt )
        return false;

    bool did_change = false;

    for ( auto& i0 : insts1 ) {
        auto orig_t = i0->target;

        if ( ! i0->live || ! orig_t || orig_t == pending_inst )
            continue;





        auto first_branch = FirstLiveInst(orig_t, false);
        if ( ! first_branch )


            continue;

        auto t = FirstLiveInst(orig_t, true);
        if ( ! t )
            t = pending_inst;

        if ( t != orig_t ) {

            if ( first_branch->live )
                --first_branch->num_labels;
            i0->target = t;
            ++t->num_labels;
            did_change = true;
        }
    }

    return did_change;
}

bool ZAMCompiler::PruneUnused() {
    bool did_prune = false;

    for ( unsigned int i = 0; i < insts1.size(); ++i ) {
        auto inst = insts1[i];

        if ( ! inst->live ) {
            ASSERT(inst->num_labels == 0);
            continue;
        }

        if ( i == insts1.size() - 1 && inst->op == OP_RETURN_X ) {


            did_prune = true;
            KillInst(i);
            continue;
        }

        if ( inst->IsLoad() && ! VarIsUsed(inst->v1) ) {
            did_prune = true;
            KillInst(i);
            continue;
        }

        if ( inst->IsNonLocalLoad() ) {


            for ( unsigned int j = i + 1; j < insts1.size(); ++j ) {
                auto i1 = insts1[j];

                if ( ! i1->live )
                    continue;

                if ( i1->DoesNotContinue() )

                    break;

                if ( i1->num_labels > 0 )

                    break;

                if ( i1->aux && i1->aux->can_change_non_locals )
                    break;

                if ( ! i1->IsNonLocalLoad() )
                    continue;

                if ( i1->v2 == inst->v2 && i1->IsGlobalLoad() == inst->IsGlobalLoad() ) {
                    did_prune = true;
                    KillInst(i1);
                }
            }
        }

        if ( ! inst->AssignsToSlot1() )
            continue;

        int slot = inst->v1;
        if ( denizen_ending.contains(slot) )

            continue;

        auto& id = frame_denizens[slot];
        if ( id->IsGlobal() || IsCapture(id) ) {


            denizen_ending[slot] = insts1.back();
            continue;
        }


        if ( ! inst->HasSideEffects() ) {
            did_prune = true;

            KillInst(i);
            continue;
        }





        if ( ! assignmentless_op.contains(inst->op) )
            reporter->InternalError("inconsistency in re-flavoring instruction with side effects");

        inst->op_type = assignmentless_op_class[inst->op];
        inst->op = assignmentless_op[inst->op];

        inst->v1 = inst->v2;
        inst->v2 = inst->v3;
        inst->v3 = inst->v4;



        did_prune = true;
    }

    return did_prune;
}

void ZAMCompiler::ComputeFrameLifetimes() {

    inst_beginnings.clear();
    inst_endings.clear();

    denizen_beginning.clear();
    denizen_ending.clear();

    for ( unsigned int i = 0; i < insts1.size(); ++i ) {
        auto inst = insts1[i];
        if ( ! inst->live )
            continue;

        if ( inst->AssignsToSlot1() )
            CheckSlotAssignment(inst->v1, inst);


        switch ( inst->op ) {
            case OP_NEXT_TABLE_ITER_fb:
            case OP_NEXT_TABLE_ITER_VAL_VAR_Vfb: {

                auto& iter_vars = inst->aux->loop_vars;
                auto depth = inst->loop_depth;

                for ( auto v : iter_vars ) {
                    if ( v < 0 )

                        continue;

                    CheckSlotAssignment(v, inst);









                    ExtendLifetime(v, EndOfLoop(inst, depth));
                }





                if ( inst->op == OP_NEXT_TABLE_ITER_VAL_VAR_Vfb )
                    ExtendLifetime(inst->v1, EndOfLoop(inst, depth));
            } break;

            case OP_NEXT_TABLE_ITER_NO_VARS_fb: break;

            case OP_NEXT_TABLE_ITER_VAL_VAR_NO_VARS_Vfb: {
                auto depth = inst->loop_depth;
                ExtendLifetime(inst->v1, EndOfLoop(inst, depth));
            } break;

            case OP_NEXT_VECTOR_ITER_VAL_VAR_VVsb: {
                CheckSlotAssignment(inst->v2, inst);

                auto depth = inst->loop_depth;
                ExtendLifetime(inst->v1, EndOfLoop(inst, depth));
                ExtendLifetime(inst->v2, EndOfLoop(inst, depth));
            } break;

            case OP_NEXT_VECTOR_BLANK_ITER_VAL_VAR_Vsb: {
                auto depth = inst->loop_depth;
                ExtendLifetime(inst->v1, EndOfLoop(inst, depth));
            } break;

            case OP_NEXT_VECTOR_ITER_Vsb:
            case OP_NEXT_STRING_ITER_Vsb:








                ExtendLifetime(inst->v1, EndOfLoop(inst, inst->loop_depth));
                break;

            case OP_NEXT_VECTOR_BLANK_ITER_sb:
            case OP_NEXT_STRING_BLANK_ITER_sb: break;

            case OP_INIT_TABLE_LOOP_Vf:
            case OP_INIT_VECTOR_LOOP_Vs:
            case OP_INIT_STRING_LOOP_Vs: {




                ASSERT(i < insts1.size() - 1);
                auto succ = insts1[i + 1];
                ASSERT(succ->live);
                auto depth = succ->loop_depth;
                ExtendLifetime(inst->v1, EndOfLoop(succ, depth));




                continue;
            }

            case OP_STORE_GLOBAL_g: {

                const auto& slot = frame_layout1[globalsI[inst->v1].id];
                ExtendLifetime(slot, EndOfLoop(inst, 1));
                break;
            }

            case OP_DETERMINE_TYPE_MATCH_VV: {
                auto aux = inst->aux;
                int n = aux->n;
                for ( int i = 0; i < n; ++i ) {
                    auto slot_i = aux->elems[i].Slot();
                    if ( slot_i >= 0 ) {
                        CheckSlotAssignment(slot_i, inst);



                        ExtendLifetime(slot_i, insts1[i + 1]);
                    }
                }
                break;
            }

            case OP_LAMBDA_Vi: {
                auto aux = inst->aux;
                int n = aux->n;
                for ( int i = 0; i < n; ++i ) {
                    auto slot_i = aux->elems[i].Slot();
                    if ( slot_i >= 0 )
                        ExtendLifetime(slot_i, EndOfLoop(inst, 1));
                }
                break;
            }

            default:

                auto aux = inst->aux;
                if ( ! aux || ! aux->elems_has_slots )
                    break;

                int n = aux->n;
                for ( auto j = 0; j < n; ++j ) {
                    auto slot_j = aux->elems[j].Slot();
                    if ( slot_j < 0 )
                        continue;

                    ExtendLifetime(slot_j, EndOfLoop(inst, 1));
                }
                break;
        }

        int s1;
        int s2;
        int s3;
        int s4;

        if ( ! inst->UsesSlots(s1, s2, s3, s4) )
            continue;

        CheckSlotUse(s1, inst);
        CheckSlotUse(s2, inst);
        CheckSlotUse(s3, inst);
        CheckSlotUse(s4, inst);
    }
}

void ZAMCompiler::ReMapFrame() {




    frame1_to_frame2.resize(frame_layout1.size(), -1);
    managed_slotsI.clear();

    for ( zeek_uint_t i = 0; i < insts1.size(); ++i ) {
        auto inst = insts1[i];

        if ( ! inst_beginnings.contains(inst) )
            continue;

        auto vars = inst_beginnings[inst];
        for ( const auto& v : vars ) {

            int slot = frame_layout1[v];
            if ( denizen_ending.contains(slot) )
                ReMapVar(v, slot, i);
        }
    }

#if 0

	printf("%s frame remapping:\n", func->Name());

	for ( unsigned int i = 0; i < shared_frame_denizens.size(); ++i )
		{
		auto& s = shared_frame_denizens[i];
		printf("*%d (%s) %lu [%d->%d]:",
			i, s.is_managed ? "M" : "N",
			s.ids.size(), s.id_start[0], s.scope_end);

		for ( auto j = 0; j < s.ids.size(); ++j )
			printf(" %s (%d)", s.ids[j]->Name(), s.id_start[j]);

		printf("\n");
		}
#endif



    std::vector<GlobalInfo> used_globals;
    std::vector<int> remapped_globals;

    for ( auto& g : globalsI ) {
        g.slot = frame1_to_frame2[g.slot];
        if ( g.slot >= 0 ) {
            remapped_globals.push_back(used_globals.size());
            used_globals.push_back(g);
        }
        else
            remapped_globals.push_back(-1);
    }

    globalsI = used_globals;





    int n1_slots = frame1_to_frame2.size();

    for ( unsigned int i = 0; i < insts1.size(); ++i ) {
        auto inst = insts1[i];

        if ( ! inst->live )
            continue;

        if ( inst->AssignsToSlot1() ) {
            auto v1 = inst->v1;
            ASSERT(v1 >= 0 && v1 < n1_slots);
            inst->v1 = frame1_to_frame2[v1];
        }


        switch ( inst->op ) {
            case OP_INIT_TABLE_LOOP_Vf:
            case OP_NEXT_TABLE_ITER_fb:
            case OP_NEXT_TABLE_ITER_VAL_VAR_Vfb: {






                auto& iter_vars = inst->aux->loop_vars;
                for ( auto& v : iter_vars ) {
                    if ( v < 0 )
                        continue;
                    ASSERT(v < n1_slots);
                    v = frame1_to_frame2[v];
                }
            } break;

            default:

                auto aux = inst->aux;
                if ( ! aux || ! aux->elems_has_slots )
                    break;

                for ( auto j = 0; j < aux->n; ++j ) {
                    auto slot = aux->elems[j].Slot();

                    if ( slot < 0 )

                        continue;

                    auto new_slot = frame1_to_frame2[slot];

                    if ( new_slot < 0 ) {
                        ODesc d;
                        inst->loc->Loc()->Describe(&d);
                        reporter->Error("%s: value used but not set: %s", d.Description(),
                                        frame_denizens[slot]->Name());
                    }

                    aux->elems[j].SetSlot(new_slot);
                }
                break;
        }

        if ( inst->IsGlobalLoad() ) {


            int g = inst->v2;
            ASSERT(remapped_globals[g] >= 0);
            inst->v2 = remapped_globals[g];




            continue;
        }

        if ( inst->IsGlobalStore() ) {
            int g = inst->v1;
            ASSERT(remapped_globals[g] >= 0);
            inst->v1 = remapped_globals[g];


            continue;
        }

        inst->UpdateSlots(frame1_to_frame2);

        if ( inst->IsDirectAssignment() && inst->v1 == inst->v2 )
            KillInst(i);
    }

    frame_sizeI = shared_frame_denizens.size();
}

void ZAMCompiler::ReMapInterpreterFrame() {


    auto args = scope->OrderedVars();
    int nparam = func->GetType()->Params()->NumFields();
    int next_interp_slot = 0;

    for ( const auto& a : args ) {
        if ( --nparam < 0 )
            break;

        ASSERT(a->Offset() == next_interp_slot);
        ++next_interp_slot;
    }



    auto f = func.get();
    if ( ! remapped_intrp_frame_sizes.contains(f) || remapped_intrp_frame_sizes[f] < next_interp_slot )
        remapped_intrp_frame_sizes[f] = next_interp_slot;
}

void ZAMCompiler::ReMapVar(const IDPtr& id, int slot, zeek_uint_t inst) {




















    bool is_managed = ZVal::IsManagedType(id->GetType()) || id->IsType();

    int apt_slot = -1;
    for ( unsigned int i = 0; i < shared_frame_denizens.size(); ++i ) {
        auto& s = shared_frame_denizens[i];







        if ( s.scope_end <= static_cast<int>(inst) && s.is_managed == is_managed ) {
            if ( s.scope_end == static_cast<int>(inst) ) {
                apt_slot = i;
                break;
            }

            else if ( apt_slot < 0 )


                apt_slot = i;
        }
    }

    int scope_end = denizen_ending[slot]->inst_num;

    if ( apt_slot < 0 ) {

        apt_slot = shared_frame_denizens.size();

        FrameSharingInfo info;
        info.is_managed = is_managed;
        shared_frame_denizens.push_back(std::move(info));

        if ( is_managed )
            managed_slotsI.push_back(apt_slot);
    }

    auto& s = shared_frame_denizens[apt_slot];

    s.ids.push_back(id);
    s.id_start.push_back(inst);
    s.scope_end = scope_end;

    frame1_to_frame2[slot] = apt_slot;
}

void ZAMCompiler::CheckSlotAssignment(int slot, const ZInstI* inst) {
    ASSERT(slot >= 0 && static_cast<zeek_uint_t>(slot) < frame_denizens.size());




    if ( ! reducer->IsTemporary(frame_denizens[slot]) )
        inst = BeginningOfLoop(inst, 1);

    SetLifetimeStart(slot, inst);
}

void ZAMCompiler::SetLifetimeStart(int slot, const ZInstI* inst) {
    if ( denizen_beginning.contains(slot) ) {


        ASSERT(denizen_beginning[slot]->inst_num <= inst->inst_num);
    }

    else {
        denizen_beginning[slot] = inst;

        if ( ! inst_beginnings.contains(inst) )


            inst_beginnings[inst] = {};

        inst_beginnings[inst].insert(frame_denizens[slot]);
    }
}

void ZAMCompiler::CheckSlotUse(int slot, const ZInstI* inst) {
    if ( slot < 0 )
        return;

    ASSERT(static_cast<zeek_uint_t>(slot) < frame_denizens.size());

    if ( ! denizen_beginning.contains(slot) ) {
        ODesc d;
        inst->loc->Loc()->Describe(&d);
        reporter->Error("%s: value used but not set: %s", d.Description(), frame_denizens[slot]->Name());
    }





    if ( reducer->IsTemporary(frame_denizens[slot]) ) {
        ASSERT(denizen_beginning.contains(slot));
        int definition_depth = denizen_beginning[slot]->loop_depth;

        if ( inst->loop_depth > definition_depth )
            inst = EndOfLoop(inst, inst->loop_depth);
    }
    else
        inst = EndOfLoop(inst, 1);

    ExtendLifetime(slot, inst);
}

void ZAMCompiler::ExtendLifetime(int slot, const ZInstI* inst) {
    ASSERT(slot >= 0);
    auto id = frame_denizens[slot];
    auto& t = id->GetType();

    if ( denizen_ending.contains(slot) ) {



        auto old_inst = denizen_ending[slot];





        if ( inst->loop_depth > 0 && reducer->IsTemporary(frame_denizens[slot]) &&
             old_inst->inst_num >= inst->inst_num )
            return;





        ASSERT(old_inst->inst_num <= inst->inst_num || inst->loop_depth > 1);

        if ( old_inst->inst_num < inst->inst_num ) {
            inst_endings[old_inst].erase(frame_denizens[slot]);

            if ( ! inst_endings.contains(inst) )
                inst_endings[inst] = {};

            inst_endings[inst].insert(frame_denizens[slot]);
            denizen_ending.at(slot) = inst;
        }
    }

    else {
        denizen_ending[slot] = inst;

        if ( ! inst_endings.contains(inst) ) {
            IDSet denizens;
            inst_endings[inst] = denizens;
        }

        inst_endings[inst].insert(frame_denizens[slot]);
    }
}

const ZInstI* ZAMCompiler::BeginningOfLoop(const ZInstI* inst, int depth) const {
    auto i = inst->inst_num;

    while ( i >= 0 && insts1[i]->loop_depth >= depth )
        --i;

    if ( i == inst->inst_num )
        return inst;



    ++i;
    while ( i != inst->inst_num && ! insts1[i]->live )
        ++i;

    return insts1[i];
}

const ZInstI* ZAMCompiler::EndOfLoop(const ZInstI* inst, int depth) const {
    auto i = inst->inst_num;

    while ( i < static_cast<int>(insts1.size()) && insts1[i]->loop_depth >= depth )
        ++i;

    if ( i == inst->inst_num )
        return inst;



    --i;
    while ( i != inst->inst_num && ! insts1[i]->live )
        --i;

    return insts1[i];
}

bool ZAMCompiler::VarIsUsed(int slot) const {
    for ( auto& inst : insts1 ) {
        if ( inst->live && inst->UsesSlot(slot) )
            return true;

        auto aux = inst->aux;
        if ( aux && aux->elems_has_slots ) {
            for ( int j = 0; j < aux->n; ++j )
                if ( aux->elems[j].Slot() == slot )
                    return true;
        }
    }

    return false;
}

ZInstI* ZAMCompiler::FirstLiveInst(ZInstI* i, bool follow_gotos) {
    if ( i == pending_inst )
        return nullptr;

    auto n = FirstLiveInst(i->inst_num, follow_gotos);
    if ( n < insts1.size() )
        return insts1[n];
    else
        return nullptr;
}

zeek_uint_t ZAMCompiler::FirstLiveInst(zeek_uint_t i, bool follow_gotos) {
    zeek_uint_t num_inspected = 0;
    while ( i < insts1.size() ) {
        auto i0 = insts1[i];
        if ( i0->live ) {
            if ( follow_gotos && i0->IsUnconditionalBranch() ) {
                if ( ++num_inspected > insts1.size() ) {
                    reporter->Error("%s contains an infinite loop", func->GetName().c_str());
                    return i;
                }

                i = i0->target->inst_num;
                continue;
            }

            return i;
        }

        ++i;
        ++num_inspected;
    }

    return i;
}

void ZAMCompiler::KillInst(zeek_uint_t i) {
    auto inst = insts1[i];

    ASSERT(inst->live);

    inst->live = false;
    auto t = inst->target;
    if ( t ) {
        if ( t->live ) {
            --(t->num_labels);
            ASSERT(t->num_labels >= 0);
        }
        else
            ASSERT(t->num_labels == 0);
    }

    int num_labels = inst->num_labels;

    inst->num_labels = 0;

    if ( inst->IsUnconditionalBranch() ) {
        ASSERT(t);



        auto after_inst = NextLiveInst(inst, true);
        auto live_target = FirstLiveInst(t, true);

        if ( after_inst != live_target ) {


            ASSERT(num_labels == 0);
        }
    }

    ZInstI* succ = NextLiveInst(inst);
    if ( succ )
        succ->num_labels += num_labels;


    if ( inst->aux && ! inst->aux->cft.empty() ) {
        auto& cft = inst->aux->cft;

        if ( cft.contains(CFT_ELSE) ) {

            if ( ! cft.contains(CFT_BLOCK_END) ) {
                ASSERT(succ);
                AddCFT(succ, CFT_ELSE);
            }
            else

                --cft[CFT_BLOCK_END];
        }

        BackPropagateCFT(i, CFT_BREAK);
        BackPropagateCFT(i, CFT_BLOCK_END);
        BackPropagateCFT(i, CFT_LOOP_END);
        BackPropagateCFT(i, CFT_INLINED_RETURN);





        ASSERT(! cft.contains(CFT_LOOP));
        ASSERT(! cft.contains(CFT_LOOP_COND));
    }
}

void ZAMCompiler::BackPropagateCFT(int inst_num, ControlFlowType cf_type) {
    auto inst = insts1[inst_num];
    auto& cft = inst->aux->cft;
    if ( ! cft.contains(cf_type) )
        return;

    int j = inst_num;
    while ( --j >= 0 )
        if ( insts1[j]->live )
            break;




    if ( j < 0 )
        return;


    AddCFT(insts1[j], cf_type);

    auto cft_cnt = cft[cf_type];
    --cft_cnt;
    insts1[j]->aux->cft[cf_type] += cft_cnt;
}

void ZAMCompiler::KillInsts(zeek_uint_t i) {
    auto inst = insts1[i];

    ASSERT(inst->num_labels == 0);

    KillInst(i);

    for ( auto j = i + 1; j < insts1.size(); ++j ) {
        auto succ = insts1[j];
        if ( succ->live ) {
            if ( succ->num_labels == 0 )
                KillInst(j);
            else

                break;
        }
    }
}

}
