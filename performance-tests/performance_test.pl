:- debug(debug_access_control).



:- use_module(acop).
:- use_module(prolog_statistics).
%:- consult(configurations/manufacturing_environment_2_2_2).
:- consult(write_environment).

:- dynamic info/3.
:- set_prolog_flag(stack_limit, 100 000 000 000).



load_access_rules(false) :-
    writeln('load cosed policy access rules'),
    retractall(acop:allow(_)),
    retractall(acop:deny(_)),
    asserta(acop:allow(location(_,_))),
    asserta(acop:allow(production_line(_))),
    asserta((acop:allow(machine(M)) :- current_user(U), line_manager(U,P), location(M,P))),
    asserta((acop:allow(start_machine(M)) :- access(machine(M)))),
    asserta((acop:allow(machine_state(M,_)) :- current_user(U), line_manager(U,L), location(M,L))),
             writeln('closed policy access rules loaded').


load_access_rules(true) :-
    writeln('load open policy access rules'),
    retractall(acop:allow(_)),
    retractall(acop:deny(_)),
    asserta((acop:deny(machine(_)))),
        asserta((acop:deny(start_machine(_)))),
        asserta((acop:deny(machine_state(M,_)))) ,
        asserta((acop:allow(machine(M)) :- current_user(U), line_manager(U,P), location(M,P))),
            asserta((acop:allow(start_machine(M)) :- access(machine(M)))),
            asserta((acop:allow(machine_state(M,_)) :- current_user(U), line_manager(U,L), location(M,L))),

%    asserta((acop:deny(machine(M)) :- \+((current_user(U), line_manager(U,P), location(M,P))))),
%    asserta((acop:deny(start_machine(M)) :- \+access(machine(M)))),
%    asserta((acop:deny(machine_state(M,_)) :- \+((current_user(U), line_manager(U,L), location(M,L)))))
             writeln('open policy access rules loaded').


test_environment :-
        consult(configurations/manufacturing_environment_3_5_10),
        write('current_user: '),
      	read_line_to_string(user_input,User),
      	atom_string(Usera, User),
      	asserta(current_user(Usera)),
        write('access_control? (y/n): '),
   		read_line_to_string(user_input,S),
   		atom_string(Sa, S),
   		(Sa==y ->(
   			write('default_access? (true/false): '),
   			read_line_to_string(user_input,Def),
   			atom_string(Defa, Def),
   			write('body_resolution? (true/false): '),
   			read_line_to_string(user_input,Body),
   			atom_string(Bodya, Body), use_access_control(Defa, Bodya, false, [time/1, call_time/2, write/1]),
   			writeln(Def+Body), load_access_rules(Defa));(write('no access control'))).


% use_access_control(Default_Access (boolean), Body_Resolution (boolean) , Allowed_Predicates (list), Action_Predicates (list))
%:- use_access_control(false, true,[time/1], []).

full_test :-
	%look for fact
	test_query(info(_,_,_)),
	write('SUCCESS'),
	%look for derived information
	test_query((age(_,_))).
	%test_query(universal_blood_donor(_)).


test_query(Q):-
	writeln(----------------------------),writeln(Q),writeln(----------------------------),writeln(----------------------------),
	test_patient_amount_query(10, Q),
	test_patient_amount_query(100, Q),
	test_patient_amount_query(1000, Q),
	test_patient_amount_query(10000, Q),
	test_patient_amount_query(20000, Q),
	test_patient_amount_query(30000, Q),
	test_patient_amount_query(50000, Q),
	test_patient_amount_query(100000, Q),
	test_patient_amount_query(1000000,Q),
	test_patient_amount_query(2000000,Q),
	test_patient_amount_query(3000000,Q),
	test_patient_amount_query(4000000,Q),
	test_patient_amount_query(5000000,Q),
	test_patient_amount_query(10000000,Q).

full_performance_test :-
    asserta(current_user(manager1)),
    write('Amount of Managers: '),
    read_line_to_string(user_input,ManagerAmount),
    number_string(ManagerAmountA, ManagerAmount),
    write('Amount of Production Lines per Manager: '),
    read_line_to_string(user_input,ProdLineAmount),
    number_string(ProdLineAmountA, ProdLineAmount),
    write('Amount of Machines per Production Line: '),
    read_line_to_string(user_input,MachineAmount),
    number_string(MachineAmountA, MachineAmount),
    test_environment(ManagerAmountA, ProdLineAmountA, MachineAmountA), halt.

query_machines_no_access_control(Res) :-
        prolog_statistics:call_time(aggregate_all(count,machine(_), Answer), Dict),
        get_dict(inferences, Dict, Res),
        write('answer '), writeln(Answer), nl.

query_machines_access_control(Res) :-
    prolog_statistics:call_time(aggregate_all(count,acop:handle(machine(_)), Answer), Dict),
    get_dict(inferences, Dict, Res),
    write('answer '), writeln(Answer), nl.

query_machine_states_no_access_control(Res) :-
    prolog_statistics:call_time(aggregate_all(count,machine_state(_,_), Answer), Dict),
    get_dict(inferences, Dict, Res),
    write('answer '), writeln(Answer), nl.

query_machine_states_access_control(Res) :-
    prolog_statistics:call_time(aggregate_all(count,acop:handle(machine_state(_,_)), Answer), Dict),
    get_dict(inferences, Dict, Res),
    write('answer '), writeln(Answer), nl.

query_specific_machine_states_no_access_control(Res) :-
    prolog_statistics:call_time(machine_state(m_1_1_1,S), Dict),
    get_dict(inferences, Dict, Res),
    write('answer '), writeln(S), nl.

query_specific_machine_states_access_control(Res) :-
    prolog_statistics:call_time(acop:handle(machine_state(m_1_1_1,S)), Dict),
    get_dict(inferences, Dict, Res),
    write('answer '), writeln(S), nl.



start_prod_line_no_access_control(Res) :-
    prolog_statistics:call_time(aggregate_all(count,start_production_line(_), Answer), Dict),
    get_dict(inferences, Dict, Res),
    write('answer '), writeln(Answer), nl.

start_prod_line_access_control(Res) :-
    prolog_statistics:call_time(aggregate_all(count,acop:handle(start_production_line(_)), Answer), Dict),
    get_dict(inferences, Dict, Res),
    write('answer '), writeln(Answer), nl.



test_environment(ManagerAmount, ProdLineAmount, MachineAmount):-
    atomic_list_concat(['performance-tests/configurations/manufacturing_environment_', ManagerAmount, '_', ProdLineAmount, '_', MachineAmount, '.pl'],FileName),
    atomic_list_concat(['performance-tests/configurations/manufacturing_environment_', ManagerAmount, '_', ProdLineAmount, '_', MachineAmount],FileNameNoPL),

    (\+exists_file(FileName) -> generate_manufacturing_environment(ManagerAmount, ProdLineAmount, MachineAmount); true),
    consult(FileNameNoPL),


    atomic_list_concat(['performance-tests/results/manufacturing_environment_query_fact_no_access_control', '.pl'],QueryFactResultFileNoAC),
    atomic_list_concat(['performance-tests/results/manufacturing_environment_query_fact_true_true', '.pl'],QueryFactResultFileTrueTrue),
    atomic_list_concat(['performance-tests/results/manufacturing_environment_query_fact_true_false', '.pl'],QueryFactResultFileTrueFalse),
    atomic_list_concat(['performance-tests/results/manufacturing_environment_query_fact_false_true', '.pl'],QueryFactResultFileFalseTrue),
    atomic_list_concat(['performance-tests/results/manufacturing_environment_query_fact_false_false', '.pl'],QueryFactResultFileFalseFalse),

    atomic_list_concat(['performance-tests/results/manufacturing_environment_query_rule_no_access_control', '.pl'],QueryRuleResultFileNoAC),
    atomic_list_concat(['performance-tests/results/manufacturing_environment_query_rule_true_true', '.pl'],QueryRuleResultFileTrueTrue),
    atomic_list_concat(['performance-tests/results/manufacturing_environment_query_rule_true_false', '.pl'],QueryRuleResultFileTrueFalse),
    atomic_list_concat(['performance-tests/results/manufacturing_environment_query_rule_false_true', '.pl'],QueryRuleResultFileFalseTrue),
    atomic_list_concat(['performance-tests/results/manufacturing_environment_query_rule_false_false', '.pl'],QueryRuleResultFileFalseFalse),

    atomic_list_concat(['performance-tests/results/manufacturing_environment_action_no_access_control', '.pl'],ActionResultFileNoAC),
    atomic_list_concat(['performance-tests/results/manufacturing_environment_action_rule_true_true', '.pl'],ActionResultFileTrueTrue),
    atomic_list_concat(['performance-tests/results/manufacturing_environment_action_rule_true_false', '.pl'],ActionResultFileTrueFalse),
    atomic_list_concat(['performance-tests/results/manufacturing_environment_action_rule_false_true', '.pl'],ActionResultFileFalseTrue),
    atomic_list_concat(['performance-tests/results/manufacturing_environment_action_rule_false_false', '.pl'],ActionResultFileFalseFalse),

    atomic_list_concat(['performance-tests/results/manufacturing_environment_query_specific_rule_no_access_control', '.pl'],QuerySpecificRuleResultFileNoAC),
    atomic_list_concat(['performance-tests/results/manufacturing_environment_query_specific_rule_true_true', '.pl'],QuerySpecificRuleResultFileTrueTrue),
    atomic_list_concat(['performance-tests/results/manufacturing_environment_query_specific_rule_true_false', '.pl'],QuerySpecificRuleResultFileTrueFalse),
    atomic_list_concat(['performance-tests/results/manufacturing_environment_query_specific_rule_false_true', '.pl'],QuerySpecificRuleResultFileFalseTrue),
    atomic_list_concat(['performance-tests/results/manufacturing_environment_query_specific_rule_false_false', '.pl'],QuerySpecificRuleResultFileFalseFalse),

atomic_list_concat(['performance-tests/results/manufacturing_environment_query_start_machine_no_access_control', '.pl'],StartMachineResultFileNoAC),
    atomic_list_concat(['performance-tests/results/manufacturing_environment_query_start_machine_true_true', '.pl'],StartMachineResultFileTrueTrue),
    atomic_list_concat(['performance-tests/results/manufacturing_environment_query_start_machine_true_false', '.pl'],StartMachineResultFileTrueFalse),
    atomic_list_concat(['performance-tests/results/manufacturing_environment_query_start_machine_false_true', '.pl'],StartMachineResultFileFalseTrue),
    atomic_list_concat(['performance-tests/results/manufacturing_environment_query_start_machine_false_false', '.pl'],StartMachineResultFileFalseFalse),




    % NO ACCESS CONTROL
    query_machines_no_access_control(_),
    prolog_statistics:call_time(aggregate_all(count,machine(_), _), Dict1),
    get_dict(inferences, Dict1, Res1),
    atomic_list_concat([ManagerAmount, ',', ProdLineAmount, ',', MachineAmount, ',', Res1],ResultRow1),
    writetoresultfile(QueryFactResultFileNoAC, ResultRow1),

    prolog_statistics:call_time(aggregate_all(count,machine_state(_,_), _), Dict1b),
    get_dict(inferences, Dict1b, Res1b),
    atomic_list_concat([ManagerAmount, ',', ProdLineAmount, ',', MachineAmount, ',', Res1b],ResultRow1b),
    writetoresultfile(QueryRuleResultFileNoAC, ResultRow1b),

    prolog_statistics:call_time(aggregate_all(count,start_production_line(_), _), Dict1c),
    get_dict(inferences, Dict1c, Res1c),
    atomic_list_concat([ManagerAmount, ',', ProdLineAmount, ',', MachineAmount, ',', Res1c],ResultRow1c),
    writetoresultfile(ActionResultFileNoAC, ResultRow1c),

    prolog_statistics:call_time(machine_state(m_1_1_1,_), Dict1d),
    get_dict(inferences, Dict1d, Res1d),
    atomic_list_concat([ManagerAmount, ',', ProdLineAmount, ',', MachineAmount, ',', Res1d],ResultRow1d),
    writetoresultfile(QuerySpecificRuleResultFileNoAC, ResultRow1d),

     prolog_statistics:call_time(aggregate_all(count,(machine(M),start_machine(M)), _), Dict1e),
     get_dict(inferences, Dict1e, Res1e),
    atomic_list_concat([ManagerAmount, ',', ProdLineAmount, ',', MachineAmount, ',', Res1e],ResultRow1e),
     writetoresultfile(StartMachineResultFileNoAC, ResultRow1e),


    % AC TRUE TRUE
    load_access_rules(true),
    use_access_control(true, true, false,[]),
    prolog_statistics:call_time(aggregate_all(count,acop:handle(machine(_)), _), Dict2),
    get_dict(inferences, Dict2, Res2),
    atomic_list_concat([ManagerAmount, ',', ProdLineAmount, ',', MachineAmount, ',', Res2],ResultRow2),
    writetoresultfile(QueryFactResultFileTrueTrue, ResultRow2),

    prolog_statistics:call_time(aggregate_all(count,acop:handle(machine_state(_,_)), _), Dict2b),
    get_dict(inferences, Dict2b, Res2b),
    atomic_list_concat([ManagerAmount, ',', ProdLineAmount, ',', MachineAmount, ',', Res2b],ResultRow2b),
    writetoresultfile(QueryRuleResultFileTrueTrue, ResultRow2b),

    prolog_statistics:call_time(aggregate_all(count,acop:handle(start_production_line(_)), _), Dict2c),
    get_dict(inferences, Dict2c, Res2c),
    atomic_list_concat([ManagerAmount, ',', ProdLineAmount, ',', MachineAmount, ',', Res2c],ResultRow2c),
    writetoresultfile(ActionResultFileTrueTrue, ResultRow2c),

    prolog_statistics:call_time(acop:handle(machine_state(m_1_1_1,_)), Dict2d),
    get_dict(inferences, Dict2d, Res2d),
    atomic_list_concat([ManagerAmount, ',', ProdLineAmount, ',', MachineAmount, ',', Res2d],ResultRow2d),
    writetoresultfile(QuerySpecificRuleResultFileTrueTrue, ResultRow2d),

    prolog_statistics:call_time(aggregate_all(count,acop:handle((machine(M),start_machine(M))), _), Dict2e),
        get_dict(inferences, Dict2e, Res2e),
        atomic_list_concat([ManagerAmount, ',', ProdLineAmount, ',', MachineAmount, ',', Res2e],ResultRow2e),
        writetoresultfile(StartMachineResultFileTrueTrue, ResultRow2e),


    % AC TRUE FALSE
    load_access_rules(true),
    use_access_control(true, false, false,[]),
    prolog_statistics:call_time(aggregate_all(count,acop:handle(machine(_)), _), Dict3),
    get_dict(inferences, Dict3, Res3),
    atomic_list_concat([ManagerAmount, ',', ProdLineAmount, ',', MachineAmount, ',', Res3],ResultRow3),
    writetoresultfile(QueryFactResultFileTrueFalse, ResultRow3),

    prolog_statistics:call_time(aggregate_all(count,acop:handle(machine_state(_,_)), _), Dict3b),
    get_dict(inferences, Dict3b, Res3b),
    atomic_list_concat([ManagerAmount, ',', ProdLineAmount, ',', MachineAmount, ',', Res3b],ResultRow3b),
    writetoresultfile(QueryRuleResultFileTrueFalse, ResultRow3b),

    prolog_statistics:call_time(aggregate_all(count,acop:handle(start_production_line(_)), _), Dict3c),
    get_dict(inferences, Dict3c, Res3c),
    atomic_list_concat([ManagerAmount, ',', ProdLineAmount, ',', MachineAmount, ',', Res3c],ResultRow3c),
    writetoresultfile(ActionResultFileTrueFalse, ResultRow3c),

    prolog_statistics:call_time(acop:handle(machine_state(m_1_1_1,_)), Dict3d),
    get_dict(inferences, Dict3d, Res3d),
    atomic_list_concat([ManagerAmount, ',', ProdLineAmount, ',', MachineAmount, ',', Res3d],ResultRow3d),
    writetoresultfile(QuerySpecificRuleResultFileTrueFalse, ResultRow3d),

    prolog_statistics:call_time(aggregate_all(count,acop:handle((machine(M),start_machine(M))), _), Dict3e),
        get_dict(inferences, Dict3e, Res3e),
        atomic_list_concat([ManagerAmount, ',', ProdLineAmount, ',', MachineAmount, ',', Res3e],ResultRow3e),
        writetoresultfile(StartMachineResultFileTrueFalse, ResultRow3e),


    % AC FALSE TRUE
    load_access_rules(false),
    use_access_control(false, true, false,[]),
    prolog_statistics:call_time(aggregate_all(count,acop:handle(machine(_)), _), Dict4),
    get_dict(inferences, Dict4, Res4),
    atomic_list_concat([ManagerAmount, ',', ProdLineAmount, ',', MachineAmount, ',', Res4],ResultRow4),
    writetoresultfile(QueryFactResultFileFalseTrue, ResultRow4),

    prolog_statistics:call_time(aggregate_all(count,acop:handle(machine_state(_,_)), _), Dict4b),
    get_dict(inferences, Dict4b, Res4b),
    atomic_list_concat([ManagerAmount, ',', ProdLineAmount, ',', MachineAmount, ',', Res4b],ResultRow4b),
    writetoresultfile(QueryRuleResultFileFalseTrue, ResultRow4b),

    prolog_statistics:call_time(aggregate_all(count,acop:handle(start_production_line(_)), _), Dict4c),
    get_dict(inferences, Dict4c, Res4c),
    atomic_list_concat([ManagerAmount, ',', ProdLineAmount, ',', MachineAmount, ',', Res4c],ResultRow4c),
    writetoresultfile(ActionResultFileFalseTrue, ResultRow4c),

    prolog_statistics:call_time(acop:handle(machine_state(m_1_1_1,_)), Dict4d),
    get_dict(inferences, Dict4d, Res4d),
    atomic_list_concat([ManagerAmount, ',', ProdLineAmount, ',', MachineAmount, ',', Res4d],ResultRow4d),
    writetoresultfile(QuerySpecificRuleResultFileFalseTrue, ResultRow4d),

   prolog_statistics:call_time(aggregate_all(count,acop:handle((machine(M),start_machine(M))), _), Dict4e),
    get_dict(inferences, Dict4e, Res4e),
    atomic_list_concat([ManagerAmount, ',', ProdLineAmount, ',', MachineAmount, ',', Res4e],ResultRow4e),
    writetoresultfile(StartMachineResultFileFalseTrue, ResultRow4e),


    % AC FALSE FALSE
    load_access_rules(false),
    use_access_control(false, false, false,[]),
    prolog_statistics:call_time(aggregate_all(count,acop:handle(machine(_)), _), Dict5),
    get_dict(inferences, Dict5, Res5),
    atomic_list_concat([ManagerAmount, ',', ProdLineAmount, ',', MachineAmount, ',', Res5],ResultRow5),
    writetoresultfile(QueryFactResultFileFalseFalse, ResultRow5),

    prolog_statistics:call_time(aggregate_all(count,acop:handle(machine_state(_,_)), _), Dict5b),
    get_dict(inferences, Dict5b, Res5b),
    atomic_list_concat([ManagerAmount, ',', ProdLineAmount, ',', MachineAmount, ',', Res5b],ResultRow5b),
    writetoresultfile(QueryRuleResultFileFalseFalse, ResultRow5b),

    prolog_statistics:call_time(aggregate_all(count,acop:handle(start_production_line(_)), _), Dict5c),
    get_dict(inferences, Dict5c, Res5c),
    atomic_list_concat([ManagerAmount, ',', ProdLineAmount, ',', MachineAmount, ',', Res5c],ResultRow5c),
    writetoresultfile(ActionResultFileFalseFalse, ResultRow5c),

    prolog_statistics:call_time(acop:handle(machine_state(m_1_1_1,_)), Dict5d),
    get_dict(inferences, Dict5d, Res5d),
    atomic_list_concat([ManagerAmount, ',', ProdLineAmount, ',', MachineAmount, ',', Res5d],ResultRow5d),
    writetoresultfile(QuerySpecificRuleResultFileFalseFalse, ResultRow5d),

   prolog_statistics:call_time(aggregate_all(count,acop:handle((machine(M),start_machine(M))), _), Dict5e),
    get_dict(inferences, Dict5e, Res5e),
    atomic_list_concat([ManagerAmount, ',', ProdLineAmount, ',', MachineAmount, ',', Res5e],ResultRow5e),
    writetoresultfile(StartMachineResultFileFalseFalse, ResultRow5e).


writetoresultfile(FileName, F):-
    open(FileName,append,Out),
    writeln(Out,F),
    close(Out).



test_patient_amount_query(PatientAmount, Query) :-
	writeln('retracting facts'),
	retractall(info(_,_,_)),
	generate_patient_records(PatientAmount),
	write(PatientAmount),writeln(' patients'),writeln(----------------------------),
	writeln('no access control'),
	time(aggregate_all(count,Query, Answer)),
	write('answer '), writeln(Answer), nl,

	writeln('default access true - body resolution true'),
	use_access_control(true, true, [],[]),
	time(aggregate_all(count,(access_control:handle(Query)), Answer2)),
	write('answer '), writeln(Answer2), nl,

	writeln('default access true - body resolution false'),
	use_access_control(true, false, [],[]),
	time(aggregate_all(count,(access_control:handle(Query)), Answer3)),
	write('answer '), writeln(Answer3), nl,

	writeln('default access false - body resolution true'),
	use_access_control(false, true, [],[]),
	time(aggregate_all(count,(access_control:handle(Query)), Answer4)),
	write('answer '), writeln(Answer4), nl,
	
	writeln('default access false - body resolution false'),
	use_access_control(false, false, [],[]),
	time(aggregate_all(count,(access_control:handle(Query)), Answer5)),
	write('answer '), writeln(Answer5), nl.




:- write('full performance test? (y/n): '),
   read_line_to_string(user_input,PerfTest),
   atom_string(PerfTestA, PerfTest),
   (PerfTestA==y -> full_performance_test ; test_environment).

