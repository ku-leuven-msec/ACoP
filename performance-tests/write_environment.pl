

generate_manufacturing_environment(ManagerAmount, ProdLineAmount, MachineAmount) :-
    atomic_list_concat(['performance-tests/configurations/manufacturing_environment_', ManagerAmount, '_', ProdLineAmount, '_', MachineAmount, '.pl'],FileName),
    asserta(fileName(FileName)),
    remove_old_file,
	writeln('generating manufacturing environment ...'),
	write_front_matter,
	write_rules,
	foreach(between(1,ManagerAmount,ManagerNr),
	    (generate_manager_record(ManagerNr),
	    foreach(between(1, ProdLineAmount,ProdLineNr),
	        (generate_productionline_record(ManagerNr, ProdLineNr),
	        foreach(between(1, MachineAmount, MachineNr), generate_machine_record(ManagerNr, ProdLineNr, MachineNr)))))),
	retractall(manageramount(_)),
    retractall(prodlineamount(_)),
    retractall(machineamount(_)).

remove_old_file :-
    fileName(FileName),
    exists_file(FileName) -> delete_file(FileName); true.

write_front_matter :-
    writetofile(':- discontiguous location/2'),
    writetofile(':- discontiguous machine/1'),
    writetofile(':- discontiguous manager/1'),
    writetofile(':- discontiguous line_manager/2'),
    writetofile(':- discontiguous production_line/1').

write_rules :-
    writetofile('start_production_line(P) :- production_line(P), location(M,P), start_machine(M)'),
    writetofile('machine_state(M,S) :- machine(M), request_state(M, S)'),
    writetofile('start_machine(M) :- write(\'starting machine \'), write(M), writeln(\'...\')'),
    writetofile('request_state(M,S) :- write(\'requesting state of machine \'), write(M), writeln(\'...\'), S=on').

writetofile(F):-
    fileName(FileName),
    open(FileName,append,Out),
    write(Out,F), writeln(Out, '.'),
    close(Out).


generate_manager_record(ManagerNr) :-
    atom_concat(manager,ManagerNr,ManagerName),
    writetofile(manager(ManagerName)).

generate_productionline_record(ManagerNr, ProdLineNr) :-
    atomic_list_concat([l,'_',ManagerNr,'_', ProdLineNr], ProdLineName),
    writetofile(production_line(ProdLineName)),
    atom_concat(manager,ManagerNr,ManagerName),
    writetofile(line_manager(ManagerName, ProdLineName)).

generate_machine_record(ManagerNr, ProdLineNr, MachineNr) :-
    atomic_list_concat([l,'_',ManagerNr,'_', ProdLineNr], ProdLineName),
    atomic_list_concat([m,'_',ManagerNr,'_', ProdLineNr, '_', MachineNr], MachineName),
    writetofile(machine(MachineName)),
    writetofile(location(MachineName, ProdLineName)).


