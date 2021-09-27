:- debug(debug_access_control).

:- use_module(acop).
:- use_module(random).


:- use_access_control(
    false,
    true,
    false,
    ['='/2, '>'/2]
).

% % KNOWLEDGE BASE
% FACTS
current_user(alice).
production_line(l1).
line_manager(alice, l1).
production_line(l2).
line_manager(bob, l2).
machine(m1).
location(m1, l1).
machine(m2).
location(m2, l1).
machine(m3).
location(m3, l2).

%RULES
start_production_line(P) :- production_line(P), location(M,P), start_machine(M).
machine_state(M,S) :- machine(M), request_state(M, S).

request_state(M,S) :- write('requesting state...'), nl, random(R), (R>0.5 -> S=on;S=off).

% % ACCESS CONTROL POLICIES
% policy 1
acop:allow(location(_,_)).
% policy 2
acop:allow(machine(M)) :- current_user(U), line_manager(U,P), location(M,P).
% policy 3
acop:allow(start_machine(M)) :- access(machine(M)).
% policy 4
acop:allow(machine_state(M,_)) :- current_user(U), line_manager(U,L), location(M,L).

