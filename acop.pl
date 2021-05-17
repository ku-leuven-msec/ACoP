:- module(access_control, [use_access_control/3, access/1]).

:- multifile allow/1.
:- multifile deny/1.

use_access_control(Default_Access, Body_Resolution, Allowed_Predicates) :- 
  create_prolog_flag(default_access, Default_Access,  [access(read_only), type(boolean), keep(true)]),
  create_prolog_flag(body_resolution, Body_Resolution,  [access(read_only), type(boolean), keep(true)]),
  asserta(allowed_predicates(Allowed_Predicates)),
  asserta(user:expand_query(Query,Out, Arg, Arg) :- (allowed_predicate(Query), Out=Query);(Out=(access_control:handle(Query)), debug(debug_access_control, 'expand_query query: ~w- args: ~w ', [Query,Arg]))).

access(X) :- default_access, must_be(nonvar, X), (allow(X); \+deny(X)).
access(X) :- \+default_access, must_be(nonvar, X), (allow(X), \+deny(X)).

%---------------
%---utilities---
%---------------
allowed_predicate(X) :- allowed_predicates(List), member(M,List), pi_head(M,X).
foreign_predicate(X) :- predicate_property(X,foreign).
built_in_predicate(X) :-  predicate_property(X, built_in).
public_predicate(P) :- \+predicate_property(P, foreign), \+predicate_property(P, built_in).

compound_term(T) :- current_predicate(',',T).
compound_term(T) :- current_predicate(';',T).

default_access :- current_prolog_flag(default_access, true).
body_resolution :- current_prolog_flag(body_resolution, true).

%------------------------
%---access definitions----
%------------------------
access_rule_exists(P) :- (allow_exists(P);deny_exists(P)),!.
allow_exists(P) :-   
    clause(allow(TP),_), 
    unifiable(TP,P,_). 

deny_exists(P) :-  
    clause(deny(TP),_), 
    unifiable(TP,P,_). 

%---------------
accessibility_determined(P) :- 
    access_rule_exists(P),
    all_allow_rules_determined(P),
    all_deny_rules_determined(P).

all_allow_rules_determined(P) :-
    copy_term(P,TP),
    forall(clause(allow(TP),B),(subsumes_chk(TP,P),term_variables(TP, Vars), forall(member(V, Vars),\+contains_var(V,B)))).

all_deny_rules_determined(P) :-
    copy_term(P,TP),
    forall(clause(deny(TP),B),(subsumes_chk(TP,P), term_variables(TP, Vars), forall(member(V, Vars),\+contains_var(V,B)))).

%---------------
access_control(P) :- default_access, (allow_check(P); \+deny_check(P)),!.
access_control(P) :- \+default_access, allow_check(P),\+deny_check(P),!.

allow_check(P) :-     
    copy_term(P,TP),
    allow(TP).

allow_check(P) :- allowed_predicate(P).

deny_check(P) :-
    copy_term(P,TP),
    deny(TP).

%---------------
pre_access_control(P) :- default_access, (pre_allow_check(P); \+pre_deny_check(P)),!.
pre_access_control(P) :- \+default_access, pre_allow_check(P),\+pre_deny_check(P),!.

pre_allow_check(P) :-     
    copy_term(P,TP),
    pre_allow(TP).

pre_allow_check(P) :- allowed_predicate(P).

pre_deny_check(P) :-
    copy_term(P,TP),
    pre_deny(TP).

%--------------------
%---term breakdown---
%--------------------
handle(T) :- \+compound_term(T),handle_predicate(T).
handle((T1,T2)) :- handle(T1), handle(T2), \+deny_check(T1).
handle((T1;T2)) :- handle(T1); handle(T2).

%------------------------
%---predicate handling---
%------------------------
handle_predicate(P) :- public_predicate(P) -> handle_public_predicate(P); handle_access(P).

handle_public_predicate(P) :- 
  clause(P,Body), 
  (access_rule_exists(P) 
    -> (accessibility_determined(P) 
          -> handle_access(P, Body)
          ; process_body_sbs(P,Body))
    ; handle_body_resolution(P, Body)).

handle_access(P) :- pre_access_control(P),  user:P,  access_control(P).
handle_access(P,Body) :- pre_access_control(P), user:Body,  access_control(P).

handle_body_resolution(P, Body) :- body_resolution -> handle(Body) ; handle_access(P, Body).

process_body_sbs(P,Body) :- sbs(P, Body, Result), handle_sbs_result(Result).

%-------------------------
%---handle step by step---
%-------------------------

sbs(P, B, state(P,Exec, ToExec)) :- sbs(P, [], B, Exec, ToExec).

sbs(P, Executed, B, Exec, ToExec) :-
  \+compound_term(B),
  (foreign_predicate(B)
    ->(pre_access_control(B), user:B,append(Executed, [B], Exec), ToExec=[])
    ;(built_in_predicate(B) 
        -> (user:B, append(Executed, [B], Exec), ToExec=[])
        ;(\+clause(B, _)
            -> ( B, append(Executed, [B], Exec), ToExec=[])
            ;(clause(B, B2), 
                (B2==true 
                  ->(B, append(Executed, [B], Exec),ToExec=[])
                  ;(sbs(P, [] , B2, ExecTemp, ToExecTemp), Exec = state(B, ExecTemp, ToExecTemp), ToExec=[])))))).

sbs(P, Executed, (B1,B2), Exec, ToExec) :-
  nth0(0, Executed, _),
  sbs(P, Executed, B1, Exec1, _),
  append(Executed, Exec1, ExecutedTotal),
  (accessibility_determined(P) 
    ->  (Exec = ExecutedTotal, ToExec=[B2])
    ;   ((access_rule_exists(P)
           -> (sbs(P, ExecutedTotal, B2, Exec, ToExec))
           ; (Exec = ExecutedTotal, ToExec=[B2])))).

sbs(P, [], (B1,B2), Exec, ToExec) :-
  sbs(P, [], B1, Exec1, _),
  (accessibility_determined(P) 
    ->  (Exec = Exec1, ToExec=[B2])
    ;   (access_rule_exists(P)
           -> (sbs(P, [B1], B2, Exec, ToExec) )
           ; (Exec = Exec1, ToExec=[B2]))).

sbs(P, Executed, (B1;B2), Exec, ToExec) :-
  sbs(P, Executed, B1, Exec, ToExec); sbs(P, Executed, (B2), Exec, ToExec). 

handle_sbs_result(state(H, Executed, ToExecute)) :-
  accessibility_determined(H)
    -> (pre_access_control(H), execute_state(Executed, ToExecute))
    ; (body_resolution -> (execute_state_body_resolution(Executed, ToExecute));(default_access, execute_state(Executed, ToExecute))).

execute_state_body_resolution(Executed, [ToExecute]) :-
  execute_body_resolution_executed(Executed),
  handle(ToExecute).

execute_state_body_resolution(Executed, []) :-
  execute_body_resolution_executed(Executed).

execute_body_resolution_executed([state(P, Executed, [ToExecute])|Rest]) :-
  accessibility_determined(P)
    -> (pre_access_control(P), execute_state(Executed, [ToExecute]), execute_body_resolution_executed(Rest))
    ; (execute_body_resolution_executed(Executed), handle(ToExecute), execute_body_resolution_executed(Rest)).

execute_body_resolution_executed([First |Rest]) :-
  current_predicate(X, First), \+(X=state),
  access_control(First), execute_body_resolution_executed(Rest).

execute_body_resolution_executed([]).
  
execute_state(Executed, ToExecute) :-
  execute_executed(Executed), 
  execute_to_execute(ToExecute).

execute_executed([state(_, Executed, ToExecute) |Rest]) :-
  execute_executed(Executed), 
  execute_to_execute(ToExecute), 
  execute_executed(Rest). 

execute_executed([First |Rest]) :- 
  current_predicate(X, First), \+(X=state),
  execute_executed(Rest).

execute_executed([]). 

execute_to_execute([First|Rest]) :-
  First,  execute_to_execute(Rest).

execute_to_execute([]).