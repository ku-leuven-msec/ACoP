# ACoP
## A Structural Approach that brings Access Control to Logic Programming

In the present digital world, we depend on information technology more than ever. Our economy, health, well-being and even our lives depend on it. In this world, information security is a basic requirement, with access control playing a key role in limiting potential risks associated with data exposure. Logic has shown to be very useful in access control.  It has been used to formally explain or verify access control policies, to express or even enforce them. Here, logic is employed as a reasoning service in support of other systems. However, a general access control mechanism for logic programs is not available. 

This work presents ACoP, a structural approach that brings Access Control to Logic Programming. It allows to constrain access to the knowledge base.
The solution supports fine-grained access control using both deny and allow list strategies.
Overhead is limited to defining access rules. The flexibility in expressing these rules allows to realize different access control mechanisms including role based, relationship based and attribute based access control. A Prolog prototype validates the presented approach.

##Using the Module
Integrating ACoP into a Prolog program is straightforward. With three steps each prolog program can be protected with custom access control policies.
### Step 1 - Loading ACoP
```
:- use_module(acop).
```

### Step 2 - Configuring ACoP
  ```
:- use_access_control(
    false,          % default access?     
    true,           % body resolution? 
    false,          % separate set of preliminary access policies?
    ['='/2, '>'/2]  % allowed predicates ([pred_name/arity])
)
```

   1. **Default Access**
   For completeness, it is required to resolve authorization when no explicit permissions are defined. 
   Therefore, ACoP must be configured for either an open (boolean value set to `true`) or a closed policy (boolean value set to `false`). In an open policy strategy, access is granted by default, while in a closed strategy, access is default denied.
   2. **Body Resolution**
   When no explicit permissions for a predicate can be found, ACoP can be configured to infer permissions based on logic rules defining the predicate (boolean value set to`true`). 
   In other words, if a rule exists that defines the predicate , it is checked whether access can be explicitly determined for each predicate in that definition. Body resolution is disabled by setting the boolean value to `false`.
   3. **Preliminary Access Policies** 
   In certain cases, it may be desirable to define a separate set of access policies which are used before resolution.
   This is usually only the case when using impure predicates. 
   4. **Allowed Predicates** 
   A list of predicates for which no access control is performed can be provided, these can for example be predicates used for arithmetic operations.


### Step 3 - Defining Access Policies
#### access policies
```
acop:allow(<pred>) :- <optional_conditions>.
acop:deny(<pred>) :- <optional_conditions>.
```
#### preliminary access policies 
Only when the module is configured to support a separate set of preliminary access control policies
```
acop:pre_allow(<pred>) :- <optional_conditions>.
acop:pre_deny(<pred>) :- <optional_conditions>.
```

