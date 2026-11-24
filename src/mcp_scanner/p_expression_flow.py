"""Whitelisted abstract expressions for P; target functions are only parsed."""
from __future__ import annotations

import ast
from copy import deepcopy
from dataclasses import replace
from itertools import product
import operator

from .models import SourceSpan, TraceStep
from .p_domains import ClassSymbol, NonTextValue, SequenceDomain, StaticLambda, RuntimeInputText, BuiltinType, BuiltinFunction, RaisedValue, StaticRaised, CaughtException, AnnotationValue
from .p_static import StaticText, UnresolvedValue
from .p_text_constraints import ValidatedToken, ascii_token_pattern
from .python_ast.index import dotted, location


class ExpressionFlowMixin:
    MAX_ALTERNATIVES = 32

    def lift(self, module, node, function, *values):
        from .p_output_flow import PossibleValues
        variants = []
        uncertainty = None
        size = 1
        for value in values:
            if isinstance(value, PossibleValues):
                options = value.values
                uncertainty = uncertainty or value.uncertainty
            else:
                options = (value,)
            size *= len(options)
            if size > self.MAX_ALTERNATIVES:
                return self.unknown("P_OUTPUT_ALTERNATIVE_LIMIT", module, node)
            variants.append(options)
        results = []
        for args in product(*variants):
            self.tick()
            try:
                results.append(function(*args))
            except (ValueError, TypeError, KeyError, IndexError, OverflowError, ZeroDivisionError):
                results.append(self.unknown("P_OUTPUT_OPERATION_UNRESOLVED", module, node))
        if len(results) == 1 and uncertainty is None:
            return results[0]
        return PossibleValues(tuple(results), uncertainty)

    def numeric(self, value):
        from .p_output_flow import PossibleValues
        if isinstance(value,PossibleValues):
            return value.uncertainty is None and all(self.numeric(v) for v in value.values)
        return type(value) in {int, float, bool} or isinstance(value, NonTextValue)

    def text_result(self, module, node, text, *sources):
        if len(text) > 65536:
            return self.unknown("P_OUTPUT_TEXT_LIMIT", module, node)
        trace = tuple(step for source in sources if isinstance(source, StaticText) for step in source.trace)
        return StaticText(text, location(module.path, node), trace,
                          ("A supported text transformation uses the source expression span.",))

    def binary(self, module, node, left, right):
        from .p_output_flow import PossibleValues
        from .p_static import StaticPath
        if isinstance(node.op,ast.Div) and isinstance(left,StaticPath) and isinstance(right,StaticText):
            from pathlib import PurePosixPath
            return StaticPath((PurePosixPath(left.value)/right.value).as_posix(),left.anchored)
        if self.numeric(left) and self.numeric(right):
            if isinstance(left, NonTextValue) or isinstance(right, NonTextValue):
                return NonTextValue("number")
            functions = {ast.Add: operator.add, ast.Sub: operator.sub, ast.Mult: operator.mul,
                         ast.Div: operator.truediv, ast.FloorDiv: operator.floordiv,
                         ast.Mod: operator.mod, ast.Pow: operator.pow}
            fn = functions.get(type(node.op))
            if fn:
                if isinstance(node.op, ast.Pow) and abs(right) > 8:
                    return NonTextValue("number")
                if abs(left) > 10**15 or abs(right) > 10**15:
                    return NonTextValue("number")
                return fn(left, right)
        from .p_output_flow import StaticSet
        if isinstance(left, StaticSet) and isinstance(right, StaticSet) and isinstance(
                node.op, (ast.Sub, ast.BitOr, ast.BitAnd, ast.BitXor)):
            a, b = {}, {}
            for source, destination in ((left, a), (right, b)):
                for item in source.values:
                    raw = self.literal(item)
                    if type(raw) not in {str, int, float, bool, type(None)}:
                        return self.unknown("P_OUTPUT_DYNAMIC_SET", module, node)
                    destination[raw] = item
            keys = ({ast.Sub: lambda: a.keys()-b.keys(),
                     ast.BitOr: lambda: a.keys()|b.keys(),
                     ast.BitAnd: lambda: a.keys()&b.keys(),
                     ast.BitXor: lambda: a.keys()^b.keys()}[type(node.op)])()
            # Stable source order without comparing heterogeneous Python values.
            order = list(dict.fromkeys([*a, *b]))
            return StaticSet([a[k] if k in a else b[k] for k in order if k in keys])
        if isinstance(node.op, ast.Add):
            if isinstance(left, StaticText) and isinstance(right, StaticText):
                return self.text_result(module, node, left.value + right.value, left, right)
            if isinstance(left, list) and isinstance(right, list) and len(left)+len(right) <= self.MAX_LOOP_ITEMS:
                return left+right
        return self.unknown("P_OUTPUT_DYNAMIC_VALUE", module, node)

    def compare(self, module, node, left, right, op):
        from .p_output_flow import StaticMapping, StaticSet
        if isinstance(left, NonTextValue) or isinstance(right, NonTextValue):
            return NonTextValue("bool")
        a, b = self.literal(left), self.literal(right)
        if isinstance(right, StaticMapping):
            b = list(right.entries)
        elif isinstance(right, StaticSet):
            b = [self.literal(v) for v in right.values]
        elif isinstance(right, list):
            b = [self.literal(v) for v in right]
        scalar = lambda v: v is None or type(v) in {str, int, float, bool}
        functions = {ast.Eq: operator.eq, ast.NotEq: operator.ne, ast.Lt: operator.lt,
                     ast.LtE: operator.le, ast.Gt: operator.gt, ast.GtE: operator.ge,
                     ast.Is: operator.is_, ast.IsNot: operator.is_not,
                     ast.In: lambda x,y:x in y, ast.NotIn: lambda x,y:x not in y}
        if scalar(a) and (scalar(b) or isinstance(b,list) and all(scalar(v) for v in b)):
            return functions[type(op)](a,b)
        return NonTextValue("bool") if scalar(a) or scalar(b) else self.unknown("P_OUTPUT_DYNAMIC_CONDITION", module, node)

    def apply_lambda(self, module, node, function, args):
        if isinstance(function,BuiltinFunction):
            return self.builtin(module,node,function.name,args,{})
        if not isinstance(function, StaticLambda):
            return self.unknown("P_OUTPUT_DYNAMIC_CALL",module,node)
        parsed = self.parse(SourceSpan(function.path))
        params = function.node.args
        if not parsed or params.vararg or params.kwarg or len(params.args)!=len(args):
            return self.unknown("P_OUTPUT_ARGUMENT_BINDING",module,node)
        env = dict(function.env)
        env.update((p.arg,v) for p,v in zip(params.args,args))
        return self.value(parsed[0],function.node.body,env)

    def comprehension(self,module,node,env):
        from .p_output_flow import StaticMapping,PossibleValues
        def combine(parts):
            if any(isinstance(v,UnresolvedValue) for v in parts):
                return next(v for v in parts if isinstance(v,UnresolvedValue))
            if isinstance(node,ast.DictComp):
                result=StaticMapping({})
                for part in parts:
                    if not isinstance(part,StaticMapping):return self.unknown("P_OUTPUT_DYNAMIC_MAPPING",module,node)
                    result.entries.update(part.entries)
                return result
            result=[];abstract=False
            for part in parts:
                if isinstance(part,SequenceDomain):
                    result.append(part.element);abstract=True
                    continue
                if not isinstance(part,list):return self.unknown("P_OUTPUT_DYNAMIC_SEQUENCE",module,node)
                result.extend(part)
                if len(result)>self.MAX_LOOP_ITEMS:return self.unknown("P_OUTPUT_LOOP_BOUNDARY",module,node)
            return SequenceDomain(PossibleValues(tuple(result),None)) if abstract and result else result
        def walk(index,local):
            self.tick()
            if index==len(node.generators):
                if isinstance(node,ast.DictComp):
                    key=self.value(module,node.key,local);raw=self.literal(key)
                    if type(raw) not in {str,int,float,bool,type(None)}:return self.unknown("P_OUTPUT_DYNAMIC_MAPPING",module,node)
                    return StaticMapping({raw:(key,self.value(module,node.value,local))})
                return [self.value(module,node.elt,local)]
            generator=node.generators[index]
            if generator.is_async:return self.unknown("P_OUTPUT_ASYNC_ITERATION",module,node)
            sequence=self.value(module,generator.iter,local)
            def consume(seq):
                items=self.sequence_items(seq)
                if isinstance(seq,SequenceDomain):
                    if isinstance(node,ast.DictComp):return self.unknown("P_OUTPUT_DYNAMIC_MAPPING",module,node)
                    calls=[n for n in ast.walk(node) if isinstance(n,ast.Call)]
                    pure={"int","float","bool","str","len","round","abs","min","max","sum","enumerate","zip","range","sorted","list","tuple","set","any","all"}
                    nested=dict(local)
                    if not self.bind_target(module,generator.target,seq.element,nested):return self.unknown("P_OUTPUT_LOOP_BINDING",module,node)
                    for call in calls:
                        if isinstance(call.func,ast.Name) and call.func.id in pure and not self.lookup(module,module.qualify(call.func.id)):continue
                        if isinstance(call.func,ast.Attribute) and call.func.attr=="model_dump" and not call.args and not call.keywords:
                            receiver=self.value(module,call.func.value,nested)
                            from .p_output_flow import StaticInstance
                            if isinstance(receiver,StaticInstance):
                                parsed=self.parse(SourceSpan(receiver.path))
                                found=self.lookup(parsed[0],receiver.class_name) if parsed else None
                                if found and self.simple_model(*found):continue
                        return self.unknown("P_OUTPUT_LOOP_EFFECT",module,node)
                    for condition in generator.ifs:
                        value=self.value(module,condition,nested)
                        if self.conditional_gap(value) is not None:return self.unknown("P_OUTPUT_COMPREHENSION_FILTER",module,condition)
                    value=walk(index+1,nested)
                    if isinstance(value,list) and value:return SequenceDomain(PossibleValues(tuple(value),None))
                    return value
                if items is None or len(items)>self.MAX_LOOP_ITEMS:return self.unknown("P_OUTPUT_LOOP_BOUNDARY",module,node)
                parts=[];uncertain_filter=False
                for item in items:
                    nested=dict(local)
                    if not self.bind_target(module,generator.target,item,nested):return self.unknown("P_OUTPUT_LOOP_BINDING",module,node)
                    for condition in generator.ifs:
                        test=self.value(module,condition,nested);truth=self.truth(test)
                        if truth is False:break
                        if truth is None:
                            if self.conditional_gap(test) is not None or isinstance(node,ast.DictComp):
                                return self.unknown("P_OUTPUT_COMPREHENSION_FILTER",module,condition)
                            if any(isinstance(n,ast.Call) for n in ast.walk(node.elt)):
                                return self.unknown("P_OUTPUT_COMPREHENSION_EFFECT",module,condition)
                            uncertain_filter=True
                    else:
                        parts.append(walk(index+1,nested))
                result=combine(parts)
                if uncertain_filter and isinstance(result,list) and result:
                    return SequenceDomain(PossibleValues(tuple(result),None))
                return result
            return self.lift(module,node,consume,sequence)
        return walk(0,dict(env))

    def canonical_symbol(self,module,symbol):
        qualified=module.qualify(symbol)
        seen=set()
        while qualified not in seen:
            seen.add(qualified)
            owner,_,member=qualified.rpartition(".")
            paths=self.module_paths.get(owner,[])
            parsed=self.parse(SourceSpan(paths[0])) if len(paths)==1 else None
            if not parsed or member not in parsed[0].aliases:break
            qualified=parsed[0].qualify(member)
        return qualified

    def safe_builtin_factory(self,module,node):
        if not isinstance(node,ast.Name) or node.id not in {"list","tuple","dict","set"}:
            return False
        if self.canonical_symbol(module,node.id)!=node.id or self.lookup(module,node.id):
            return False
        for statement in module.tree.body:
            if isinstance(statement,(ast.Assign,ast.AnnAssign)):
                targets=statement.targets if isinstance(statement,ast.Assign) else [statement.target]
                if any(isinstance(t,ast.Name) and t.id==node.id for t in targets):
                    return False
            if isinstance(statement,(ast.If,ast.For,ast.While,ast.Try,ast.With)) and any(
                    isinstance(n,ast.Name) and isinstance(n.ctx,ast.Store) and n.id==node.id for n in ast.walk(statement)):
                return False
        return True

    def safe_annotation_metadata(self,module,node,active=None):
        active=set() if active is None else active
        for child in ast.walk(node):
            self.tick()
            if isinstance(child,ast.Call):
                if self.canonical_symbol(module,dotted(child.func)) not in {"pydantic.Field","pydantic.fields.Field"}:
                    return False
                basic={"default","default_factory","description","title","ge","le","gt","lt",
                       "min_length","max_length","pattern","strict","frozen","multiple_of","allow_inf_nan","alias"}
                if any(k.arg not in basic for k in child.keywords):
                    return False
                for keyword in child.keywords:
                    if keyword.arg=="default_factory" and not self.safe_builtin_factory(module,keyword.value):
                        return False
            if isinstance(child,ast.Name):
                symbol=self.canonical_symbol(module,child.id)
                owner,_,member=symbol.rpartition(".")
                target=module if not owner or owner==module.name else None
                if target is None:
                    paths=self.module_paths.get(owner,[])
                    parsed=self.parse(SourceSpan(paths[0])) if len(paths)==1 else None
                    target=parsed[0] if parsed else None
                if target:
                    key=(target.path,member or symbol)
                    if key in active:continue
                    for stmt in target.tree.body:
                        targets=stmt.targets if isinstance(stmt,ast.Assign) else [stmt.target] if isinstance(stmt,ast.AnnAssign) else []
                        if any(isinstance(t,ast.Name) and t.id==(member or symbol) for t in targets) and stmt.value is not None:
                            if not self.safe_annotation_metadata(target,stmt.value,active|{key}):return False
        return True

    def constrain_input_text(self,module,value,field):
        if getattr(self,"input_kind","tool")!="tool":
            return value
        if not isinstance(field,ast.Call) or self.canonical_symbol(module,dotted(field.func)) not in {"pydantic.Field","pydantic.fields.Field"}:
            return value
        if not self.safe_annotation_metadata(module,field):
            return value
        if isinstance(value,SequenceDomain):
            bounds={k.arg:k.value.value for k in field.keywords if k.arg in {"min_length","max_length"}
                    and isinstance(k.value,ast.Constant) and type(k.value.value) is int and k.value.value>=0}
            lower=max(value.min_length,bounds.get("min_length",0))
            upper=bounds.get("max_length",value.max_length)
            if value.max_length is not None and upper is not None:upper=min(value.max_length,upper)
            return SequenceDomain(value.element,lower,upper)
        if not isinstance(value,RuntimeInputText):
            return value
        pattern=next((k.value.value for k in field.keywords if k.arg=="pattern"
                      and isinstance(k.value,ast.Constant) and isinstance(k.value.value,str)),None)
        if ascii_token_pattern(pattern):
            return ValidatedToken("P_OUTPUT_VALIDATED_TOKEN",value.span,pattern)
        return value

    def comparable_domain(self,value):
        from .p_output_flow import PossibleValues
        if isinstance(value,(StaticText,RuntimeInputText)):
            return "str"
        if self.numeric(value):
            return "number"
        if isinstance(value,(list,tuple)):
            parts=tuple(self.comparable_domain(v) for v in value)
            return ("tuple",parts) if all(v is not None for v in parts) else None
        if isinstance(value,PossibleValues) and value.uncertainty is None:
            parts=[self.comparable_domain(v) for v in value.values]
            return parts[0] if parts and parts[0] is not None and all(p==parts[0] for p in parts) else None
        return None

    def input_value(self,module,node,active=None):
        from .p_output_flow import PossibleValues
        active=set() if active is None else active
        if any(name=="mcp" or name.startswith("mcp.") or name=="fastmcp" or name.startswith("fastmcp.") for name in self.module_paths):
            return self.unknown("P_OUTPUT_UNVERIFIED_INPUT_CONTRACT",module,node)
        if node is None:
            return self.unknown("P_OUTPUT_RUNTIME_PARAMETER",module,module.tree)
        if isinstance(node,ast.Constant) and node.value is None:return None
        if isinstance(node,ast.BinOp) and isinstance(node.op,ast.BitOr):
            return PossibleValues((self.input_value(module,node.left,active),self.input_value(module,node.right,active)),None)
        if isinstance(node,ast.Subscript):
            origin=module.qualify(dotted(node.value))
            args=list(node.slice.elts) if isinstance(node.slice,ast.Tuple) else [node.slice]
            if origin in {"typing.Annotated","typing_extensions.Annotated"}:
                if not self.safe_annotation_metadata(module,node):
                    return self.unknown("P_OUTPUT_UNVERIFIED_INPUT_METADATA",module,node)
                value=self.input_value(module,args[0],active)
                for metadata in args[1:]:
                    value=self.constrain_input_text(module,value,metadata)
                return value
            if origin in {"typing.Literal","typing_extensions.Literal"} and all(isinstance(a,ast.Constant) for a in args):
                return PossibleValues(tuple(self.value(module,a,{}) for a in args),None)
            if origin in {"list","tuple","set","typing.List","typing.Sequence","typing.Tuple"}:
                if origin in {"list","tuple","set"} and not self.safe_builtin_factory(module,node.value):
                    return self.unknown("P_OUTPUT_UNVERIFIED_INPUT_CONTRACT",module,node)
                if origin in {"tuple","typing.Tuple"} and not (len(args)==2 and isinstance(args[1],ast.Constant) and args[1].value is Ellipsis):
                    if len(args)>self.MAX_ALTERNATIVES:
                        return self.unknown("P_OUTPUT_TUPLE_DOMAIN_LIMIT",module,node)
                    elements=tuple(self.input_value(module,arg,active) for arg in args)
                    element=elements[0] if len(elements)==1 else PossibleValues(elements,None)
                    return SequenceDomain(element,len(args),len(args))
                return SequenceDomain(self.input_value(module,args[0],active))
        symbol=module.qualify(dotted(node))
        rebound=False
        if symbol in {"str","int","float","bool"}:
            for statement in module.tree.body:
                targets=statement.targets if isinstance(statement,ast.Assign) else [statement.target] if isinstance(statement,ast.AnnAssign) else []
                if any(isinstance(t,ast.Name) and t.id==symbol for t in targets):rebound=True
                if isinstance(statement,(ast.FunctionDef,ast.AsyncFunctionDef,ast.ClassDef)) and statement.name==symbol:rebound=True
                if isinstance(statement,(ast.If,ast.For,ast.While,ast.Try,ast.With)) and any(
                    isinstance(n,ast.Name) and isinstance(n.ctx,ast.Store) and n.id==symbol for n in ast.walk(statement)):
                    return self.unknown("P_OUTPUT_UNVERIFIED_INPUT_CONTRACT",module,node)
        if symbol=="str" and not rebound:
            return RuntimeInputText("P_OUTPUT_RUNTIME_PARAMETER",location(module.path,node))
        if symbol in {"int","float","bool"} and not rebound:
            return NonTextValue(symbol)
        found=self.lookup(module,symbol)
        if found and isinstance(found[1],ast.ClassDef):
            return self.model_input(found[0],found[1],active)
        owner,_,name=symbol.rpartition(".")
        target=module if not owner or owner==module.name else None
        if target is None:
            paths=self.module_paths.get(owner,[])
            parsed=self.parse(SourceSpan(paths[0])) if len(paths)==1 else None
            target=parsed[0] if parsed else None
        if target and (target.path,name or symbol) not in active:
            if any(isinstance(statement,(ast.If,ast.For,ast.While,ast.Try,ast.With)) and any(
                    isinstance(n,ast.Name) and isinstance(n.ctx,ast.Store) and n.id==(name or symbol) for n in ast.walk(statement))
                    for statement in target.tree.body):
                return self.unknown("P_OUTPUT_UNVERIFIED_INPUT_CONTRACT",module,node)
            for stmt in reversed(target.tree.body):
                assigned=stmt.targets if isinstance(stmt,ast.Assign) else [stmt.target] if isinstance(stmt,ast.AnnAssign) else []
                if any(isinstance(t,ast.Name) and t.id==(name or symbol) for t in assigned) and stmt.value is not None:
                    return self.input_value(target,stmt.value,active|{(target.path,name or symbol)})
        return self.unknown("P_OUTPUT_RUNTIME_PARAMETER",module,node)

    def model_input(self,module,cls,active):
        from .p_output_flow import StaticInstance
        if not self.simple_model(module,cls) or (module.path,cls.name) in active:
            return self.unknown("P_OUTPUT_UNMODELED_INPUT",module,cls)
        from .p_output_flow import PossibleValues
        fields={}
        for node in cls.body:
            if not isinstance(node,ast.AnnAssign) or not isinstance(node.target,ast.Name):
                continue
            value=self.input_value(module,node.annotation,active|{(module.path,cls.name)})
            default=node.value
            has_default=default is not None and not (isinstance(default,ast.Constant) and default.value is Ellipsis)
            if isinstance(default,ast.Call):
                value=self.constrain_input_text(module,value,default)
                raw=default.args[0] if default.args else next((k.value for k in default.keywords if k.arg=="default"),None)
                has_default=(raw is not None and not (isinstance(raw,ast.Constant) and raw.value is Ellipsis)
                             or any(k.arg=="default_factory" for k in default.keywords))
                fallback=self.field_default(module,default) if has_default else None
            elif has_default:
                fallback=self.value(module,default,self.module_environment(module.path))
            else:
                fallback=None
            fields[node.target.id]=PossibleValues((value,fallback),None) if has_default else value
        return StaticInstance(module.path,cls.name,fields)

    def simple_model(self,module,cls):
        bases={module.qualify(dotted(b)) for b in cls.bases}
        if any(name=="pydantic" or name.startswith("pydantic.") for name in self.module_paths):return False
        if not (bases=={"pydantic.BaseModel"} and not cls.decorator_list and not cls.keywords):return False
        for statement in cls.body:
            if isinstance(statement,ast.AnnAssign):
                if not self.safe_annotation_metadata(module,statement.annotation):return False
                if isinstance(statement.value,ast.Call) and not self.safe_annotation_metadata(module,statement.value):return False
                continue
            if isinstance(statement,ast.Pass):continue
            if isinstance(statement,ast.Expr) and isinstance(statement.value,ast.Constant) and isinstance(statement.value.value,str):continue
            if isinstance(statement,ast.Assign) and len(statement.targets)==1 and isinstance(statement.targets[0],ast.Name) and statement.targets[0].id=="model_config":
                call=statement.value
                if isinstance(call,ast.Call) and module.qualify(dotted(call.func))=="pydantic.ConfigDict" and not call.args and all(
                        k.arg in {"extra","frozen","strict"} and isinstance(k.value,ast.Constant)
                        and (k.arg!="strict" or type(k.value.value) is bool) for k in call.keywords):continue
            return False
        return True

    def construct_model(self,caller,node,target,cls,args,kw):
        from .p_output_flow import StaticInstance
        if not self.simple_model(target,cls) or args:
            return self.unknown("P_OUTPUT_UNMODELED_CONSTRUCTOR",caller,node)
        fields={}
        for field in cls.body:
            if not isinstance(field,ast.AnnAssign) or not isinstance(field.target,ast.Name):continue
            name=field.target.id
            if name in kw:
                fields[name]=kw[name]
            elif field.value is not None and not isinstance(field.value,ast.Call):
                fields[name]=self.value(target,field.value,self.module_environment(target.path))
            elif isinstance(field.value,ast.Call):
                fields[name]=self.field_default(target,field.value)
            else:
                return self.unknown("P_OUTPUT_ARGUMENT_BINDING",caller,node)
        if set(kw)-set(fields):
            return self.unknown("P_OUTPUT_ARGUMENT_BINDING",caller,node)
        return StaticInstance(target.path,cls.name,fields)

    def field_default(self,module,node):
        if module.qualify(dotted(node.func)) not in {"pydantic.Field","pydantic.fields.Field"}:
            return self.unknown("P_OUTPUT_UNMODELED_DEFAULT",module,node)
        keywords={k.arg:k.value for k in node.keywords}
        if len(node.args)==1 and "default" not in keywords:
            return self.value(module,node.args[0],self.module_environment(module.path))
        if "default" in keywords:
            return self.value(module,keywords["default"],self.module_environment(module.path))
        factory=keywords.get("default_factory")
        if self.safe_builtin_factory(module,factory):
            from .p_output_flow import StaticMapping,StaticSet
            return {"list":list,"tuple":list,"dict":lambda:StaticMapping({}),"set":StaticSet}[factory.id]()
        return self.unknown("P_OUTPUT_UNMODELED_DEFAULT",module,node)

    def builtin(self,module,node,name,args,kw):
        from .p_output_flow import StaticMapping,StaticSet,PossibleValues,StaticInstance
        def unknown():return self.unknown("P_OUTPUT_UNSUPPORTED_CALL",module,node)
        if name=="isinstance" and len(args)==2 and not kw:
            candidate,kind=args
            if isinstance(kind,list) and all(isinstance(k,BuiltinType) for k in kind):
                answers=[self.builtin(module,node,"isinstance",[candidate,k],{}) for k in kind]
                return True if True in answers else False if all(v is False for v in answers) else NonTextValue("bool")
            if not isinstance(kind,BuiltinType):return unknown()
            if isinstance(candidate,NonTextValue):
                if candidate.kind in {"int","float","bool"}:
                    return candidate.kind==kind.name or candidate.kind=="bool" and kind.name=="int"
                return NonTextValue("bool")
            if isinstance(candidate,SequenceDomain):
                return NonTextValue("bool") if kind.name in {"list","tuple","set"} else False
            if isinstance(candidate,RuntimeInputText):return kind.name=="str"
            types={"str":StaticText,"list":list,"tuple":tuple,"dict":StaticMapping,"set":StaticSet}
            if kind.name in types:return isinstance(candidate,types[kind.name])
            if type(candidate) in {int,float,bool,type(None)}:
                return isinstance(candidate,{"int":int,"float":float,"bool":bool}[kind.name])
            return NonTextValue("bool")
        if name in {"int","float"} and 1<=len(args)<=2:
            a=args[0]
            if isinstance(a,NonTextValue):return NonTextValue(name)
            if type(a) in {int,float,bool} or isinstance(a,StaticText):
                return {"int":int,"float":float}[name](self.literal(a))
            return self.unknown("P_OUTPUT_DYNAMIC_CONVERSION",module,node) if isinstance(a,UnresolvedValue) else unknown()
        if name=="bool" and len(args)==1:
            truth=self.truth(args[0])
            return NonTextValue("bool") if truth is None else truth
        if name=="str" and len(args)==1:
            a=args[0]
            if isinstance(a,CaughtException):
                message=a.message
                if isinstance(message,StaticText):
                    text=repr(message.value) if a.exception.removeprefix("builtins.")=="KeyError" else message.value
                    return self.text_result(module,node,text,message)
                if message is None or type(message) in {int,float,bool}:
                    return self.text_result(module,node,str(message) if message is not None else "")
                return self.unknown("P_OUTPUT_EXCEPTION_TEXT",module,node)
            if isinstance(a,(StaticText,RuntimeInputText)):return a
            if a is None or type(a) in {int,float,bool}:return self.text_result(module,node,str(a))
            return unknown()
        if name=="len" and len(args)==1:
            a=args[0]
            from .p_snapshot_io import StaticBytes
            if isinstance(a,StaticBytes):return len(a.value)
            items=self.sequence_items(a)
            if items is not None:return len(items)
            if isinstance(a,StaticText):return len(a.value)
            if isinstance(a,RuntimeInputText):return NonTextValue("int")
            if isinstance(a,SequenceDomain):return NonTextValue("int")
            return unknown()
        if name in {"round","abs"} and args and self.numeric(args[0]):
            if isinstance(args[0],NonTextValue):return NonTextValue("number")
            return round(args[0],self.literal(args[1])) if name=="round" and len(args)==2 else round(args[0]) if name=="round" else abs(args[0])
        if name=="range" and 1<=len(args)<=3 and any(isinstance(v,NonTextValue) for v in args) and all(
                type(v) is int or isinstance(v,NonTextValue) and v.kind=="int" for v in args):
            return SequenceDomain(NonTextValue("int"))
        if name=="range" and 1<=len(args)<=3 and all(type(v) is int for v in args):
            result=range(*args)
            return list(result) if len(result)<=self.MAX_LOOP_ITEMS else self.unknown("P_OUTPUT_LOOP_BOUNDARY",module,node)
        if name in {"list","tuple","set"} and len(args)<=1 and not kw:
            items=[] if not args else self.sequence_items(args[0])
            if items is None:return unknown()
            return StaticSet(items) if name=="set" else list(items)
        if name=="enumerate" and args:
            if isinstance(args[0],SequenceDomain):return SequenceDomain([NonTextValue("int"),args[0].element],args[0].min_length,args[0].max_length)
            items=self.sequence_items(args[0]);start=args[1] if len(args)>1 else kw.get("start",0)
            if items is not None and type(start) is int:return [[i,v] for i,v in enumerate(items,start)]
            return unknown()
        if name=="zip":
            if kw:return unknown()
            if any(isinstance(v,SequenceDomain) for v in args):
                elements=[]
                for value in args:
                    if isinstance(value,SequenceDomain):
                        elements.append(value.element)
                    else:
                        items=self.sequence_items(value)
                        if items is None:return unknown()
                        if not items:return []
                        elements.append(items[0] if len(items)==1 else PossibleValues(tuple(items),None))
                return SequenceDomain(elements)
            lists=[self.sequence_items(v) for v in args]
            if all(v is not None for v in lists):return [list(v) for v in zip(*lists)]
            return unknown()
        if name=="collections.Counter" and len(args)==1 and not kw:
            items=self.sequence_items(args[0])
            if items is None:return unknown()
            entries={}
            for value in items:
                key=self.literal(value)
                if type(key) not in {str,int,float,bool,type(None)}:return unknown()
                original,count=entries.get(key,(value,0))
                entries[key]=(original,count+1)
            return StaticMapping(entries)
        if name in {"sum","any","all","min","max","sorted"} and args:
            allowed={"sum":{"start"},"any":set(),"all":set(),"min":{"key","default"},"max":{"key","default"},"sorted":{"key","reverse"}}[name]
            if set(kw)-allowed:return unknown()
            if name in {"any","all","sorted"} and len(args)!=1:return unknown()
            if name=="sum" and (len(args)>2 or len(args)>1 and "start" in kw):return unknown()
            if name in {"min","max"} and len(args)>1 and "default" in kw:return unknown()
            key=kw.get("key")
            reverse=kw.get("reverse",False)
            if name=="sorted" and not (type(reverse) in {bool,int} or isinstance(reverse,NonTextValue) and reverse.kind in {"bool","int"}):
                return self.unknown("P_OUTPUT_SORT_ARGUMENT",module,node)
            items=self.sequence_items(args[0]) if len(args)==1 or name in {"sum","sorted","any","all"} else list(args)
            def pure_key(value):
                if key is None:return value
                pure={"int","float","bool","str","len","round","abs","min","max","sum"}
                if not isinstance(key,(StaticLambda,BuiltinFunction)) or (
                        isinstance(key,StaticLambda) and any(
                            not isinstance(call.func,ast.Name) or call.func.id not in pure
                            or self.lookup(module,module.qualify(call.func.id))
                            for call in ast.walk(key.node.body) if isinstance(call,ast.Call))):
                    return self.unknown("P_OUTPUT_SORT_KEY_EFFECT",module,node)
                return self.apply_lambda(module,node,key,[value])
            if items is None:
                if not isinstance(args[0],SequenceDomain):return unknown()
                element=args[0].element
                if name in {"sorted","min","max"}:
                    comparison=pure_key(element)
                    if self.comparable_domain(comparison) is None:
                        return comparison if isinstance(comparison,UnresolvedValue) else self.unknown("P_OUTPUT_SORT_KEY_UNRESOLVED",module,node)
                    if name=="sorted":return args[0]
                    return PossibleValues((element,kw["default"]),None) if "default" in kw and args[0].min_length==0 else element
                if name=="sum":
                    initial=args[1] if len(args)>1 else kw.get("start",0)
                    return NonTextValue("number") if self.numeric(element) and self.numeric(initial) else unknown()
                if name in {"any","all"} and (self.numeric(element) or isinstance(element,(StaticText,RuntimeInputText,StaticMapping,list,StaticInstance)) or element is None):
                    return NonTextValue("bool")
                return unknown()
            if name in {"any","all"}:
                if any(isinstance(v,UnresolvedValue) and not isinstance(v,RuntimeInputText) for v in items):return unknown()
                truths=[self.truth(v) for v in items]
                if name=="any" and True in truths:return True
                if name=="all" and False in truths:return False
                return NonTextValue("bool") if None in truths else (any(truths) if name=="any" else all(truths))
            if name=="sum":
                initial=args[1] if len(args)>1 else kw.get("start",0)
                if not all(self.numeric(v) for v in [*items,initial]):return unknown()
                return sum(items,initial) if all(type(v) in {int,float,bool} for v in [*items,initial]) else NonTextValue("number")
            if not items:
                return [] if name=="sorted" else kw.get("default",unknown())
            if key is None and all(self.numeric(v) for v in items) and any(type(v) not in {int,float,bool} for v in items):
                return [NonTextValue("number") for _ in items] if name=="sorted" else NonTextValue("number")
            keys=[pure_key(v) for v in items]
            if any(self.comparable_domain(v) is None for v in keys):
                return self.unknown("P_OUTPUT_SORT_KEY_UNRESOLVED",module,node)
            raw=[self.literal(v) for v in keys]
            if not all(type(v) in {int,float,bool,str} for v in raw):
                choice=PossibleValues(tuple(items),None)
                return [choice for _ in items] if name=="sorted" else choice
            if name=="sorted":
                def ordered(flag):
                    return [v for _,v in sorted(zip(raw,items),key=lambda pair:pair[0],reverse=flag)]
                if isinstance(reverse,NonTextValue):
                    return PossibleValues((ordered(False),ordered(True)),None)
                return ordered(bool(reverse))
            index=(min if name=="min" else max)(range(len(items)),key=lambda i:raw[i])
            return items[index]
        return unknown()

    def method(self,module,node,receiver,name,args,kw):
        from .p_output_flow import StaticMapping,StaticInstance,StaticSet,PossibleValues
        snapshot=self.snapshot_call(module,node,"",args,kw,receiver,name)
        if snapshot is not NotImplemented:return snapshot
        if isinstance(receiver,BuiltinType) and receiver.name=="dict" and name=="fromkeys" and 1<=len(args)<=2 and not kw:
            items=self.sequence_items(args[0])
            if items is None:return self.unknown("P_OUTPUT_LOOP_BOUNDARY",module,node)
            entries={}
            for key in items:
                raw=self.literal(key)
                if type(raw) not in {str,int,float,bool,type(None)}:return self.unknown("P_OUTPUT_DYNAMIC_MAPPING",module,node)
                entries[raw]=(key,args[1] if len(args)>1 else None)
            return StaticMapping(entries)
        if isinstance(receiver,RuntimeInputText):
            if name in {"lower","upper","casefold"} and not kw and not args:
                return receiver
            if name in {"strip","lstrip","rstrip"} and not kw and len(args)<=1 and all(
                    isinstance(a,StaticText) or a is None for a in args):
                return receiver
            if name=="replace" and not kw and 2<=len(args)<=3 and all(
                    isinstance(a,StaticText) for a in args[:2]) and (len(args)==2 or type(args[2]) is int):
                if isinstance(receiver,ValidatedToken) and any(not 33<=ord(c)<=126 for c in args[1].value):
                    return RuntimeInputText("P_OUTPUT_RUNTIME_PARAMETER",location(module.path,node))
                return receiver
            if name=="split" and not kw and len(args)<=2:
                return SequenceDomain(receiver)
            if name in {"startswith","endswith","isdigit","isdecimal","isalnum"} and not kw:
                return NonTextValue("bool")
        if isinstance(receiver,list):
            if name=="append" and len(args)==1 and not kw:
                if len(receiver)>=self.MAX_LOOP_ITEMS:return self.unknown("P_OUTPUT_LOOP_BOUNDARY",module,node)
                receiver.append(args[0]);return None
            if name=="extend" and len(args)==1 and not kw:
                items=self.sequence_items(args[0])
                if items is None or len(receiver)+len(items)>self.MAX_LOOP_ITEMS:return self.unknown("P_OUTPUT_LOOP_BOUNDARY",module,node)
                receiver.extend(items);return None
            if name=="pop" and len(args)<=1 and not kw:
                index=args[0] if args else -1
                if type(index) is int:return receiver.pop(index)
            if name=="count" and len(args)==1 and not kw:
                if isinstance(args[0],(UnresolvedValue,NonTextValue)):return NonTextValue("int")
                raw=self.literal(args[0])
                return sum(self.literal(v)==raw for v in receiver)
            if name=="clear" and not args and not kw:
                receiver.clear();return None
            if name=="reverse" and not args and not kw:
                receiver.reverse();return None
        if isinstance(receiver,StaticMapping):
            if name=="update" and len(args)<=1:
                if args:
                    if not isinstance(args[0],StaticMapping):return self.unknown("P_OUTPUT_MUTATION_UNOBSERVED",module,node)
                    receiver.entries.update(args[0].entries)
                receiver.entries.update({k:(StaticText(k,location(module.path,node)),v) for k,v in kw.items()})
                return None
            if name in {"items","keys","values"} and not args and not kw:
                if name=="keys":
                    return StaticSet([k for k,_ in receiver.entries.values()])
                return [[k,v] for k,v in receiver.entries.values()] if name=="items" else [
                    v for _,v in receiver.entries.values()]
            if name=="get" and args:
                raw=self.literal(args[0]);default=args[1] if len(args)>1 else None
                if type(raw) in {str,int,float,bool,type(None)}:return receiver.entries.get(raw,(None,default))[1]
        if isinstance(receiver,ClassSymbol) and name=="model_validate" and len(args)==1 and not kw:
            parsed=self.parse(SourceSpan(receiver.path))
            found=self.lookup(parsed[0],receiver.name) if parsed else None
            if found and isinstance(args[0],StaticMapping):
                return self.construct_model(module,node,found[0],found[1],[],{k:v for k,(_,v) in args[0].entries.items()})
        if isinstance(receiver,StaticInstance) and name=="model_dump" and not args and not kw:
            parsed=self.parse(SourceSpan(receiver.path))
            found=self.lookup(parsed[0],receiver.class_name) if parsed else None
            if found and self.simple_model(*found):
                return StaticMapping({k:(StaticText(k,location(module.path,node)),v) for k,v in receiver.fields.items()})
            return NotImplemented
        if isinstance(receiver,StaticText):
            if name in {"strip","lstrip","rstrip"} and not kw and len(args)<=1 and all(
                    isinstance(a,StaticText) or a is None for a in args):
                text = {"strip":str.strip,"lstrip":str.lstrip,"rstrip":str.rstrip}[name](
                    receiver.value, *[self.literal(a) for a in args])
                from .models import TraceStep
                return replace(receiver, value=text, trace=receiver.trace + (
                    TraceStep("call", location(module.path,node), symbol="static string normalization"),))
            if name in {"isdigit","isdecimal","isalnum"} and not args and not kw:
                return {"isdigit":str.isdigit,"isdecimal":str.isdecimal,"isalnum":str.isalnum}[name](receiver.value)
            raw=[self.literal(v) for v in args]
            if name in {"lower","upper","casefold"} and not args and not kw:
                return self.text_result(module,node,{"lower":str.lower,"upper":str.upper,"casefold":str.casefold}[name](receiver.value),receiver)
            if name in {"startswith","endswith"} and len(raw)==1 and type(raw[0]) is str:
                return receiver.value.startswith(raw[0]) if name=="startswith" else receiver.value.endswith(raw[0])
            if name=="replace" and 2<=len(raw)<=3 and all(type(v) is str for v in raw[:2]):
                return self.text_result(module,node,receiver.value.replace(*raw),receiver)
            if name=="split" and len(raw)<=2 and all(v is None or type(v) in {str,int} for v in raw):
                return [StaticText(v,receiver.span,receiver.trace,receiver.limitations) for v in receiver.value.split(*raw)]
            if name=="join" and len(args)==1:
                items=self.sequence_items(args[0])
                if items is not None and all(isinstance(v,StaticText) for v in items):
                    return self.text_result(module,node,receiver.value.join(v.value for v in items),receiver,*items)
        return NotImplemented

    def cached_base_call(self,module,node,env,args,keywords,receiver=None):
        cache={(id(a),id(env)):v for a,v in zip(node.args,args)}
        cache.update({(id(k.value),id(env)):keywords[k.arg] for k in node.keywords if k.arg in keywords})
        if isinstance(node.func,ast.Attribute):cache[(id(node.func.value),id(env))]=receiver
        self.expression_caches.append(cache)
        try:return self.base_value(module,node,env)
        finally:self.expression_caches.pop()

    def value(self,module,node,env):
        for cache in reversed(getattr(self,"expression_caches",[])):
            key=(id(node),id(env))
            if key in cache:return cache[key]
        result=self.expression_value(module,node,env)
        from .p_output_flow import PossibleValues
        def separate(value):
            if isinstance(value, RaisedValue):
                return [], [value]
            if isinstance(value, PossibleValues):
                normal, raised = [], []
                for member in value.values:
                    n, r = separate(member)
                    normal.extend(n)
                    raised.extend(r)
                if value.uncertainty is not None:
                    normal.append(value.uncertainty)
                return normal, raised
            return [value], []
        normal, raised = separate(result)
        if raised:
            if not self.raise_frames:
                return self.unknown("P_OUTPUT_INITIALIZER_EXCEPTION", module, node)
            # Record exception alternatives before the successful path can
            # mutate the caller environment further.
            for value in raised[1:] if not normal else raised:
                origin = self.outcome("next", env)
                local = self.fork_environment(env)
                self.raise_frames[-1].append(self.outcome(
                    "raise", local, value.message, value.span, value.exception))
                self.activate(origin)
            if not normal:
                raise StaticRaised(raised[0])
            result = normal[0] if len(normal)==1 else PossibleValues(tuple(normal),
                result.uncertainty if isinstance(result, PossibleValues) else None)
        def unbound(value):
            if isinstance(value,UnresolvedValue) and value.code=="P_OUTPUT_POSSIBLY_UNBOUND":
                self.pending_gaps.append(value)
            elif isinstance(value,PossibleValues):
                for part in value.values:
                    unbound(part)
        if isinstance(node,ast.Name):
            unbound(result)
        if isinstance(node,ast.Call) and isinstance(result,UnresolvedValue) and not isinstance(result,RuntimeInputText) and self.handler_envs is not None:
            self.pending_gaps.append(result)
        return result

    def expression_value(self,module,node,env):
        from .p_output_flow import StaticMapping,StaticInstance,PossibleValues
        self.tick()
        if node is None:return None
        if isinstance(node,ast.Set):
            from .p_output_flow import StaticSet
            entries = {}
            for element in node.elts:
                value = self.value(module, element, env)
                raw = self.literal(value)
                if type(raw) not in {str, int, float, bool, type(None)}:
                    return self.unknown("P_OUTPUT_DYNAMIC_SET", module, node)
                entries[raw] = value
            return StaticSet(list(entries.values()))
        if isinstance(node,ast.Lambda):
            return StaticLambda(module.path,node,env)
        if isinstance(node,(ast.ListComp,ast.SetComp,ast.DictComp,ast.GeneratorExp)):
            return self.comprehension(module,node,env)
        if isinstance(node,ast.Dict) and any(k is None for k in node.keys):
            result=StaticMapping({})
            for key,expression in zip(node.keys,node.values):
                if key is None:
                    spread=self.value(module,expression,env)
                    if not isinstance(spread,StaticMapping):return self.unknown("P_OUTPUT_DYNAMIC_MAPPING",module,node)
                    result.entries.update(spread.entries)
                else:
                    k=self.value(module,key,env);raw=self.literal(k)
                    if type(raw) not in {str,int,float,bool,type(None)}:return self.unknown("P_OUTPUT_DYNAMIC_MAPPING",module,node)
                    result.entries[raw]=(k,self.value(module,expression,env))
            return result
        if isinstance(node,ast.IfExp):
            condition=self.value(module,node.test,env);truth=self.truth(condition)
            if truth is not None:return self.value(module,node.body if truth else node.orelse,env)
            origin=self.outcome("next",env);values=[]
            for expression in (node.body,node.orelse):
                self.activate(origin)
                local=self.fork_environment(env)
                values.append(self.value(module,expression,local))
            return PossibleValues(tuple(values),self.conditional_gap(condition))
        if isinstance(node,ast.BinOp):
            left=self.value(module,node.left,env);right=self.value(module,node.right,env)
            from .p_static import StaticPath
            if isinstance(node.op,ast.Div) and isinstance(left,StaticPath) and isinstance(self.literal(right),str):
                from pathlib import PurePosixPath
                return StaticPath((PurePosixPath(left.value)/self.literal(right)).as_posix(),left.anchored)
            return self.lift(module,node,lambda a,b:self.binary(module,node,a,b),left,right)
        if isinstance(node,ast.Compare):
            previous=self.value(module,node.left,env);results=[]
            for op,expression in zip(node.ops,node.comparators):
                current=self.value(module,expression,env)
                results.append(self.lift(module,node,lambda a,b:self.compare(module,node,a,b,op),previous,current, ))
                previous=current
            return False if False in results else True if all(v is True for v in results) else NonTextValue("bool")
        if isinstance(node,ast.UnaryOp):
            val=self.value(module,node.operand,env)
            if isinstance(node.op,ast.Not):
                truth=self.truth(val);return NonTextValue("bool") if truth is None else not truth
            if self.numeric(val):
                def unary(v):
                    if isinstance(v,NonTextValue):return NonTextValue("number")
                    return -v if isinstance(node.op,ast.USub) else v
                return self.lift(module,node,unary,val)
        if isinstance(node,ast.BoolOp):
            def choose(index,local):
                value=self.value(module,node.values[index],local)
                if index==len(node.values)-1:return value
                truth=self.truth(value)
                stop=(truth is False) if isinstance(node.op,ast.And) else (truth is True)
                if stop:return value
                if truth is not None:return choose(index+1,local)
                origin=self.outcome("next",local)
                branch=self.fork_environment(local)
                rest=choose(index+1,branch)
                self.activate(origin)
                returned=False if isinstance(node.op,ast.And) and isinstance(value,NonTextValue) and value.kind=="bool" else (
                    True if isinstance(node.op,ast.Or) and isinstance(value,NonTextValue) and value.kind=="bool" else value)
                return PossibleValues((returned,rest),self.conditional_gap(value))
            return choose(0,env)
        if isinstance(node,ast.Subscript):
            receiver=self.value(module,node.value,env)
            if isinstance(receiver,SequenceDomain) and not isinstance(node.slice,ast.Slice):
                index=self.value(module,node.slice,env)
                if type(index) is int or isinstance(index,NonTextValue) and index.kind=="int":return receiver.element
            if isinstance(node.slice,ast.Slice):
                if isinstance(receiver,SequenceDomain):return receiver
                if (isinstance(receiver,list) and node.slice.lower is None and node.slice.step is None
                        and node.slice.upper is not None and isinstance(self.value(module,node.slice.upper,env),NonTextValue)):
                    if len(receiver)+1>self.MAX_ALTERNATIVES:return self.unknown("P_OUTPUT_ALTERNATIVE_LIMIT",module,node)
                    return PossibleValues(tuple(receiver[:i] for i in range(len(receiver)+1)),None)
                bounds=[self.value(module,v,env) if v is not None else None for v in (node.slice.lower,node.slice.upper,node.slice.step)]
                if all(v is None or type(v) is int for v in bounds):
                    if isinstance(receiver,list):return receiver[slice(*bounds)]
                    if isinstance(receiver,StaticText):return self.text_result(module,node,receiver.value[slice(*bounds)],receiver)
            key=self.value(module,node.slice,env) if not isinstance(node.slice,ast.Slice) else None
            if isinstance(receiver,PossibleValues) or isinstance(key,PossibleValues):
                def select(r,k):
                    raw=self.literal(k)
                    if isinstance(r,StaticMapping) and type(raw) in {str,int,float,bool,type(None)}:
                        return r.entries.get(raw,(None,self.unknown("P_OUTPUT_MISSING_KEY",module,node)))[1]
                    if isinstance(r,list) and type(raw) is int:return r[raw]
                    return self.unknown("P_OUTPUT_DYNAMIC_SUBSCRIPT",module,node)
                return self.lift(module,node,select,receiver,key)
        if isinstance(node,ast.Attribute):
            receiver=self.value(module,node.value,env)
            if isinstance(receiver,PossibleValues):
                return self.lift(module,node,lambda r:r.fields.get(node.attr,self.unknown("P_OUTPUT_DYNAMIC_ATTRIBUTE",module,node)) if isinstance(r,StaticInstance)
                                 else self.unknown("P_OUTPUT_DYNAMIC_ATTRIBUTE",module,node),receiver)
        if isinstance(node,ast.Name) and node.id not in env:
            symbol=module.qualify(node.id)
            found=self.lookup(module,symbol)
            if not found and symbol==node.id and node.id in {"str","int","float","bool","list","tuple","dict","set"}:
                return BuiltinType(node.id)
            if not found and symbol==node.id and node.id in {"abs","len","round"}:
                return BuiltinFunction(node.id)
            if found and isinstance(found[1],ast.ClassDef):
                return ClassSymbol(found[0].path,found[1].name)
        if isinstance(node,ast.Call) and not any(isinstance(a,ast.Starred) for a in node.args) and not any(k.arg is None for k in node.keywords):
            symbol=dotted(node.func);head=symbol.partition(".")[0]
            name=module.qualify(symbol) if head not in env else ""
            if name in {"pydantic.Field","pydantic.fields.Field"} and not self.lookup(module,name) and not any(
                    k=="pydantic" or k.startswith("pydantic.") for k in self.module_paths):
                safe={"default","default_factory","description","title","ge","le","gt","lt",
                      "min_length","max_length","pattern","strict","frozen","multiple_of","allow_inf_nan","alias"}
                if len(node.args)<=1 and all(k.arg in safe for k in node.keywords):
                    factory=next((k.value for k in node.keywords if k.arg=="default_factory"),None)
                    if factory is not None and not self.safe_builtin_factory(module,factory):
                        return self.unknown("P_OUTPUT_UNMODELED_DEFAULT_FACTORY",module,node)
                    # Evaluate argument expressions abstractly; callbacks are not
                    # invoked just because Field itself is metadata.
                    for expression in [*node.args,*[k.value for k in node.keywords if k.arg!="default_factory"]]:
                        value=self.value(module,expression,env)
                        if isinstance(value,UnresolvedValue):
                            return value
                    return AnnotationValue()
                return self.unknown("P_OUTPUT_UNMODELED_FIELD_METADATA",module,node)
            message_roles={"mcp.server.fastmcp.prompts.base.UserMessage":"user",
                           "mcp.server.fastmcp.prompts.base.AssistantMessage":"assistant"}
            wrappers=set(message_roles)|{"mcp.types.PromptMessage","mcp.types.TextContent"}
            if name in wrappers and not self.lookup(module,name) and not any(
                    k=="mcp" or k.startswith("mcp.") for k in self.module_paths):
                args=[self.value(module,a,env) for a in node.args]
                kw={k.arg:self.value(module,k.value,env) for k in node.keywords}
                def mapping(fields):
                    return StaticMapping({k:(StaticText(k,location(module.path,node)),v) for k,v in fields.items()})
                if name in message_roles and len(args)<=1 and not (args and "content" in kw) and not (set(kw)-{"content"}):
                    content=args[0] if args else kw.get("content",self.unknown("P_PROMPT_DYNAMIC_CONTENT",module,node))
                    return mapping({"role":StaticText(message_roles[name],location(module.path,node)),"content":content})
                if name=="mcp.types.PromptMessage" and not args and set(kw)=={"role","content"}:
                    return mapping(kw)
                if name=="mcp.types.TextContent" and not args and set(kw)=={"type","text"} and self.literal(kw["type"])=="text":
                    return mapping(kw)
                return self.unknown("P_PROMPT_DYNAMIC_MESSAGE",module,node)
            builtins={"int","float","bool","str","len","round","abs","range","list","tuple","set","enumerate","zip","sum","min","max","any","all","sorted","collections.Counter","isinstance"}
            found=self.lookup(module,name) if name else None
            snapshot_name=name in {"json.loads","json.load"} and not found
            supported_method=isinstance(node.func,ast.Attribute) and node.func.attr in {
                "items","keys","values","get","model_dump","model_validate","lower","upper","casefold","strip","lstrip","rstrip","startswith","endswith","replace","split","join",
                "append","extend","pop","count","clear","reverse","update",
                "open","read","read_text","read_bytes","decode","exists","is_file","is_symlink","fromkeys","isdigit","isdecimal","isalnum"}
            if name in builtins and not found or found and isinstance(found[1],ast.ClassDef) and self.simple_model(*found) or name=="getattr" or supported_method or snapshot_name:
                args=[self.value(module,a,env) for a in node.args]
                kw={k.arg:self.value(module,k.value,env) for k in node.keywords}
                if snapshot_name:
                    result=self.lift(module,node,lambda *a:self.snapshot_call(module,node,name,list(a),kw),*args)
                    if result is not NotImplemented:return result
                    return self.cached_base_call(module,node,env,args,kw,self.value(module,node.func.value,env))
                if name in builtins and not found:
                    if id(node) in self.awaited_calls:return self.unknown("P_OUTPUT_UNSUPPORTED_AWAIT",module,node)
                    return self.lift(module,node,lambda *a:self.builtin(module,node,name,list(a),kw),*args)
                if found and isinstance(found[1],ast.ClassDef) and self.simple_model(*found):
                    return self.construct_model(module,node,found[0],found[1],args,kw)
                if name=="getattr" and 2<=len(args)<=3:
                    attr=self.literal(args[1])
                    if isinstance(attr,str):
                        return self.lift(module,node,lambda obj:obj.fields.get(attr,args[2] if len(args)>2 else self.unknown("P_OUTPUT_DYNAMIC_ATTRIBUTE",module,node))
                                         if isinstance(obj,StaticInstance) else self.unknown("P_OUTPUT_DYNAMIC_ATTRIBUTE",module,node),args[0])
                if supported_method:
                    receiver=self.value(module,node.func.value,env)
                    if id(node) in self.awaited_calls:return self.unknown("P_OUTPUT_UNSUPPORTED_AWAIT",module,node)
                    mutators={"append","extend","pop","clear","reverse","update"}
                    if node.func.attr in mutators and (isinstance(receiver,PossibleValues) or any(isinstance(v,PossibleValues) for v in args)):
                        gap=self.unknown("P_OUTPUT_MUTATION_ALTERNATIVES",module,node)
                        if isinstance(receiver,list):receiver[:]=[gap]
                        elif isinstance(receiver,StaticMapping):receiver.entries={None:(None,gap)}
                        return gap
                    def resolve_method(r,*a):
                        result=self.method(module,node,r,node.func.attr,list(a),kw)
                        if result is NotImplemented:
                            from .p_static import StaticPath,StaticFile
                            if isinstance(r,(StaticPath,StaticFile)) and node.func.attr in {"open","read","read_text"}:
                                return NotImplemented
                        return result
                    result=self.lift(module,node,resolve_method,receiver,*args)
                    from .p_static import StaticPath,StaticFile
                    if result is NotImplemented and isinstance(receiver,(StaticPath,StaticFile)) and node.func.attr in {"open","read","read_text"}:
                        return self.cached_base_call(module,node,env,args,kw,receiver)
                    if result is not NotImplemented and not isinstance(result,PossibleValues):return result
                    if isinstance(result,PossibleValues) and all(v is not NotImplemented for v in result.values):return result
                    if isinstance(receiver,StaticInstance):
                        parsed=self.parse(SourceSpan(receiver.path))
                        cls=self.lookup(parsed[0],receiver.class_name) if parsed else None
                        fn=next((f for f in reversed(cls[1].body) if isinstance(f,(ast.FunctionDef,ast.AsyncFunctionDef)) and f.name==node.func.attr),None) if cls else None
                        if fn:return self.invoke(module,node,cls[0],fn,[receiver,*args],kw)
                    return self.unknown("P_OUTPUT_UNSUPPORTED_CALL",module,node)
        return self.base_value(module,node,env)
