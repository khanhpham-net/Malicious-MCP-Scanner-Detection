"""Extract bounded tool/resource outputs using the shared static resolver."""
from __future__ import annotations

import ast
import hashlib
from dataclasses import replace
from .models import SourceSpan, TraceStep
from .p_surface import SurfaceText
from .p_domains import NonTextValue, SequenceDomain, MappingDomain
from .p_text_constraints import ValidatedToken, token_proof_available
from .python_ast.index import location
from .p_static import (
    StaticText as _Text, StaticPath as _Path,
    StaticFile as _File, UnresolvedValue as _Unknown,
)


from .p_output_flow import OutputValueResolver, StaticMapping, PossibleValues, StaticInstance, StaticSet


class _OutputExtractor(OutputValueResolver):
    def emit(self, value, context, returned, field_path="result", possible=False):
        self.tick()
        if isinstance(value, ValidatedToken) and token_proof_available():
            self.proved_no_instruction.append({"field_path":field_path,"domain":"validated-ascii-single-token",
                "pattern_sha256":hashlib.sha256(value.pattern.encode()).hexdigest(),
                "scope":"standalone field cannot match the reviewed multiword P rules"})
            return
        if isinstance(value, NonTextValue):
            self.proved_non_text.append({"field_path":field_path,"domain":value.kind})
            return
        if value is None or type(value) in {int,float,bool}:
            self.proved_non_text.append({"field_path":field_path,"domain":"constant-"+type(value).__name__})
            return
        if isinstance(value, SequenceDomain):
            self.emit(value.element, context, returned, field_path + "[*]", possible=True)
        elif isinstance(value, MappingDomain):
            if value.max_length != 0:
                self.emit(value.key, context, returned, field_path + ".key[*]", possible=True)
                self.emit(value.value, context, returned, field_path + ".value[*]", possible=True)
        elif isinstance(value, PossibleValues):
            self.emit(value.uncertainty, context, returned, field_path)
            for member in value.values:
                self.emit(member, context, returned, field_path, possible=True)
        elif isinstance(value, StaticMapping):
            for index, (key, member) in enumerate(value.entries.values()):
                self.emit(key, context, returned, f"{field_path}.key[{index}]", possible=possible)
                self.emit(member, context, returned, f"{field_path}.value[{index}]", possible=possible)
        elif isinstance(value, _Unknown):
            self.result.status = "partial"
            self.result.diagnostics.append({
                "code": value.code, "component": context["component"],
                "server_id": context["server_id"], "location": value.span.to_dict(), "field_path": field_path,
            })
        elif isinstance(value, _Text):
            trace = list(value.trace) or [TraceStep("artifact", value.span, symbol="static tool output")]
            if returned:
                trace.append(TraceStep("sink", returned, symbol="handler return"))
            if possible:
                trace = [replace(step, edge_kind="possible") for step in trace]
            limits = list(value.limitations)
            if possible:
                limits.append("Text is on a statically possible branch; runtime selection is unverified.")
            self.result.texts.append(SurfaceText(
                server_id=context["server_id"], component=context["component"],
                surface_kind=context["surface_kind"], text=value.value, content_span=value.span,
                declaration_span=context["declaration"], trace=trace,
                field_path=field_path, limitations=limits,
            ))
        elif isinstance(value, (list, tuple)):
            for index, member in enumerate(value):
                self.emit(member, context, returned, f"{field_path}[{index}]", possible=possible)
        elif isinstance(value, (_File, _Path, StaticInstance, StaticSet, bytes, complex)):
            self.result.status = "partial"
            self.result.diagnostics.append({"code": "P_OUTPUT_UNSUPPORTED_VALUE", "component": context["component"]})
        elif value is not None and type(value) not in {int, float, bool}:
            self.result.status = "partial"
            self.result.diagnostics.append({"code": "P_OUTPUT_UNSUPPORTED_VALUE", "component": context["component"]})

    def run(self, servers, *, kind="tool", surface_kind="tool_result"):
        components=[]
        try:
            for server in servers:
                for reg in server.get("registrations", []):
                    self.tick()
                    if reg["kind"] != kind:
                        continue
                    span = SourceSpan.from_dict(reg["handler_span"])
                    parsed = self.parse(span)
                    handler = parsed[1].get((span.start_line,span.start_col)) if parsed else None
                    if not isinstance(handler,(ast.FunctionDef,ast.AsyncFunctionDef)):
                        self.result.status="partial"
                        self.result.diagnostics.append({"code":"P_OUTPUT_HANDLER_UNAVAILABLE","location":span.to_dict()})
                        continue
                    module = parsed[0]
                    self.begin_handler()
                    self.input_kind=kind
                    if any(name=="mcp" or name.startswith("mcp.") or name=="fastmcp" or name.startswith("fastmcp.") for name in self.module_paths):
                        self.pending_gaps.append(_Unknown("P_OUTPUT_UNVERIFIED_INPUT_CONTRACT",span))
                    env = dict(self.module_environment(module.path))
                    parameters = [*handler.args.posonlyargs, *handler.args.args, *handler.args.kwonlyargs]
                    parameters.extend(arg for arg in (handler.args.vararg, handler.args.kwarg) if arg is not None)
                    positional=[*handler.args.posonlyargs,*handler.args.args]
                    defaults=dict(zip([p.arg for p in positional[len(positional)-len(handler.args.defaults):]],
                                      handler.args.defaults))
                    defaults.update({p.arg:v for p,v in zip(handler.args.kwonlyargs,handler.args.kw_defaults) if v is not None})
                    for arg in parameters:
                        value=self.input_value(module,arg.annotation or arg)
                        if arg.arg in defaults:
                            default=defaults[arg.arg]
                            if isinstance(default,ast.Call) and self.canonical_symbol(module,ast.unparse(default.func)) in {"pydantic.Field","pydantic.fields.Field"}:
                                value=self.constrain_input_text(module,value,default)
                                raw=default.args[0] if default.args else next((k.value for k in default.keywords if k.arg=="default"),None)
                                has_default=(raw is not None and not (isinstance(raw,ast.Constant) and raw.value is Ellipsis)
                                             or any(k.arg=="default_factory" for k in default.keywords))
                                if has_default:
                                    fallback=self.field_default(module,default)
                                    value=PossibleValues((value,fallback),None)
                            else:
                                fallback=self.value(module,default,self.module_environment(module.path))
                                value=PossibleValues((value,fallback),None)
                        env[arg.arg]=value
                    first_text=len(self.result.texts)
                    first_issue=len(self.result.diagnostics)
                    self.proved_non_text=[]
                    self.proved_no_instruction=[]
                    value, returned = self.body(module,handler.body,env)
                    context={"server_id":server["server_id"],"surface_kind":surface_kind,"component":f"{kind}:{reg['name']}",
                             "declaration":SourceSpan.from_dict(reg["declaration_span"])}
                    self.emit(value,context,returned)
                    for gap in self.pending_gaps:self.emit(gap,context,None,"effects")
                    for text in self.pending_error_texts:self.emit(text,context,None,"error_response",possible=True)
                    issues=self.result.diagnostics[first_issue:]
                    unique_issues=[]
                    seen=set()
                    for issue in issues:
                        key=(issue.get("code"),str(issue.get("location")),issue.get("field_path"))
                        if key not in seen:
                            unique_issues.append(issue);seen.add(key)
                    self.result.diagnostics[first_issue:]=unique_issues
                    fragments=self.result.texts[first_text:]
                    components.append({
                        "server_id":server["server_id"],"component":context["component"],
                        "status":"partial" if unique_issues else "complete",
                        "observed_text_fragments":len(fragments),
                        "proved_non_text_fields":list({(v["field_path"],v["domain"]):v for v in self.proved_non_text}.values()),
                        "proved_no_instruction_fields":list({(v["field_path"],v["pattern_sha256"]):v for v in self.proved_no_instruction}.values()),
                        "observed_field_paths":list(dict.fromkeys(t.field_path for t in fragments)),
                        "unresolved_fields":[{"field_path":i.get("field_path"),"code":i.get("code"),"location":i.get("location")} for i in unique_issues]
                    })
        except (TimeoutError,RecursionError):
            self.result.status="partial"
            self.result.diagnostics.append({"code":"P_OUTPUT_EXTRACTION_BUDGET"})
        if components:
            self.result.diagnostics.append({
                "code":"P_OUTPUT_COVERAGE_SUMMARY","level":"info","surface":surface_kind,
                "scope":"immutable approved snapshot return text under the declared FastMCP input contract",
                "components":components,
            })
        return self.result


def extract_python_tool_results(inventory,discovered_servers,*,deadline=None):
    """Observe bounded static outputs; read file contents only from inventory.

    Supports literal collections, known text wrappers, root-relative literal paths
    and __file__-anchored paths, bounded first-party helpers and simple methods.
    Possible conditional text is retained with partial coverage. Interpolation and
    unobserved files produce partial coverage. No target code or file is opened.
    """
    return _OutputExtractor(inventory,deadline).run(discovered_servers)



def extract_python_resource_results(inventory, discovered_servers, *, deadline=None):
    """Reuse static output/file resolution for resource text handlers."""
    result = _OutputExtractor(inventory,deadline).run(
        discovered_servers,kind="resource",surface_kind="resource_body")
    aliases = {
        "P_OUTPUT_UNSUPPORTED_CALL": "P_RESOURCE_DYNAMIC_BODY",
        "P_OUTPUT_DYNAMIC_VALUE": "P_RESOURCE_DYNAMIC_BODY",
        "P_OUTPUT_UNRESOLVED_VALUE": "P_RESOURCE_DYNAMIC_BODY",
        "P_OUTPUT_UNSUPPORTED_BODY": "P_RESOURCE_UNSUPPORTED_BODY",
        "P_OUTPUT_EXTRACTION_BUDGET": "P_RESOURCE_EXTRACTION_BUDGET",
    }
    for diagnostic in result.diagnostics:
        diagnostic["code"] = aliases.get(diagnostic["code"],diagnostic["code"])
    return result
