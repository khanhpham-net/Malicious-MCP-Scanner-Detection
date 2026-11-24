"""Prompt message extraction through the shared bounded return-flow engine."""
from __future__ import annotations

import ast
from dataclasses import replace
import time

from .models import SourceSpan
from .p_static import StaticText, UnresolvedValue
from .p_output_flow import StaticMapping, PossibleValues
from .p_tool_result import _OutputExtractor


class PromptOutputExtractor(_OutputExtractor):
    def issue(self, code, context, value=None):
        self.result.status="partial"
        self.result.diagnostics.append({
            "code":code,"server_id":context["server_id"],"component":context["component"],
            "location":(value.span if isinstance(value,UnresolvedValue) else context["declaration"]).to_dict(),
        })

    def text_content(self, value, context, returned, path, role, possible):
        if isinstance(value,PossibleValues):
            if value.uncertainty is not None:
                self.issue("P_PROMPT_DYNAMIC_CONTENT",context,value.uncertainty)
            for part in value.values:
                self.text_content(part,context,returned,path,role,True)
            return
        if isinstance(value,StaticMapping):
            fields={k:v for k,(_,v) in value.entries.items()}
            if self.literal(fields.get("type"))=="text" and "text" in fields:
                return self.text_content(fields["text"],context,returned,path,role,possible)
            self.issue("P_PROMPT_UNSUPPORTED_MESSAGE",context)
            return
        if not isinstance(value,StaticText):
            self.issue("P_PROMPT_DYNAMIC_CONTENT",context,value)
            return
        first=len(self.result.texts)
        super().emit(value,context,returned,path,possible)
        for item in self.result.texts[first:]:
            item.trace[0]=replace(item.trace[0],note=f"role={role}")
            if role=="unverified":
                item.limitations.append("Prompt role is unverified; content is statically possible only.")

    def emit(self,value,context,returned,field_path="result",possible=False):
        self.tick()
        if field_path in {"effects","error_response"}:
            return super().emit(value,context,returned,field_path,possible)
        path="messages" if field_path=="result" else field_path
        if isinstance(value,PossibleValues):
            if value.uncertainty is not None:
                self.issue("P_PROMPT_DYNAMIC_MESSAGE",context,value.uncertainty)
            for part in value.values:
                self.emit(part,context,returned,path,True)
        elif isinstance(value,list):
            if path!="messages":
                self.issue("P_PROMPT_UNSUPPORTED_MESSAGE",context)
                return
            for index,part in enumerate(value):
                self.emit(part,context,returned,f"messages[{index}]",possible)
        elif isinstance(value,StaticText):
            self.text_content(value,context,returned,path+".content","user",possible)
        elif isinstance(value,StaticMapping):
            fields={k:v for k,(_,v) in value.entries.items()}
            role=self.literal(fields.get("role"))
            if "content" not in fields:
                self.issue("P_PROMPT_DYNAMIC_MESSAGE",context)
                return
            if role not in {"user","assistant"}:
                self.issue("P_PROMPT_DYNAMIC_MESSAGE",context)
                if isinstance(fields.get("role"),UnresolvedValue):
                    role="unverified";possible=True
                else:
                    return
            self.text_content(fields["content"],context,returned,path+".content",role,possible)
        elif value is None and self.pending_error_texts:
            pass
        elif isinstance(value,UnresolvedValue):
            code=("P_PROMPT_DYNAMIC_MESSAGE" if value.code in {"P_OUTPUT_DYNAMIC_CALL","P_PROMPT_DYNAMIC_MESSAGE"} else
                  "P_PROMPT_DYNAMIC_CONTENT" if value.code in {"P_OUTPUT_DYNAMIC_VALUE","P_OUTPUT_RUNTIME_PARAMETER"} else
                  "P_PROMPT_UNSUPPORTED_MESSAGE")
            self.issue(code,context,value)
        else:
            self.issue("P_PROMPT_UNSUPPORTED_MESSAGE",context)


def extract_prompt_outputs(inventory,servers,*,deadline=None):
    extractor=PromptOutputExtractor(inventory,deadline)
    if deadline is not None and time.monotonic()>=deadline:
        extractor.result.status="partial"
        extractor.result.diagnostics.append({"code":"P_PROMPT_EXTRACTION_BUDGET"})
        return extractor.result
    for server in servers:
        for reg in server.get("registrations",[]):
            if reg["kind"]!="prompt":
                continue
            span=SourceSpan.from_dict(reg["handler_span"])
            record=extractor.records.get(span.path)
            if record is not None and record.text is not None:
                try:
                    ast.parse(record.text,filename=span.path)
                except (SyntaxError,ValueError,RecursionError):
                    extractor.result.status="partial"
                    extractor.result.diagnostics.append({"code":"P_PROMPT_PARSE_ERROR","location":span.to_dict()})
    result=extractor.run(servers,kind="prompt",surface_kind="prompt_message")
    aliases={"P_OUTPUT_EXTRACTION_BUDGET":"P_PROMPT_EXTRACTION_BUDGET",
             "P_OUTPUT_HANDLER_UNAVAILABLE":"P_PROMPT_SOURCE_UNAVAILABLE"}
    for diagnostic in result.diagnostics:
        code=diagnostic.get("code")
        diagnostic["code"]=aliases.get(code,code)
    return result
