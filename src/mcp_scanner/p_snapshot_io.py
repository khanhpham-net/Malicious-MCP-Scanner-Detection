"""Read-only byte/JSON models using only approved inventory snapshot text."""
from __future__ import annotations

import ast
from dataclasses import dataclass, replace
import json
from pathlib import PurePosixPath, PureWindowsPath

from .models import SourceSpan, TraceStep
from .p_static import StaticPath, StaticText, UnresolvedValue
from .python_ast.index import location


@dataclass(frozen=True)
class BinaryFile:
    path: StaticPath


@dataclass(frozen=True)
class StaticBytes:
    value: bytes
    span: SourceSpan
    trace: tuple = ()
    limitations: tuple = ()


class SnapshotIoMixin:
    def json_text(self,value,source):
        from .p_output_flow import StaticMapping
        self.tick()
        if isinstance(value,str):
            return StaticText(value,source.span,source.trace,source.limitations+(
                "Decoded JSON locations cover the artifact, not individual string offsets.",))
        if isinstance(value,list):return [self.json_text(v,source) for v in value]
        if isinstance(value,dict):
            return StaticMapping({k:(self.json_text(k,source),self.json_text(v,source)) for k,v in value.items()})
        return value

    def snapshot_call(self,module,node,name,args,kw,receiver=None,method=None):
        def unknown(code):return self.unknown(code,module,node)
        if name=="json.loads" and len(args)==1 and not kw:
            source=args[0]
            if isinstance(source,(StaticText,StaticBytes)):
                if len(source.value)>65536:return unknown("P_OUTPUT_TEXT_LIMIT")
                try:return self.json_text(json.loads(source.value),source)
                except (ValueError,UnicodeError,RecursionError):return unknown("P_OUTPUT_INVALID_JSON")
            return unknown("P_OUTPUT_DYNAMIC_JSON")
        if name=="json.load" and len(args)==1 and isinstance(args[0],BinaryFile) and not kw:
            source=self.binary_read(module,node,args[0].path)
            if isinstance(source,StaticBytes):
                try:return self.json_text(json.loads(source.value),source)
                except (ValueError,UnicodeError,RecursionError):return unknown("P_OUTPUT_INVALID_JSON")
            return source
        if isinstance(receiver,StaticPath):
            if method in {"exists","is_file","is_symlink"} and not args and not kw:
                from .p_domains import NonTextValue
                raw=receiver.value.replace("\\","/")
                candidate=PurePosixPath(raw)
                if candidate.is_absolute() or PureWindowsPath(raw).drive or ".." in candidate.parts:
                    return NonTextValue("bool")
                path=candidate.as_posix()
                if path in self.records:
                    return method!="is_symlink"
                prefix="" if path=="." else path.rstrip("/")+"/"
                if any(p.startswith(prefix) for p in self.records):
                    return method=="exists"
                return NonTextValue("bool")
            if method=="open" and args and self.literal(args[0])=="rb" and len(args)==1 and not kw:
                return BinaryFile(receiver)
            if method=="read_bytes" and not args and not kw:
                return self.binary_read(module,node,receiver)
        if isinstance(receiver,BinaryFile) and method=="read" and len(args)<=1 and not kw:
            value=self.binary_read(module,node,receiver.path)
            if not isinstance(value,StaticBytes):return value
            if args:
                count=self.literal(args[0])
                if type(count) is not int:return unknown("P_OUTPUT_UNSUPPORTED_READ")
                if count>=0:value=replace(value,value=value.value[:count])
            return value
        if isinstance(receiver,StaticBytes):
            if method=="decode" and len(args)<=1 and not kw:
                encoding=self.literal(args[0]) if args else "utf-8"
                if encoding not in {"utf-8","utf8","UTF-8"}:return unknown("P_OUTPUT_UNSUPPORTED_READ")
                try:return StaticText(receiver.value.decode("utf-8"),receiver.span,receiver.trace,receiver.limitations)
                except UnicodeError:return unknown("P_OUTPUT_INVALID_UTF8")
        return NotImplemented

    def binary_read(self,module,node,path):
        if not isinstance(path,StaticPath):return self.unknown("P_OUTPUT_DYNAMIC_PATH",module,node)
        raw=path.value.replace("\\","/")
        candidate=PurePosixPath(raw)
        if candidate.is_absolute() or PureWindowsPath(raw).drive or ".." in candidate.parts or candidate.suffix.lower() not in {".json",".txt",".md"}:
            return self.unknown("P_OUTPUT_FILE_PATH_UNSUPPORTED",module,node)
        record=self.records.get(candidate.as_posix())
        if record is None or record.text is None:
            return self.unknown("P_OUTPUT_FILE_UNAVAILABLE",module,node)
        data=record.text.encode("utf-8")
        if len(data)>65536:return self.unknown("P_OUTPUT_TEXT_LIMIT",module,node)
        lines=record.text.splitlines()
        span=SourceSpan(record.rel_path,start_line=1,start_col=1,end_line=max(1,len(lines)),
                        end_col=len(lines[-1])+1 if lines else 1)
        return StaticBytes(data,span,(
            TraceStep("artifact",span,symbol="approved snapshot bytes"),
            TraceStep("call",location(module.path,node),symbol="static binary read"),
        ),("Bytes were reconstructed only from approved UTF-8 inventory text; runtime file changes are unobserved.",))
