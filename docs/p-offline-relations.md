# Offline P instruction relations

This additional analysis is entirely local. It does not call a model or API,
download weights, import a target module, start a server, or invoke target tools.
The existing seven English text heuristics remain a separately scoped detector.

## What is implemented

1. `p_directives.py` tokenizes original English MCP text and recognizes a bounded
   grammar of explicitly named tool invocations and resource reads. It records
   scalar argument literals and character offsets. These are invocation facts,
   not maliciousness judgments. Ordinary workflows produce the same facts.
2. `p_behavior.py` attaches existing grounded Python AST findings to an exact
   server, registered capability, declaration, and handler. Summary diagnostics
   expose effects, sources, guards and trace locations without raw input text.
3. The same module reinterprets a selected handler with directive-specified
   scalar arguments using the existing abstract interpreter. This is static
   specialization; the Python program is not executed. Unknown parameters,
   unsupported conditions, effects or dispatch remain partial.
4. `p_relations.py` composes those facts. A new P finding needs an explicit
   cross-component directive, one exact same-server target, supported argument
   binding, and a completed specialization with a concrete sensitive transfer,
   fixed high-risk command, or destructive resource consequence. A generic
   input-to-shell vulnerability or network capability is insufficient.
5. `P_RETURN_FLOW_SUMMARY` records the provenance of extracted output fragments
   using locations, hashes and traces. It is not a vulnerability verdict.

The source may be any of the five conceptual P surfaces: tool description,
tool result, resource, input-schema description, or prompt. Metadata/body
subsurfaces retain their existing seven coverage keys.

## Evidence and reporting

The agent-mediated edge is always `possible`. A specialized static consequence
does not prove that a host or model followed the instruction, nor that the
package author intended harm. Network destination and credential audience
limitations from the core engine still apply.

Modeled library calls describe possible normal-success paths; they do not
prove that a network request succeeds, a file exists, or a runtime environment
permits the action. Unsupported exception/context-manager constructs and
dynamic execution leave specialization partial rather than inventing a path.

A standalone relation uses rule `mcp-p-offline-instruction-chain`, category `P`,
kind `semantic_indicator`, evidence strength `traced_or_grounded`, pending human
review, and an uncalibrated policy confidence of 0.5. Existing P findings at the
same source are enriched instead of charging that source twice. Independently
grounded core findings retain their original identities.

`P_HANDLER_BEHAVIOR_SUMMARY` describes supported observed effects only. An empty
summary must never be read as an assertion that the handler has no side effects.

The versioned `p_offline_relations` engine reports its own scope and status.
Unsupported/unresolved relations, grammar budgets and failed specialization stay
explicit. They cannot clear an existing coverage gap or convert partial to
complete. Existing validated-token certificates prove absence of the old regex
patterns only; omitted token fields leave the new relation scope partial.

## Supported scope and boundaries

- English explicit named invocations and scalar literal bindings only.
- Quoted names are supported; explicit reported examples and negations are
  treated conservatively. This is not full natural-language understanding.
- Cross-component Python consequences only. Self-directed instructions and
  JavaScript/TypeScript consequence specialization need separate models.
- Literal published resource URIs are resolved from approved source text.
  Dynamic URIs or ambiguous targets are not guessed.
- Top-level prose omissions are not evidence that an agent selects Python
  defaults. Missing bindings cannot certify a triggering path.
- Untrusted external content reaching a protocol return is not automatically
  prompt injection. Constant text can contain a real injection and is still
  inspected. A test filename does not exempt code from analysis.
- Delimiters, annotations, word choices, or a stated read-only purpose do not
  by themselves establish safety or successful sanitization.
- No new general-purpose taint engine, trained language model, unrestricted
  dispatcher resolver, or arbitrary code/description alignment is claimed.

## Research inputs

The implementation is independent and reuses this project's own interpreter;
it does not vendor third-party scanner code.

- Cisco MCP Scanner, commit
  `8c3cae130a12afb7b3abfe9c8a4e2a5e2b103735`: capability anchoring,
  evidence composition, separation of capability risk and malicious behavior,
  and explicit handling of analysis failures.
  https://github.com/cisco-ai-defense/mcp-scanner/tree/8c3cae130a12afb7b3abfe9c8a4e2a5e2b103735
- MCP-BiFlow: protocol-aware handler/dispatch recovery, request/return boundary
  reasoning and trace provenance. Paper: https://arxiv.org/abs/2605.07836
  Artifact examined: https://zenodo.org/records/19465735 (v3).
  Some rule configuration files in that archive are Git LFS pointers, so a full
  reproducible run of that artifact was not claimed.
- Connor: composed influence paths and code evidence. Its interactive host and
  LLM judges are not incorporated into this offline implementation.
  https://arxiv.org/abs/2604.01905

## Validation requirements

Acceptance checks distinguish the triggering literal from a non-triggering
literal, a rejecting guard, public-data transfer, and generic shell capability.
They cover all five source surfaces, registered aliases, first-party helper
files, server isolation, unresolved bindings, unknown conditions, secret
redaction, disabled P analysis, deduplication, and no target execution.

Development corpus replays must preserve input hashes and non-P finding IDs.
Any observed SIM/BEN scores remain development results. Model-free processing
and passing unit tests do not establish independent benchmark accuracy.
