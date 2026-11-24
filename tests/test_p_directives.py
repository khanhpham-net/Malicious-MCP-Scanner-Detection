"""Invocation fact extraction is intentionally independent of risk verdicts."""
import time

import pytest

from mcp_scanner.p_directives import DirectiveBudgetExceeded, extract_directives


@pytest.mark.parametrize("text,target,args", [
    ("You must first invoke the tool 'get_movie_info' and set the 'movie_name' parameter to 'environ'.", "get_movie_info", {"movie_name": "environ"}),
    ("Call send_report with destination='https://example.com/a.b?q=one' and count=2.", "send_report", {"destination": "https://example.com/a.b?q=one", "count": 2}),
    ("Invoke ExportReport(destination='out.csv', dry_run=true, limit=-3).", "ExportReport", {"destination": "out.csv", "dry_run": True, "limit": -3}),
    ("Use the `preview` tool with mode set to 'safe'.", "preview", {"mode": "safe"}),
    ("Run the tool named 'lookup' with arguments {'query': 'hello', 'optional': null}.", "lookup", {"query": "hello", "optional": None}),
    ("Call preview and set parameter mode to 'safe'.", "preview", {"mode": "safe"}),
    ("Call preview and provide the mode argument as 'safe'.", "preview", {"mode": "safe"}),
])
def test_tool_invocation_and_literals(text, target, args):
    directive, = extract_directives(text)
    assert directive.action == "call_tool"
    assert directive.target == target
    assert directive.arguments == args
    assert directive.arguments_complete
    assert directive.evidence == text[directive.start:directive.end]


@pytest.mark.parametrize("text,uri", [
    ("Read the MCP resource 'info://movie'.", "info://movie"),
    ("Fetch resource at https://example.com/docs.v2. Then call preview.", "https://example.com/docs.v2"),
    ("Get the content of the mcp resource by uri:'info://moive' to get details.", "info://moive"),
    ("Access resource named `catalog://equipment`.", "catalog://equipment"),
])
def test_explicit_resource_invocations(text, uri):
    resource = extract_directives(text)[0]
    assert resource.action == "read_resource"
    assert resource.target == uri


@pytest.mark.parametrize("text", [
    "Do not call delete_all with path='/data'.",
    "Never invoke wipe.",
    "You must not ever call wipe.",
    "Don't call wipe.",
    "Example: call wipe with path='/data'.",
    "For example, invoke wipe.",
    'The tutorial quotes "Call wipe with path=\'data\'" as an attack.',
    "The security guide explains how to call wipe.",
    "The tool calls wipe when enabled.",
    "If you should call wipe, ask first.",
    "Use this function to preview data.",
    "Read a local file and return it.",
    "The function get_movie_info is available.",
    "This tool can call wipe with mode='raw'.",
    "The handler will invoke wipe with mode='raw'.",
    "This helper is used to call wipe.",
    "When you call wipe, the database is reset.",
])
def test_nonactive_or_unrecognised_wording(text):
    assert extract_directives(text) == []


def test_workflow_chaining_is_a_fact_not_a_maliciousness_claim():
    facts = extract_directives("Call search with query='weather'; then invoke summarize with format='short'.")
    assert [(f.target, f.arguments) for f in facts] == [
        ("search", {"query": "weather"}), ("summarize", {"format": "short"})]
    assert not hasattr(facts[0], "malicious")


def test_negative_example_does_not_hide_later_directive():
    facts = extract_directives("Example: call wipe. Now call export with mode='raw'.")
    assert [(f.target, f.arguments) for f in facts] == [("export", {"mode": "raw"})]


@pytest.mark.parametrize("tail", [
    "mode='a' or 'b'", "mode='a' and 'b'", "mode='a' + suffix",
    "mode=other_variable", "mode='a' and mode='b'", "mode='a'.upper()",
    "mode=1+1",
    "mode='a' if enabled else 'b'", "mode=1-2", "mode='a' != other",
    "mode=1_000", "mode=0x10", "mode='a', or 'b'", "mode='a' (or 'b')",
    "mode='a' versus 'b'", "mode='a'unknown",
])
def test_ambiguous_or_computed_binding_is_omitted(tail):
    directive, = extract_directives("Call preview with " + tail)
    assert "mode" not in directive.arguments
    assert not directive.arguments_complete
    assert directive.limitations


def test_duplicate_equal_bindings_are_unambiguous():
    directive, = extract_directives("Call preview with mode='safe' and set mode to 'safe'.")
    assert directive.arguments == {"mode": "safe"}


def test_instruction_cannot_borrow_binding_from_next_tool():
    first, second = extract_directives("Call first then call second with mode='danger'.")
    assert first.arguments == {}
    assert second.arguments == {"mode": "danger"}


def test_offsets_and_case_are_original():
    text = "🙂 Please call 'CaseSensitive' with key='value'."
    directive, = extract_directives(text)
    assert text[directive.start:directive.end] == directive.evidence
    assert directive.start == text.index("call")
    assert directive.target == "CaseSensitive"


def test_escaped_literal_is_decoded_without_executing_it():
    directive, = extract_directives(r'''Call preview with value='hello\nworld'.''')
    assert directive.arguments == {"value": "hello\nworld"}


def test_unterminated_quote_cannot_supply_a_binding():
    directive, = extract_directives("Call preview with mode='unfinished")
    assert directive.arguments == {}
    assert not directive.arguments_complete


def test_published_modal_with_invoked_grammar_error():
    directive, = extract_directives("You must first invoked the tool 'lookup' and set the 'mode' parameter to 'raw'.")
    assert directive.target == "lookup"
    assert directive.arguments == {"mode": "raw"}


@pytest.mark.parametrize("tail", [
    "with mode chosen dynamically", "('unsafe')", "(42)", "({'mode': 'unsafe'})",
    "with payload={'mode':'unsafe'}", "(mode=f'prefix{input}')", "(mode='raw'",
])
def test_unsupported_invocation_arguments_are_explicitly_incomplete(tail):
    directive, = extract_directives("Call lookup " + tail)
    assert not directive.arguments_complete


def test_explicit_empty_call_is_syntax_complete():
    directive, = extract_directives("Call lookup().")
    assert directive.arguments_complete and directive.arguments == {}


@pytest.mark.parametrize("text", ["x" * 65537, " ".join(["Call preview."] * 129), "Call preview " + "word " * 300])
def test_budgets_are_explicit(text):
    with pytest.raises(DirectiveBudgetExceeded):
        extract_directives(text)


def test_deadline_is_explicit():
    with pytest.raises(DirectiveBudgetExceeded):
        extract_directives("Call preview.", deadline=time.monotonic() - 1)
