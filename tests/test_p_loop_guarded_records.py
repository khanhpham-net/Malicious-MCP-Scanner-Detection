"""Guard/heap contracts independent of the development dataset; AST only."""
import pytest

from test_p_loop_summaries import ATTACK, SAFE, check, is_p


@pytest.mark.parametrize('guard', [
    'previous is not None', 'None is not previous',
    'not previous is None', 'previous is not None and value > previous',
    'not (previous is None or value <= previous)',
])
def test_none_guards_allow_loop_carried_numeric_arithmetic(tmp_path, guard):
    result = check(tmp_path,
        f"previous=None\nresult=[]\nfor value in values:\n    if {guard}:\n"
        "        result.append(value-previous)\n    previous=value\nreturn result")
    assert result.status == 'complete'
    assert not is_p(result)


def test_none_guard_narrows_a_conditional_expression(tmp_path):
    result = check(tmp_path,
        "previous=None\nresult=[]\nfor value in values:\n"
        "    result.append(value-previous if previous is not None else 0)\n"
        "    previous=value\nreturn result")
    assert result.status == 'complete'


def test_short_circuit_does_not_evaluate_none_arithmetic(tmp_path):
    result = check(tmp_path,
        "previous=None\nresult=[]\nfor value in values:\n"
        "    if previous is not None and value-previous > 5:\n"
        "        result.append({'distance':value-previous,'state':'gap'})\n"
        "    previous=value if previous is None else max(value,previous)\nreturn result")
    assert result.status == 'complete'


@pytest.mark.parametrize('guard', ['previous is None and enabled', 'previous is None or enabled'])
def test_boolean_guards_do_not_infer_facts_from_disjunctive_paths(tmp_path, guard):
    result = check(tmp_path,
        f"previous=None\nresult=[]\nfor value in values:\n    if {guard}:\n"
        "        result.append(value-previous)\n    previous=value\nreturn result",
        signature='values:list[int], enabled:bool')
    assert result.status == 'partial'


def test_none_filter_keeps_server_controlled_text(tmp_path):
    result = check(tmp_path,
        f"previous=None\nresult=[]\nfor enabled in values:\n    if previous is not None:\n"
        f"        result.append(previous)\n    previous={ATTACK!r} if enabled else None\nreturn result",
        signature='values:list[bool]')
    assert result.status == 'complete'
    assert is_p(result)


def test_none_filter_does_not_certify_unknown_input_text(tmp_path):
    result = check(tmp_path,
        "previous=None\nresult=[]\nfor value in values:\n    if previous is not None:\n"
        "        result.append(previous)\n    previous=text\nreturn result",
        signature='values:list[int], text:str')
    assert result.status == 'partial'


@pytest.mark.parametrize('record', ['[value,PAYLOAD]', "{'entry':[value,PAYLOAD]}", '[value,[PAYLOAD]]'])
@pytest.mark.parametrize('payload', [SAFE, ATTACK])
def test_fresh_nested_list_snapshots_keep_all_text(tmp_path, record, payload):
    record = record.replace('PAYLOAD', repr(payload))
    result = check(tmp_path,
        f"result=[]\nfor value in values:\n    result.append({record})\nreturn result")
    assert result.status == 'complete'
    assert is_p(result) is (payload == ATTACK)


def test_fresh_list_tail_append_keeps_payload_after_the_loop(tmp_path):
    result = check(tmp_path,
        f"result=[]\nfor value in values:\n    result.append([value])\n"
        f"result.append([{ATTACK!r}])\nreturn result")
    assert result.status == 'complete'
    assert is_p(result)


@pytest.mark.parametrize('mutation', ["result[0][0]='safe'", "result[0].clear()", "result[0].append('safe')"])
def test_modifying_a_representative_cannot_erase_other_rows(tmp_path, mutation):
    result = check(tmp_path,
        f"result=[]\nfor value in values:\n    result.append([{ATTACK!r}])\n{mutation}\nreturn result")
    assert result.status == 'partial'


def test_reused_named_list_is_not_frozen_as_a_fresh_literal(tmp_path):
    result = check(tmp_path,
        f"result=[]\nitem=[]\nfor value in values:\n    result.append(item)\n"
        f"item.append({ATTACK!r})\nreturn result")
    assert result.status == 'partial' or is_p(result)


def test_mutable_leaf_from_an_input_cannot_be_frozen(tmp_path):
    result = check(tmp_path,
        "result=[]\nfor value in values:\n    result.append([provided])\nreturn result",
        signature='values:list[int], provided:list[str]')
    assert result.status == 'partial'


def test_unguarded_none_arithmetic_does_not_become_complete(tmp_path):
    result = check(tmp_path,
        "previous=None\nresult=[]\nfor value in values:\n"
        "    result.append(value-previous)\n    previous=value\nreturn result")
    assert result.status == 'partial'
