"""X.509 路径构建规格测试：初始状态 15 个红，全部由 NotImplementedError 触发。"""

from __future__ import annotations

from x509 import (
    build_path,
    name_in_subtree,
    names_constrained,
    parse_cert,
    path_batch,
    path_length_ok,
    policy_ok,
    signature_links,
)


def _dns(value: str) -> dict[str, str]:
    return {"type": "dns", "value": value}


def _cert(
    thumbprint: str,
    cn: str,
    issuer: str,
    *,
    ca: bool = False,
    path_len: int | None = None,
    permitted: list[dict[str, str]] | None = None,
    excluded: list[dict[str, str]] | None = None,
    san: list[str] | None = None,
    policies: list[str] | None = None,
    mappings: list[dict[str, str]] | None = None,
    inhibit: bool = False,
    self_signed: bool = False,
    signature_ok: bool = True,
) -> dict:
    return {
        "thumbprint": thumbprint,
        "subject": {"cn": cn, "san": list(san or [])},
        "issuer": {"cn": issuer},
        "extensions": {
            "basic_constraints": {"ca": ca, "path_len": path_len},
            "name_constraints": {
                "permitted": list(permitted or []),
                "excluded": list(excluded or []),
            },
            "certificate_policies": list(policies or []),
            "policy_mappings": [dict(item) for item in (mappings or [])],
            "inhibit_policy_mapping": inhibit,
        },
        "self_signed": self_signed,
        "signature_ok": signature_ok,
    }


def _request(target: dict, pool: list[dict], anchors: list[dict]) -> dict:
    return {"target": target, "pool": pool, "anchors": anchors}


def _outcome(result: dict) -> dict:
    return {
        "ok": result["ok"],
        "reason": result["reason"],
        "path": [cert["thumbprint"] for cert in result["path"]],
    }


def test_01_name_constraints_check_all_subject_alt_names():
    leaf = _cert(
        "leaf-01",
        "good.example.com",
        "ca-01",
        san=["bad.example.net"],
    )
    parsed = parse_cert(leaf)
    assert parsed["subject"]["san"] == ["bad.example.net"]
    assert parsed["ca"] is False
    assert parsed["path_len"] is None
    assert parsed["name_constraints"] == {"permitted": [], "excluded": []}

    constraints = {"permitted": [_dns("example.com")], "excluded": []}
    assert names_constrained(parsed["subject"], constraints) is False

    ca = _cert(
        "ca-01",
        "ca.example.com",
        "root-01",
        ca=True,
        path_len=1,
        permitted=[_dns("example.com")],
    )
    root = _cert(
        "root-01",
        "root.example.com",
        "root.example.com",
        ca=True,
        self_signed=True,
    )
    result = build_path(leaf, [ca], [root])
    assert result["ok"] is False
    assert result["reason"] == "SAN_NOT_PERMITTED"


def test_02_excluded_subtree_beats_permitted_subtree():
    constraints = {
        "permitted": [_dns("example.com")],
        "excluded": [_dns("secret.example.com")],
    }
    assert name_in_subtree("host.secret.example.com", _dns("example.com")) is True
    assert name_in_subtree("notsecret.example.com", _dns("secret.example.com")) is False
    assert name_in_subtree("a.example.com", _dns("*.example.com")) is True
    assert name_in_subtree("a.b.example.com", _dns("*.example.com")) is False
    assert (
        names_constrained(
            {"cn": "host.secret.example.com", "san": []},
            constraints,
        )
        is False
    )

    leaf = _cert(
        "leaf-02",
        "host.secret.example.com",
        "ca-02",
        san=["host.secret.example.com"],
    )
    ca = _cert(
        "ca-02",
        "ca.example.com",
        "root-02",
        ca=True,
        path_len=1,
        permitted=constraints["permitted"],
        excluded=constraints["excluded"],
    )
    root = _cert(
        "root-02",
        "root.example.com",
        "root.example.com",
        ca=True,
        self_signed=True,
    )
    result = build_path(leaf, [ca], [root])
    assert result["ok"] is False
    assert result["reason"] == "EXCLUDED_NAME"


def test_03_name_constraints_propagate_to_lower_leaf():
    leaf = _cert(
        "leaf-03",
        "ok.example.com",
        "ca2-03",
        san=["evil.test"],
    )
    ca2 = _cert(
        "ca2-03",
        "ca2.example.com",
        "ca1-03",
        ca=True,
        path_len=0,
    )
    ca1 = _cert(
        "ca1-03",
        "ca1.example.com",
        "root-03",
        ca=True,
        path_len=1,
        permitted=[_dns("example.com")],
    )
    root = _cert(
        "root-03",
        "root.example.com",
        "root.example.com",
        ca=True,
        self_signed=True,
    )
    result = build_path(leaf, [ca1, ca2], [root])
    assert result["ok"] is False
    assert result["reason"] == "SAN_NOT_PERMITTED"


def test_04_path_length_counts_intermediates_not_all_certificates():
    leaf = _cert("leaf-04", "leaf.example.com", "ca-04")
    ca = _cert(
        "ca-04",
        "ca.example.com",
        "root-04",
        ca=True,
        path_len=0,
    )
    root = _cert(
        "root-04",
        "root.example.com",
        "root.example.com",
        ca=True,
        self_signed=True,
    )
    chain = [leaf, ca, root]
    assert path_length_ok(chain) is True
    result = build_path(leaf, [ca], [root])
    assert result["ok"] is True
    assert result["reason"] == "OK"


def test_05_path_length_must_decrease_at_each_intermediate():
    leaf = _cert("leaf-05", "leaf.example.com", "lower-05")
    lower = _cert(
        "lower-05",
        "lower.example.com",
        "upper-05",
        ca=True,
        path_len=1,
    )
    upper = _cert(
        "upper-05",
        "upper.example.com",
        "root-05",
        ca=True,
        path_len=1,
    )
    root = _cert(
        "root-05",
        "root.example.com",
        "root.example.com",
        ca=True,
        self_signed=True,
    )
    chain = [leaf, lower, upper, root]
    assert path_length_ok(chain) is False
    result = build_path(leaf, [lower, upper], [root])
    assert result["ok"] is False
    assert result["reason"] == "PATH_LENGTH_NOT_DECREASING"


def test_06_policy_sets_intersect_instead_of_union():
    policy_a = "1.3.6.1.4.1.100.1"
    policy_b = "1.3.6.1.4.1.100.2"
    leaf = _cert(
        "leaf-06",
        "leaf.example.com",
        "ca-06",
        policies=[policy_a],
    )
    ca = _cert(
        "ca-06",
        "ca.example.com",
        "root-06",
        ca=True,
        path_len=1,
        policies=[policy_b],
    )
    root = _cert(
        "root-06",
        "root.example.com",
        "root.example.com",
        ca=True,
        self_signed=True,
        policies=[policy_a],
    )
    chain = [leaf, ca, root]
    policy = {"initial_policy_set": [policy_a]}
    assert policy_ok(chain, policy) is False

    result = path_batch([_request(leaf, [ca], [root])], policy)["results"][0]
    assert result["ok"] is False
    assert result["reason"] == "POLICY_NOT_SATISFIED"


def test_07_inhibit_policy_mapping_rejects_mapping():
    policy_a = "1.3.6.1.4.1.200.1"
    policy_b = "1.3.6.1.4.1.200.2"
    leaf = _cert(
        "leaf-07",
        "leaf.example.com",
        "ca-07",
        policies=[policy_b],
    )
    ca = _cert(
        "ca-07",
        "ca.example.com",
        "root-07",
        ca=True,
        path_len=1,
        policies=[policy_a],
        mappings=[
            {"issuer_domain": policy_a, "subject_domain": policy_b},
        ],
        inhibit=True,
    )
    root = _cert(
        "root-07",
        "root.example.com",
        "root.example.com",
        ca=True,
        self_signed=True,
        policies=[policy_a],
    )
    chain = [leaf, ca, root]
    policy = {"initial_policy_set": [policy_a]}
    assert policy_ok(chain, policy) is False

    result = path_batch([_request(leaf, [ca], [root])], policy)["results"][0]
    assert result["ok"] is False
    assert result["reason"] == "POLICY_MAPPING_INHIBITED"


def test_08_self_signed_certificate_cannot_impersonate_anchor():
    leaf = _cert("leaf-08", "leaf.example.com", "Fake Root")
    fake = _cert(
        "fake-08",
        "Fake Root",
        "Fake Root",
        ca=True,
        path_len=1,
        self_signed=True,
    )
    real = _cert(
        "root-08",
        "Real Root",
        "Real Root",
        ca=True,
        self_signed=True,
    )
    assert signature_links([leaf, fake]) == []

    broken = _cert("broken-08", "leaf.example.com", "Other Root")
    assert signature_links([broken, fake]) == [0]

    result = build_path(leaf, [fake], [real])
    assert result["ok"] is False
    assert result["reason"] == "SELF_SIGNED_NOT_ANCHOR"
    assert result["path"][-1]["thumbprint"] == "fake-08"


def test_09_path_build_detects_certificate_cycle():
    leaf = _cert("leaf-09", "leaf.example.com", "ca-a-09")
    ca_a = _cert(
        "ca-a-09",
        "ca-a.example.com",
        "ca-b-09",
        ca=True,
        path_len=2,
    )
    ca_b = _cert(
        "ca-b-09",
        "ca-b.example.com",
        "ca-a-09",
        ca=True,
        path_len=2,
    )
    root = _cert(
        "root-09",
        "root.example.com",
        "root.example.com",
        ca=True,
        self_signed=True,
    )
    result = build_path(leaf, [ca_a, ca_b], [root])
    assert result["ok"] is False
    assert result["reason"] == "PATH_CYCLE"


def test_10_batch_resets_visited_state_between_requests():
    shared = _cert(
        "shared-10",
        "shared.example.com",
        "root-10",
        ca=True,
        path_len=1,
    )
    root = _cert(
        "root-10",
        "root.example.com",
        "root.example.com",
        ca=True,
        self_signed=True,
    )
    leaf_one = _cert("leaf-10a", "one.example.com", "shared-10")
    leaf_two = _cert("leaf-10b", "two.example.com", "shared-10")
    requests = [
        _request(leaf_one, [shared], [root]),
        _request(leaf_two, [shared], [root]),
    ]
    results = path_batch(requests, {})["results"]
    assert len(results) == 2
    assert [result["ok"] for result in results] == [True, True]
    assert [result["reason"] for result in results] == ["OK", "OK"]
    assert [result["path"][1]["thumbprint"] for result in results] == [
        "shared-10",
        "shared-10",
    ]


def test_11_single_layer_chain_from_anchor_passes():
    leaf = _cert("leaf-11", "leaf.example.com", "root-11")
    root = _cert(
        "root-11",
        "root.example.com",
        "root.example.com",
        ca=True,
        self_signed=True,
    )
    parsed = parse_cert(root)
    assert parsed["ca"] is True
    assert parsed["self_signed"] is True
    assert signature_links([leaf, root]) == []

    result = build_path(leaf, [], [root])
    assert result["ok"] is True
    assert result["reason"] == "OK"
    assert [cert["thumbprint"] for cert in result["path"]] == ["leaf-11", "root-11"]


def test_12_two_layer_chain_with_satisfied_constraints_passes():
    leaf = _cert(
        "leaf-12",
        "api.example.com",
        "ca-12",
        san=["*.example.com"],
    )
    ca = _cert(
        "ca-12",
        "ca.example.com",
        "root-12",
        ca=True,
        path_len=1,
        permitted=[_dns("example.com")],
        excluded=[_dns("secret.example.com")],
    )
    root = _cert(
        "root-12",
        "root.example.com",
        "root.example.com",
        ca=True,
        self_signed=True,
    )
    constraints = {
        "permitted": [_dns("example.com")],
        "excluded": [_dns("secret.example.com")],
    }
    assert (
        names_constrained(
            {"cn": "api.example.com", "san": ["*.example.com"]},
            constraints,
        )
        is True
    )
    result = build_path(leaf, [ca], [root])
    assert result["ok"] is True
    assert result["reason"] == "OK"


def test_13_subject_alt_name_outside_constraint_is_rejected():
    leaf = _cert(
        "leaf-13",
        "api.example.com",
        "ca-13",
        san=["api.example.net"],
    )
    ca = _cert(
        "ca-13",
        "ca.example.com",
        "root-13",
        ca=True,
        path_len=1,
        permitted=[_dns("example.com")],
    )
    root = _cert(
        "root-13",
        "root.example.com",
        "root.example.com",
        ca=True,
        self_signed=True,
    )
    constraints = {"permitted": [_dns("example.com")], "excluded": []}
    assert (
        names_constrained(
            {"cn": "api.example.com", "san": ["api.example.net"]},
            constraints,
        )
        is False
    )
    result = build_path(leaf, [ca], [root])
    assert result["ok"] is False
    assert result["reason"] == "SAN_NOT_PERMITTED"


def test_14_path_length_exceeded_is_rejected():
    leaf = _cert("leaf-14", "leaf.example.com", "lower-14")
    lower = _cert(
        "lower-14",
        "lower.example.com",
        "upper-14",
        ca=True,
        path_len=None,
    )
    upper = _cert(
        "upper-14",
        "upper.example.com",
        "root-14",
        ca=True,
        path_len=0,
    )
    root = _cert(
        "root-14",
        "root.example.com",
        "root.example.com",
        ca=True,
        self_signed=True,
    )
    chain = [leaf, lower, upper, root]
    assert path_length_ok(chain) is False
    result = build_path(leaf, [lower, upper], [root])
    assert result["ok"] is False
    assert result["reason"] == "PATH_LENGTH_EXCEEDED"


def test_15_batch_results_match_independent_builds():
    ca_one = _cert(
        "ca-15a",
        "ca-one.example.com",
        "root-15",
        ca=True,
        path_len=1,
    )
    ca_two = _cert(
        "ca-15b",
        "ca-two.example.com",
        "root-15",
        ca=True,
        path_len=1,
    )
    root = _cert(
        "root-15",
        "root.example.com",
        "root.example.com",
        ca=True,
        self_signed=True,
    )
    leaf_one = _cert("leaf-15a", "one.example.com", "ca-15a")
    leaf_two = _cert("leaf-15b", "two.example.com", "ca-15b")
    request_one = _request(leaf_one, [ca_one], [root])
    request_two = _request(leaf_two, [ca_two], [root])

    batch = path_batch([request_one, request_two], {})["results"]
    solo_one = path_batch([request_one], {})["results"][0]
    solo_two = path_batch([request_two], {})["results"][0]
    assert len(batch) == 2
    assert [result["ok"] for result in batch] == [True, True]
    assert _outcome(batch[0]) == _outcome(solo_one)
    assert _outcome(batch[1]) == _outcome(solo_two)