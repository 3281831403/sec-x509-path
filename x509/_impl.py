"""X.509 路径构建与校验的唯一实现文件。

这里恰好保留八个公开函数；所有实现都放在本文件，不新增公开入口。
下划线开头的函数为模块私有辅助，不出现在 __all__ 中。
"""

from __future__ import annotations

from typing import Any

__all__ = [
    "parse_cert",
    "name_in_subtree",
    "names_constrained",
    "path_length_ok",
    "policy_ok",
    "signature_links",
    "build_path",
    "path_batch",
]


# ---------------------------------------------------------------------------
# 私有辅助
# ---------------------------------------------------------------------------


def _normalize_dns(name: Any) -> str:
    """DNS 规范化：小写、去首尾空白、去掉恰好一个末尾点。"""
    text = str(name).strip().lower()
    if text.endswith("."):
        text = text[:-1]
    return text


def _dns_labels(name: Any) -> list[str]:
    return _normalize_dns(name).split(".")


def _subject_cn(subject: dict[str, Any]) -> str:
    return str((subject or {}).get("cn", ""))


def _subject_sans(subject: dict[str, Any]) -> list[str]:
    return list((subject or {}).get("san") or [])


def _outcome(ok: bool, reason: str, path: list[dict[str, Any]]) -> dict[str, Any]:
    return {"ok": ok, "reason": reason, "path": path}


def _constraint_reason(
    subject: dict[str, Any], constraints: dict[str, Any]
) -> str | None:
    """对单个主体做名称约束检查，返回原因码；满足约束时返回 None。

    缺陷 1/2 修复点：CN 与全部 SAN 都检查；排除子树优先于包含子树。
    """
    constraints = constraints or {}
    permitted = list(constraints.get("permitted") or [])
    excluded = list(constraints.get("excluded") or [])

    cn = _subject_cn(subject)
    sans = _subject_sans(subject)
    all_names = [cn, *sans]

    # 否定子树先判定：CN 或任一 SAN 命中 excluded 即拒绝，优先于 permitted。
    for name in all_names:
        for subtree in excluded:
            if name_in_subtree(name, subtree):
                return "EXCLUDED_NAME"

    # permitted 为空表示没有正向限制。
    if permitted:
        if not any(name_in_subtree(cn, subtree) for subtree in permitted):
            return "CN_NOT_PERMITTED"
        for san in sans:
            if not any(name_in_subtree(san, subtree) for subtree in permitted):
                return "SAN_NOT_PERMITTED"

    return None


def _path_length_reason(chain: list[dict[str, Any]]) -> str | None:
    """路径长度检查，返回原因码；合法时返回 None。

    缺陷 4/5 修复点：只统计 chain[1:-1] 的中间证书；相邻中间证书的
    path_len 在叶->锚方向必须严格递增（即锚->叶严格递减）。
    """
    intermediates = chain[1:-1]

    # 每张中间证书允许的下级中间 CA 数量，不得少于它实际下方的中间证书数。
    for position, cert in enumerate(intermediates, start=1):
        limit = cert.get("path_len")
        below = position - 1
        if limit is not None and limit < below:
            return "PATH_LENGTH_EXCEEDED"

    # 相邻中间证书：叶->锚方向 path_len 必须严格递增。None 表示无此约束，不参与比较。
    for index in range(1, len(chain) - 2):
        lower = chain[index].get("path_len")
        upper = chain[index + 1].get("path_len")
        if lower is not None and upper is not None and not lower < upper:
            return "PATH_LENGTH_NOT_DECREASING"

    return None


def _policy_reason(
    chain: list[dict[str, Any]], policy: dict[str, Any]
) -> str | None:
    """策略校验，返回原因码；通过或未启用时返回 None。

    缺陷 6/7 修复点：策略集合按交集传播；inhibit_policy_mapping 生效后
    链上的策略映射一律拒绝。
    """
    initial = (policy or {}).get("initial_policy_set")
    if not initial:
        # 缺失策略或初始策略集合为空：不启用策略检查。
        return None

    # 自锚向叶扫描：一旦出现 inhibit_policy_mapping，其后的映射全部非法。
    inhibited = False
    for cert in reversed(chain):
        if cert.get("inhibit_policy_mapping"):
            inhibited = True
        if inhibited and cert.get("policy_mappings"):
            return "POLICY_MAPPING_INHIBITED"

    # 自锚向叶传播：先与当前证书的策略集合取交集，再通过当前证书的策略映射
    # （issuer_domain -> subject_domain）把集合翻译到下级证书的策略域。
    # 映射翻译出的策略必须在下一张证书的策略集合中交集存活，无法凭空继承。
    current = set(initial)
    for cert in reversed(chain):
        current &= set(cert.get("policies") or [])
        if not current:
            return "POLICY_NOT_SATISFIED"

        mappings = cert.get("policy_mappings") or []
        if mappings:
            forward = {
                item["issuer_domain"]: item["subject_domain"] for item in mappings
            }
            current = {forward.get(value, value) for value in current}

    return None


# ---------------------------------------------------------------------------
# 八个公开函数
# ---------------------------------------------------------------------------


def parse_cert(cert: dict[str, Any]) -> dict[str, Any]:
    """解析 subject、issuer、基本约束、名称约束和扩展项。

    缺失的可选扩展按空值处理，不抛出异常。
    """
    cert = cert or {}
    extensions = cert.get("extensions") or {}
    basic_constraints = extensions.get("basic_constraints") or {}
    name_constraints = extensions.get("name_constraints") or {}

    subject = dict(cert.get("subject") or {})
    subject.setdefault("cn", "")
    subject["san"] = list(subject.get("san") or [])

    issuer = dict(cert.get("issuer") or {})
    issuer.setdefault("cn", "")

    return {
        "thumbprint": cert.get("thumbprint"),
        "subject": subject,
        "issuer": issuer,
        "ca": bool(basic_constraints.get("ca", False)),
        "path_len": basic_constraints.get("path_len"),
        "name_constraints": {
            "permitted": list(name_constraints.get("permitted") or []),
            "excluded": list(name_constraints.get("excluded") or []),
        },
        "policies": list(extensions.get("certificate_policies") or []),
        "policy_mappings": [
            dict(item) for item in (extensions.get("policy_mappings") or [])
        ],
        "inhibit_policy_mapping": bool(
            extensions.get("inhibit_policy_mapping", False)
        ),
        "extensions": extensions,
        "self_signed": bool(cert.get("self_signed", False)),
        "signature_ok": bool(cert.get("signature_ok", True)),
    }


def name_in_subtree(name: str, subtree: dict[str, Any]) -> bool:
    """判断一个 DNS 名称是否落在给定子树内。

    按标签边界比较，不使用子串/简单后缀；通配符子树只匹配恰好一个前导标签。
    """
    if not subtree or subtree.get("type") != "dns":
        return False

    name_labels = _dns_labels(name)
    subtree_labels = _dns_labels(subtree.get("value", ""))

    if subtree_labels[0] == "*":
        # *.example.com 只匹配恰好一个前导标签，如 a.example.com、*.example.com。
        if len(name_labels) != len(subtree_labels):
            return False
        return name_labels[1:] == subtree_labels[1:]

    # 普通子树：完全相等，或多出至少一个前导标签且后缀按标签完全一致。
    if name_labels == subtree_labels:
        return True
    return (
        len(name_labels) > len(subtree_labels)
        and name_labels[-len(subtree_labels):] == subtree_labels
    )


def names_constrained(
    subject: dict[str, Any], issuer_constraints: dict[str, Any]
) -> bool:
    """检查主体 CN 与全部 SAN 是否满足名称约束。"""
    return _constraint_reason(subject, issuer_constraints) is None


def path_length_ok(chain: list[dict[str, Any]]) -> bool:
    """检查中间证书数量以及路径长度是否逐级递减。"""
    chain = [parse_cert(cert) for cert in chain]
    return _path_length_reason(chain) is None


def policy_ok(chain: list[dict[str, Any]], policy: dict[str, Any]) -> bool:
    """按交集传播策略，并拒绝被禁止的策略映射。"""
    chain = [parse_cert(cert) for cert in chain]
    return _policy_reason(chain, policy) is None


def signature_links(chain: list[dict[str, Any]]) -> list[int]:
    """逐级校验签发关系，返回第一个失败下标组成的列表；全部成功返回空列表。

    缺陷 8 修复点：本函数只做签发关系与签名事实校验，不因证书自签而放行；
    自签证书是否能充当锚由 build_path 依据受信锚集合判定。
    测试数据中 child.issuer.cn 可能写的是父证书的 subject CN 或 thumbprint，
    两者任一匹配即视为名称衔接。
    """
    chain = [parse_cert(cert) for cert in chain]
    for index in range(len(chain) - 1):
        child = chain[index]
        parent = chain[index + 1]
        issuer_cn = _subject_cn(child["issuer"])
        parent_names = {_subject_cn(parent["subject"]), parent["thumbprint"]}
        if issuer_cn not in parent_names or not child["signature_ok"]:
            return [index]
    return []


def build_path(
    target: dict[str, Any],
    pool: list[dict[str, Any]],
    anchors: list[dict[str, Any]],
) -> dict[str, Any]:
    """从池中构建到受信锚的路径，去环并返回结果与原因码。"""
    target = parse_cert(target)
    pool = [parse_cert(cert) for cert in (pool or [])]
    anchors = [parse_cert(cert) for cert in (anchors or [])]

    anchor_thumbprints = {cert["thumbprint"] for cert in anchors}

    # 测试数据里 child.issuer.cn 可能写父证书的 subject CN，也可能写其 thumbprint，
    # 因此两类键都建索引，查找时两个入口合并并按 thumbprint 去重。
    pool_index: dict[str, list[dict[str, Any]]] = {}
    for cert in pool:
        pool_index.setdefault(_subject_cn(cert["subject"]), []).append(cert)
        pool_index.setdefault(cert["thumbprint"], []).append(cert)

    anchor_index: dict[str, list[dict[str, Any]]] = {}
    for cert in anchors:
        anchor_index.setdefault(_subject_cn(cert["subject"]), []).append(cert)
        anchor_index.setdefault(cert["thumbprint"], []).append(cert)

    def validate(chain: list[dict[str, Any]]) -> dict[str, Any]:
        # 1. 签名链与签发关系。
        if signature_links(chain):
            return _outcome(False, "SIGNATURE_INVALID", chain)

        # 2. 路径长度（中间证书计数 + 逐级递减）。
        length_reason = _path_length_reason(chain)
        if length_reason is not None:
            return _outcome(False, length_reason, chain)

        # 3. 名称约束向下传播：每张上层证书的约束作用于它下面的所有证书，
        #    包括叶子与全部下级 CA（缺陷 3 修复点）。
        for index, cert in enumerate(chain):
            constraints = cert.get("name_constraints") or {}
            if not constraints.get("permitted") and not constraints.get("excluded"):
                continue
            for lower_index in range(index):
                reason = _constraint_reason(
                    chain[lower_index]["subject"], constraints
                )
                if reason is not None:
                    return _outcome(False, reason, chain)

        return _outcome(True, "OK", chain)

    def search(
        cert: dict[str, Any],
        visited: set[Any],
        chain: list[dict[str, Any]],
    ) -> dict[str, Any]:
        thumbprint = cert["thumbprint"]

        # 缺陷 9 修复点：按 thumbprint 去环，重复证书立即终止该分支。
        if thumbprint in visited:
            return _outcome(False, "PATH_CYCLE", chain)
        visited = visited | {thumbprint}
        chain = chain + [cert]

        # 只有 thumbprint 与受信锚完全相同的证书才能终止路径。
        if thumbprint in anchor_thumbprints:
            return validate(chain)

        # 缺陷 8 修复点：自签证书不在锚集合中时不能冒充锚。
        if cert.get("self_signed"):
            return _outcome(False, "SELF_SIGNED_NOT_ANCHOR", chain)

        issuer_cn = _subject_cn(cert["issuer"])
        candidates: list[dict[str, Any]] = []
        known: set[Any] = set()
        for parent in (
            *pool_index.get(issuer_cn, ()),
            *anchor_index.get(issuer_cn, ()),
        ):
            if parent["thumbprint"] not in known:
                candidates.append(parent)
                known.add(parent["thumbprint"])

        if not candidates:
            return _outcome(False, "NO_TRUSTED_ANCHOR", chain)

        failure: dict[str, Any] | None = None
        for parent in candidates:
            outcome = search(parent, visited, chain)
            if outcome["ok"]:
                return outcome
            failure = outcome
        return failure  # type: ignore[return-value]

    # 每次调用使用全新的 visited 集合，状态绝不跨请求复用（缺陷 10 修复点）。
    return search(target, set(), [])


def path_batch(
    requests: list[dict[str, Any]], policy: dict[str, Any]
) -> dict[str, Any]:
    """批量构路径，每个请求使用独立的搜索状态。"""
    results = []
    for request in requests or []:
        outcome = build_path(
            request["target"],
            request.get("pool", []),
            request.get("anchors", []),
        )

        # 仅在路径有效且显式启用策略检查时叠加策略校验。
        if outcome["ok"] and policy and policy.get("initial_policy_set"):
            reason = _policy_reason(outcome["path"], policy)
            if reason is not None:
                outcome = _outcome(False, reason, outcome["path"])

        results.append(outcome)

    return {"results": results}
