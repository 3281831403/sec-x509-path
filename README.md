内部证书体系上线后，一张带名称约束的中间证书签出的叶子证书能直接访问全部域名：名称约束只检查主体通用名，不检查主体备用名称；排除子树在包含判定之后才检查，导致本应排除的名称被放行；名称约束不向下传播，中间证书的约束在叶子层被丢弃；路径长度按证书总数计算而不是中间证书数，合法链被拒；路径长度不递减，同一中间证书可重复使用放大深度；策略集合用并集传播，未声明的策略被意外继承；禁止映射标志被忽略，策略映射可绕过限制；签名链校验遇到自签证书直接放行，自签可冒充锚；构路径时不去环，互相签发的两张证书导致无限展开；批量构路径复用已访问集合，第二个目标用到第一个目标的路径状态。x509/_impl.py 是核心，tests/test_path.py 15个红。要修的是：按上面的顺序把 10 个缺陷逐个修掉。

## 运行方式

在仓库根目录执行：

```text
python -m pytest tests -q
```

初始状态预期为 15 failed，15 个异常全部是 NotImplementedError；修复完成后应为 15 passed。测试不联网，不读取仓库外文件。

## 字段表

| 字段 | 值 |
| --- | --- |
| 安全域 | 安全 |
| 任务方向 | 漏洞检测与攻防 |
| 任务类型 | Bugfix |
| 运行时 | Python 3 |
| 测试框架 | pytest |
| 外部依赖 | 无外部依赖 |

## 仓库约束

tests/test_path.py 是验收测试，不可修改，也不可增加 skip、xfail、夹具或替换断言。实现只写在 x509/_impl.py，且该文件恰好保留 8 个公开桩；x509/api.py 只从 x509._impl 再导出，x509/__init__.py 只从 x509.api 再导出。不要把实现散落到其他模块，不要引入第三方包，不要联网。

## 门面布局

```text
sec-x509-path/
  README.md
  conftest.py
  x509/
    __init__.py
    _impl.py
    api.py
  tests/
    test_path.py
```

x509/_impl.py 是唯一实现文件。x509/api.py 和 x509/__init__.py 只是门面，修改它们不会改变测试结果。tests/test_path.py 恰好包含 15 个测试；初始 15 个红必须全部来自 NotImplementedError，不能是断言失败、收集错误或导入错误。

## 证书映射

测试中的证书是普通 dict，字段如下：

```python
cert = {
    "thumbprint": "leaf-01",
    "subject": {"cn": "leaf.example.com", "san": ["leaf.example.com"]},
    "issuer": {"cn": "ca-01"},
    "extensions": {
        "basic_constraints": {"ca": False, "path_len": None},
        "name_constraints": {
            "permitted": [{"type": "dns", "value": "example.com"}],
            "excluded": [{"type": "dns", "value": "secret.example.com"}],
        },
        "certificate_policies": ["2.23.140.1.2.1"],
        "policy_mappings": [
            {"issuer_domain": "2.23.140.1.2.1", "subject_domain": "1.3.6.1.4.1.99.1"}
        ],
        "inhibit_policy_mapping": False,
    },
    "self_signed": False,
    "signature_ok": True,
}
```

parse_cert 必须解析出 subject、issuer、basic_constraints、name_constraints 和全部 extensions，至少包含这些键：thumbprint、subject、issuer、ca、path_len、name_constraints、policies、policy_mappings、inhibit_policy_mapping、extensions、self_signed、signature_ok。缺失的可选扩展按空值处理，不能抛出异常。

链的顺序固定为叶子到锚：chain[0] 是叶子或目标，chain[-1] 是锚。path_length_ok 只统计 chain[1:-1] 中的中间证书，叶子和锚都不计入；同一中间证书不能在有效路径中重复出现。

## DNS 子树规则

名称匹配必须先做 DNS 规范化：大小写不敏感，去掉末尾一个点，按标签边界比较，不能使用简单子串或简单后缀比较。普通子树 example.com 匹配 example.com 和任意 label.example.com，但不匹配 badexample.com。带通配符的子树例如 *.example.com 只匹配恰好一个前导标签，即 a.example.com 和 *.example.com，不匹配 example.com 或 a.b.example.com。

names_constrained 先看所有否定子树，只要主体 CN 或任一 SAN 命中 excluded 就返回 False；然后用 permitted 做正向检查。permitted 为空表示没有正向限制。name_in_subtree 只回答单个名称与单个子树的匹配，不处理 excluded。

## 原因码

build_path 和 path_batch 的每个结果都包含 ok、path、reason。成功时 reason 为 OK。失败原因码固定如下：

| 原因码 | 含义 |
| --- | --- |
| OK | 路径有效 |
| CN_NOT_PERMITTED | 主体通用名不满足名称约束 |
| SAN_NOT_PERMITTED | 主体备用名称不满足名称约束 |
| EXCLUDED_NAME | 名称命中排除子树，优先于包含判定 |
| PATH_LENGTH_EXCEEDED | 中间证书数量超过路径长度约束 |
| PATH_LENGTH_NOT_DECREASING | 相邻中间证书的路径长度没有严格递减 |
| POLICY_NOT_SATISFIED | 策略交集为空或不满足初始策略 |
| POLICY_MAPPING_INHIBITED | 链上存在被禁止的策略映射 |
| SELF_SIGNED_NOT_ANCHOR | 路径终止于不在受信锚集合中的自签证书 |
| PATH_CYCLE | 构路径时检测到重复证书 |
| NO_TRUSTED_ANCHOR | 候选路径无法终止于受信锚 |
| SIGNATURE_INVALID | 相邻证书的签发关系或签名校验失败 |

## 八个公开函数

parse_cert 把原始证书规范化为上述字段。name_in_subtree 判断单个 DNS 名称是否落在单个子树内。names_constrained 同时检查 CN 与全部 SAN。path_length_ok 检查中间证书数量和逐级递减。policy_ok 从初始策略集合出发，沿链向下与每张证书的策略集合取交集；策略映射只允许在未被 inhibit_policy_mapping 禁止时替换策略，最终集合为空则失败。signature_links 按叶子到锚的顺序逐段检查 child.issuer 是否等于 parent.subject 且 child.signature_ok 为真，成功返回空列表，失败返回只含第一个失败下标的列表。

build_path 从 target 出发在 pool 中找签发者，必须终止于 anchors 中 thumbprint 完全相同的证书。搜索必须去环，自签证书只有出现在 anchors 中才算锚。到达锚后再校验签名链、路径长度和整条链上所有上层名称约束；上层约束必须向下传播到叶子和所有下级 CA。path_batch 对 requests 中的每个请求独立调用同样的构建与校验逻辑，每个请求形如 target、pool、anchors，返回 results 列表；policy 缺失或 initial_policy_set 为空时不启用策略检查。某个请求的已访问集合不得泄漏到下一个请求。

## 字段表

| 字段 | 取值 |
| --- | --- |
| 所属领域 | 安全 |
| 子方向 | 漏洞检测与攻防 |
| 任务类型 | Bugfix |
| 语言/框架 | Python 3, pytest |
| 环境可复现等级 | 无外部依赖 |

