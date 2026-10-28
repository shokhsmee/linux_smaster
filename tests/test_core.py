from guardian.models import Finding, Severity
from guardian.report import score
from guardian.models import ModuleResult


def f(title="x", sev=Severity.HIGH, module="m", check="c"):
    return Finding(module=module, check=check, severity=sev, title=title)


def test_fingerprint_stable_across_time():
    a, b = f(), f()
    assert a.fingerprint == b.fingerprint
    assert f(title="y").fingerprint != a.fingerprint


def test_store_dedup_and_resolve(ctx):
    store = ctx.store
    new = store.record([f("a"), f("b")])
    assert {x.title for x in new} == {"a", "b"}
    # second run: nothing new
    assert store.record([f("a"), f("b")]) == []
    # 'b' disappears -> resolved; 'c' appears -> new
    new = store.record([f("a"), f("c")])
    assert [x.title for x in new] == ["c"]
    assert {x.title for x in store.open_findings()} == {"a", "c"}
    # 'b' returns after being resolved -> reported as new again
    assert [x.title for x in store.record([f("a"), f("b"), f("c")])] == ["b"]


def test_store_kv_cache_expiry(ctx):
    ctx.store.set("k", {"v": 1})
    assert ctx.store.get("k") == {"v": 1}
    assert ctx.store.get("k", max_age_hours=0) is None


def test_score():
    r = ModuleResult(module="m", findings=[f(sev=Severity.CRITICAL), f("b", Severity.LOW)])
    assert score([r]) == 100 - 25 - 1
    assert score([ModuleResult(module="m", findings=[f(str(i), Severity.CRITICAL) for i in range(10)])]) == 0
