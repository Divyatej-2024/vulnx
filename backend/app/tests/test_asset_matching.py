from app.assets.matching import matches_asset_cpe


ASSET = "cpe:2.3:a:acme:widget:2.4.1:*:*:*:*:*:*:*"


def _record(criteria, **extra):
    return {"cve": {"configurations": [{"nodes": [{
        "cpeMatch": [{"vulnerable": True, "criteria": criteria, **extra}]
    }]}]}}


def test_matches_exact_vendor_product_and_version():
    assert matches_asset_cpe(
        _record("cpe:2.3:a:acme:widget:2.4.1:*:*:*:*:*:*:*"), ASSET
    )


def test_matches_wildcard_version_as_candidate():
    assert matches_asset_cpe(
        _record("cpe:2.3:a:acme:widget:*:*:*:*:*:*:*:*"), ASSET
    )


def test_rejects_different_product_or_vendor():
    assert not matches_asset_cpe(
        _record("cpe:2.3:a:other:widget:2.4.1:*:*:*:*:*:*:*"), ASSET
    )
    assert not matches_asset_cpe(
        _record("cpe:2.3:a:acme:other:2.4.1:*:*:*:*:*:*:*"), ASSET
    )


def test_supports_numeric_inclusive_version_range():
    assert matches_asset_cpe(
        _record("cpe:2.3:a:acme:widget:*:*:*:*:*:*:*:*",
                versionStartIncluding="2.0", versionEndIncluding="2.5"),
        ASSET,
    )


def test_excludes_version_outside_range():
    assert not matches_asset_cpe(
        _record("cpe:2.3:a:acme:widget:*:*:*:*:*:*:*:*",
                versionStartIncluding="2.5"),
        ASSET,
    )


def test_ignores_non_vulnerable_or_malformed_criteria():
    assert not matches_asset_cpe(
        _record("cpe:2.3:a:acme:widget:2.4.1:*:*:*:*:*:*:*",
                vulnerable=False), ASSET
    )
    assert not matches_asset_cpe({"cve": {"configurations": []}}, "not-a-cpe")
