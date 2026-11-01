from sqlalchemy import create_engine, inspect, text

from app.migrations.add_epss_history import migrate


def test_migration_adds_missing_columns_preserves_rows_and_is_repeatable():
    engine = create_engine("sqlite://")
    with engine.begin() as connection:
        connection.execute(text(
            "CREATE TABLE threat_intelligence (cve_id VARCHAR PRIMARY KEY, epss_probability FLOAT)"
        ))
        connection.execute(text(
            "INSERT INTO threat_intelligence (cve_id, epss_probability) VALUES ('CVE-2025-1234', 0.5)"
        ))

    first = migrate(engine)
    columns = {item["name"] for item in inspect(engine).get_columns("threat_intelligence")}
    assert {"epss_score_date", "epss_model_version"}.issubset(columns)
    assert first["added_columns"] == ["epss_model_version", "epss_score_date"]
    assert {"threat_intelligence", "epss_history"}.issubset(set(inspect(engine).get_table_names()))

    with engine.connect() as connection:
        assert connection.execute(text(
            "SELECT cve_id, epss_probability FROM threat_intelligence"
        )).one() == ("CVE-2025-1234", 0.5)

    second = migrate(engine)
    assert second["added_columns"] == []
    engine.dispose()


def test_migration_creates_missing_intelligence_tables():
    engine = create_engine("sqlite://")
    result = migrate(engine)
    inspector = inspect(engine)
    assert {"threat_intelligence", "epss_history"}.issubset(set(inspector.get_table_names()))
    columns = {item["name"] for item in inspector.get_columns("threat_intelligence")}
    assert {"epss_score_date", "epss_model_version"}.issubset(columns)
    assert result["added_columns"] == []
    engine.dispose()
