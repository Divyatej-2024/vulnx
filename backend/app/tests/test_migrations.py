from sqlalchemy import create_engine, inspect, text

from app.migrations.add_epss_history import migrate


def test_migration_adds_only_missing_columns_and_is_repeatable():
    engine = create_engine("sqlite://")
    with engine.begin() as connection:
        connection.execute(text(
            "CREATE TABLE threat_intelligence (cve_id VARCHAR PRIMARY KEY, epss_probability FLOAT)"
        ))

    first = migrate(engine)
    columns = {item["name"] for item in inspect(engine).get_columns("threat_intelligence")}
    assert {"epss_score_date", "epss_model_version"}.issubset(columns)
    assert first["added_columns"] == ["epss_model_version", "epss_score_date"]
    assert "epss_history" in inspect(engine).get_table_names()

    second = migrate(engine)
    assert second["added_columns"] == []
    engine.dispose()
