"""Explicit additive migration for EPSS provenance and 90-day history.

Run from backend with DATABASE_URL configured:
    python -m app.migrations.add_epss_history

This migration does not run automatically at API startup. It adds nullable
columns and creates a separate history table; it does not rewrite NVD data.
"""
from sqlalchemy import inspect, text

from app.db import engine
from app.models import Base


def migrate(bind=engine):
    inspector = inspect(bind)
    if "threat_intelligence" not in inspector.get_table_names():
        raise RuntimeError("threat_intelligence table is missing; initialise the existing schema first")

    existing = {column["name"] for column in inspector.get_columns("threat_intelligence")}
    dialect = bind.dialect.name
    if dialect == "postgresql":
        definitions = {
            "epss_score_date": "DATE",
            "epss_model_version": "VARCHAR(40)",
        }
    elif dialect == "sqlite":
        definitions = {
            "epss_score_date": "DATE",
            "epss_model_version": "VARCHAR(40)",
        }
    else:
        raise RuntimeError(f"Unsupported database dialect for this migration: {dialect}")

    with bind.begin() as connection:
        for name, sql_type in definitions.items():
            if name not in existing:
                connection.execute(text(
                    f"ALTER TABLE threat_intelligence ADD COLUMN {name} {sql_type}"
                ))

    Base.metadata.create_all(bind=bind, tables=[Base.metadata.tables["epss_history"]])
    return {"added_columns": sorted(set(definitions) - existing), "history_table": "epss_history"}


if __name__ == "__main__":
    print(migrate())
