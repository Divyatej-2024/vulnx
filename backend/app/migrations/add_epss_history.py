"""Idempotent additive migration for EPSS provenance and 90-day history.

Run from backend with DATABASE_URL configured:
    python -m app.migrations.add_epss_history

The migration creates missing intelligence tables and adds missing nullable
columns to an existing threat_intelligence table. It never rewrites CVE data.
"""
from sqlalchemy import inspect, text

from app.db import engine
from app.models import Base, EPSSHistory, ThreatIntelligence


def migrate(bind=engine):
    dialect = bind.dialect.name
    if dialect not in {"postgresql", "sqlite"}:
        raise RuntimeError(f"Unsupported database dialect for this migration: {dialect}")

    # create_all is additive: it creates absent tables but does not mutate an
    # existing table, which is why the missing columns are handled below.
    Base.metadata.create_all(
        bind=bind,
        tables=[ThreatIntelligence.__table__, EPSSHistory.__table__],
    )

    inspector = inspect(bind)
    existing = {column["name"] for column in inspector.get_columns("threat_intelligence")}
    definitions = {
        "epss_score_date": "DATE",
        "epss_model_version": "VARCHAR(40)",
    }

    with bind.begin() as connection:
        for name, sql_type in definitions.items():
            if name not in existing:
                connection.execute(text(
                    f"ALTER TABLE threat_intelligence ADD COLUMN {name} {sql_type}"
                ))

    return {
        "added_columns": sorted(set(definitions) - existing),
        "history_table": "epss_history",
    }


if __name__ == "__main__":
    print(migrate())
