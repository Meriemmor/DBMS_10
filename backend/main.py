from datetime import date
from typing import Literal

from fastapi import FastAPI, Header, HTTPException
from pydantic import BaseModel
from psycopg.errors import ForeignKeyViolation, UniqueViolation, CheckViolation

from database import get_connection

app = FastAPI(title="Vulnerability Tracker API")

API_KEY = "my_secret_api_key"


class FindingCreate(BaseModel):
    asset_id: int
    vulnerability_id: int
    status: Literal["Open", "In Progress", "Resolved"]
    discovered_on: date
    due_date: date
    resolved_on: date | None = None


class FindingUpdate(BaseModel):
    status: Literal["Open", "In Progress", "Resolved"] | None = None
    due_date: date | None = None
    resolved_on: date | None = None


def verify_api_key(x_api_key: str | None):
    if x_api_key != API_KEY:
        raise HTTPException(
            status_code=401,
            detail="Invalid or missing API key"
        )


@app.get("/")
def root():
    return {"message": "Vulnerability Tracker API is running"}


@app.get("/db-test")
def db_test():
    with get_connection() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT COUNT(*) FROM finding;")
            count = cur.fetchone()[0]

    return {"findings": count}


@app.get("/findings")
def get_findings(
    status: str | None = None,
    severity: str | None = None
):
    with get_connection() as conn:
        with conn.cursor() as cur:
            query = """
                SELECT
                    f.id,
                    a.name,
                    t.name,
                    v.cve_id,
                    v.severity,
                    f.status,
                    f.discovered_on,
                    f.due_date,
                    f.resolved_on
                FROM finding f
                JOIN asset a ON f.asset_id = a.id
                JOIN team t ON a.team_id = t.id
                JOIN vulnerability v ON f.vulnerability_id = v.id
            """

            conditions = []
            params = []

            if status:
                conditions.append("f.status = %s")
                params.append(status)

            if severity:
                conditions.append("v.severity = %s")
                params.append(severity)

            if conditions:
                query += " WHERE " + " AND ".join(conditions)

            query += " ORDER BY f.id;"

            cur.execute(query, params)
            rows = cur.fetchall()

    return {
        "findings": [
            {
                "id": row[0],
                "asset": row[1],
                "team": row[2],
                "cve_id": row[3],
                "severity": row[4],
                "status": row[5],
                "discovered_on": row[6],
                "due_date": row[7],
                "resolved_on": row[8]
            }
            for row in rows
        ]
    }


@app.get("/summary")
def get_summary():
    with get_connection() as conn:
        with conn.cursor() as cur:
            cur.execute("""
                SELECT
                    v.severity,
                    COUNT(*)
                FROM finding f
                JOIN vulnerability v
                    ON f.vulnerability_id = v.id
                WHERE f.status <> 'Resolved'
                GROUP BY v.severity;
            """)

            rows = cur.fetchall()

    summary = {
        "Critical": 0,
        "High": 0,
        "Medium": 0,
        "Low": 0
    }

    for row in rows:
        summary[row[0]] = row[1]

    return {"summary": summary}


@app.get("/findings/{finding_id}")
def get_finding(finding_id: int):
    with get_connection() as conn:
        with conn.cursor() as cur:
            cur.execute("""
                SELECT
                    f.id,
                    a.name,
                    t.name,
                    v.cve_id,
                    v.severity,
                    f.status,
                    f.discovered_on,
                    f.due_date,
                    f.resolved_on
                FROM finding f
                JOIN asset a ON f.asset_id = a.id
                JOIN team t ON a.team_id = t.id
                JOIN vulnerability v ON f.vulnerability_id = v.id
                WHERE f.id = %s;
            """, (finding_id,))

            row = cur.fetchone()

    if row is None:
        raise HTTPException(
            status_code=404,
            detail="Finding not found"
        )

    return {
        "id": row[0],
        "asset": row[1],
        "team": row[2],
        "cve_id": row[3],
        "severity": row[4],
        "status": row[5],
        "discovered_on": row[6],
        "due_date": row[7],
        "resolved_on": row[8]
    }


@app.post("/findings", status_code=201)
def create_finding(
    finding: FindingCreate,
    x_api_key: str | None = Header(
        default=None,
        alias="X-API-Key"
    )
):
    verify_api_key(x_api_key)

    try:
        with get_connection() as conn:
            with conn.cursor() as cur:
                cur.execute("""
                    INSERT INTO finding (
                        asset_id,
                        vulnerability_id,
                        status,
                        discovered_on,
                        due_date,
                        resolved_on
                    )
                    VALUES (%s, %s, %s, %s, %s, %s)
                    RETURNING id;
                """, (
                    finding.asset_id,
                    finding.vulnerability_id,
                    finding.status,
                    finding.discovered_on,
                    finding.due_date,
                    finding.resolved_on
                ))

                new_id = cur.fetchone()[0]

    except UniqueViolation:
        raise HTTPException(
            status_code=409,
            detail="This vulnerability already exists for this asset"
        )

    except ForeignKeyViolation:
        raise HTTPException(
            status_code=400,
            detail="Asset or vulnerability does not exist"
        )

    except CheckViolation:
        raise HTTPException(
            status_code=400,
            detail="Finding violates database rules"
        )

    return {
        "message": "Finding created",
        "id": new_id
    }


@app.patch("/findings/{finding_id}")
def update_finding(
    finding_id: int,
    update: FindingUpdate,
    x_api_key: str | None = Header(
        default=None,
        alias="X-API-Key"
    )
):
    verify_api_key(x_api_key)

    updates = update.model_dump(exclude_unset=True)

    if not updates:
        raise HTTPException(
            status_code=400,
            detail="No fields provided"
        )

    with get_connection() as conn:
        with conn.cursor() as cur:
            cur.execute("""
                SELECT
                    status,
                    discovered_on,
                    due_date,
                    resolved_on
                FROM finding
                WHERE id = %s;
            """, (finding_id,))

            row = cur.fetchone()

            if row is None:
                raise HTTPException(
                    status_code=404,
                    detail="Finding not found"
                )

            current_status = row[0]
            discovered_on = row[1]
            current_due_date = row[2]
            current_resolved_on = row[3]

            new_status = updates.get(
                "status",
                current_status
            )

            new_due_date = updates.get(
                "due_date",
                current_due_date
            )

            if "resolved_on" in updates:
                new_resolved_on = updates["resolved_on"]
            else:
                new_resolved_on = current_resolved_on

            if new_due_date < discovered_on:
                raise HTTPException(
                    status_code=400,
                    detail="Due date cannot be before discovered date"
                )

            if new_status == "Resolved" and new_resolved_on is None:
                raise HTTPException(
                    status_code=400,
                    detail="Resolved findings require a resolved_on date"
                )

            if new_status != "Resolved" and new_resolved_on is not None:
                raise HTTPException(
                    status_code=400,
                    detail="resolved_on must be empty unless status is Resolved"
                )

            cur.execute("""
                UPDATE finding
                SET
                    status = %s,
                    due_date = %s,
                    resolved_on = %s
                WHERE id = %s;
            """, (
                new_status,
                new_due_date,
                new_resolved_on,
                finding_id
            ))

    return {
        "message": "Finding updated",
        "id": finding_id
    }


@app.get("/assets")
def get_assets():
    with get_connection() as conn:
        with conn.cursor() as cur:
            cur.execute("""
                SELECT
                    a.id,
                    a.name,
                    a.type,
                    t.name
                FROM asset a
                JOIN team t ON a.team_id = t.id
                ORDER BY a.id;
            """)

            rows = cur.fetchall()

    return {
        "assets": [
            {
                "id": row[0],
                "name": row[1],
                "type": row[2],
                "team": row[3]
            }
            for row in rows
        ]
    }


@app.get("/teams")
def get_teams():
    with get_connection() as conn:
        with conn.cursor() as cur:
            cur.execute("""
                SELECT
                    id,
                    name,
                    contact_email
                FROM team
                ORDER BY id;
            """)

            rows = cur.fetchall()

    return {
        "teams": [
            {
                "id": row[0],
                "name": row[1],
                "contact_email": row[2]
            }
            for row in rows
        ]
    }
