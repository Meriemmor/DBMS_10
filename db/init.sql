CREATE TABLE team (
    id SERIAL PRIMARY KEY,
    name VARCHAR(100) NOT NULL,
    contact_email VARCHAR(255) NOT NULL
);

CREATE TABLE asset (
    id SERIAL PRIMARY KEY,
    name VARCHAR(100) NOT NULL,
    type VARCHAR(50) NOT NULL,
    team_id INTEGER NOT NULL REFERENCES team(id)
);

CREATE TABLE vulnerability (
    id SERIAL PRIMARY KEY,
    cve_id VARCHAR(50) NOT NULL UNIQUE,
    severity VARCHAR(20) NOT NULL
        CHECK (severity IN ('Critical', 'High', 'Medium', 'Low')),
    description TEXT
);

CREATE TABLE finding (
    id SERIAL PRIMARY KEY,
    asset_id INTEGER NOT NULL REFERENCES asset(id),
    vulnerability_id INTEGER NOT NULL REFERENCES vulnerability(id),
    status VARCHAR(20) NOT NULL
        CHECK (status IN ('Open', 'In Progress', 'Resolved')),
    discovered_on DATE NOT NULL,
    due_date DATE NOT NULL,
    resolved_on DATE,

    CHECK (due_date >= discovered_on),

    CHECK (
        (status = 'Resolved' AND resolved_on IS NOT NULL)
        OR
        (status <> 'Resolved' AND resolved_on IS NULL)
    ),

    UNIQUE (asset_id, vulnerability_id)
);

INSERT INTO team (name, contact_email)
VALUES ('Platform', 'platform@example.com');

INSERT INTO asset (name, type, team_id)
VALUES ('web-01', 'Server', 1);

INSERT INTO vulnerability (cve_id, severity, description)
VALUES
    ('CVE-2026-1234', 'Critical', 'Example critical vulnerability'),
    ('CVE-2026-5678', 'High', 'Example high severity vulnerability');

INSERT INTO finding (
    asset_id,
    vulnerability_id,
    status,
    discovered_on,
    due_date
)
VALUES (
    1,
    1,
    'Open',
    '2026-07-16',
    '2026-07-30'
);
