PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS domains (
    domain_id INTEGER PRIMARY KEY,
    hostname TEXT NOT NULL UNIQUE COLLATE NOCASE
);

CREATE TABLE IF NOT EXISTS threat_sources (
    source_id INTEGER PRIMARY KEY,
    name TEXT NOT NULL UNIQUE,
    description TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS reputation_entries (
    domain_id INTEGER PRIMARY KEY REFERENCES domains(domain_id) ON DELETE CASCADE,
    source_id INTEGER NOT NULL REFERENCES threat_sources(source_id),
    confidence INTEGER NOT NULL CHECK (confidence BETWEEN 0 AND 100),
    note TEXT NOT NULL,
    added_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS brands (
    brand_id INTEGER PRIMARY KEY,
    name TEXT NOT NULL UNIQUE
);

CREATE TABLE IF NOT EXISTS brand_domains (
    brand_id INTEGER NOT NULL REFERENCES brands(brand_id) ON DELETE CASCADE,
    domain_id INTEGER NOT NULL REFERENCES domains(domain_id) ON DELETE CASCADE,
    PRIMARY KEY (brand_id, domain_id)
);

INSERT OR IGNORE INTO threat_sources (name, description)
VALUES ('local-demo', 'Reserved .test examples for demonstrating the interface; not a live threat feed.');

INSERT OR IGNORE INTO domains (hostname) VALUES
    ('paypa1-secure.test'),
    ('account-verify.test'),
    ('parcel-track.test');

INSERT OR IGNORE INTO reputation_entries (domain_id, source_id, confidence, note)
SELECT domains.domain_id, threat_sources.source_id, 100, 'Demonstration entry only; .test is reserved for testing.'
FROM domains CROSS JOIN threat_sources
WHERE threat_sources.name = 'local-demo'
  AND domains.hostname IN ('paypa1-secure.test', 'account-verify.test', 'parcel-track.test');

INSERT OR IGNORE INTO brands (name) VALUES
    ('paypal'), ('google'), ('amazon'), ('microsoft'), ('apple'), ('chase'), ('fedex'), ('dhl');

INSERT OR IGNORE INTO domains (hostname) VALUES
    ('paypal.com'), ('google.com'), ('google.co.uk'), ('amazon.com'),
    ('amazon.co.uk'), ('microsoft.com'), ('apple.com'), ('chase.com'),
    ('fedex.com'), ('dhl.com');

INSERT OR IGNORE INTO brand_domains (brand_id, domain_id)
SELECT brands.brand_id, domains.domain_id
FROM brands JOIN domains ON
    (brands.name = 'paypal' AND domains.hostname = 'paypal.com') OR
    (brands.name = 'google' AND domains.hostname IN ('google.com', 'google.co.uk')) OR
    (brands.name = 'amazon' AND domains.hostname IN ('amazon.com', 'amazon.co.uk')) OR
    (brands.name = 'microsoft' AND domains.hostname = 'microsoft.com') OR
    (brands.name = 'apple' AND domains.hostname = 'apple.com') OR
    (brands.name = 'chase' AND domains.hostname = 'chase.com') OR
    (brands.name = 'fedex' AND domains.hostname = 'fedex.com') OR
    (brands.name = 'dhl' AND domains.hostname = 'dhl.com');
