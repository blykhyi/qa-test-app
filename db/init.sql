-- Vulnerability Management Dashboard — Database Schema

CREATE TABLE IF NOT EXISTS assets (
    id SERIAL PRIMARY KEY,
    hostname VARCHAR(255) NOT NULL,
    ip_address VARCHAR(45),
    asset_type VARCHAR(50) NOT NULL,        -- server, container, application
    environment VARCHAR(50) NOT NULL,       -- production, staging, development
    os VARCHAR(100),
    is_active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS vulnerabilities (
    id SERIAL PRIMARY KEY,
    cve_id VARCHAR(20) UNIQUE NOT NULL,
    title VARCHAR(500) NOT NULL,
    description TEXT,
    severity VARCHAR(20) NOT NULL,           -- critical, high, medium, low
    cvss_score DOUBLE PRECISION,             -- BUG #4: no CHECK constraint for 0-10 range
    published_date DATE,
    created_at TIMESTAMP DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS findings (
    id SERIAL PRIMARY KEY,
    asset_id INTEGER NOT NULL REFERENCES assets(id),
    vulnerability_id INTEGER NOT NULL REFERENCES vulnerabilities(id),
    status VARCHAR(50) NOT NULL DEFAULT 'open',  -- open, confirmed, in_progress, resolved, false_positive
    detected_at TIMESTAMP DEFAULT NOW(),
    resolved_at TIMESTAMP,
    scanner VARCHAR(100),
    notes TEXT,
    is_dismissed BOOLEAN DEFAULT FALSE
);

CREATE TABLE IF NOT EXISTS scans (
    id SERIAL PRIMARY KEY,
    asset_id INTEGER NOT NULL REFERENCES assets(id),
    scanner_name VARCHAR(100) NOT NULL,
    status VARCHAR(50) NOT NULL DEFAULT 'running',  -- running, completed, failed
    started_at TIMESTAMP DEFAULT NOW(),
    completed_at TIMESTAMP,
    findings_count INTEGER DEFAULT 0
);

-- ============================================================
-- Seed Data
-- ============================================================

-- Assets
INSERT INTO assets (hostname, ip_address, asset_type, environment, os) VALUES
    ('prod-web-01',     '10.0.1.10',  'server',      'production',  'Ubuntu 22.04 LTS'),
    ('prod-web-02',     '10.0.1.11',  'server',      'production',  'Ubuntu 22.04 LTS'),
    ('staging-api-01',  '10.0.2.20',  'server',      'staging',     'Amazon Linux 2023'),
    ('k8s-payments',    '10.0.3.50',  'container',   'production',  'Alpine 3.18'),
    ('dev-backend-01',  '10.0.4.100', 'server',      'development', 'Ubuntu 20.04 LTS'),
    ('auth-service',    NULL,         'application', 'production',  NULL);

-- Vulnerabilities (realistic CVE-like entries)
INSERT INTO vulnerabilities (cve_id, title, description, severity, cvss_score, published_date) VALUES
    ('CVE-2021-44228', 'Log4Shell - Remote Code Execution in Apache Log4j',
     'Apache Log4j2 allows remote code execution via crafted log messages using JNDI lookups.',
     'critical', 10.0, '2021-12-10'),

    ('CVE-2022-22965', 'Spring4Shell - RCE in Spring Framework',
     'Spring Framework allows remote code execution via data binding to a ClassLoader.',
     'critical', 9.8, '2022-03-31'),

    ('CVE-2023-44487', 'HTTP/2 Rapid Reset Attack',
     'HTTP/2 protocol allows denial of service via rapid stream creation and cancellation.',
     'high', 7.5, '2023-10-10'),

    ('CVE-2023-32681', 'Requests Library SSRF Vulnerability',
     'Python Requests library before 2.31.0 allows SSRF via crafted URLs.',
     'medium', 6.1, '2023-05-26'),

    ('CVE-2024-21626', 'Container Escape via runc Process.cwd',
     'runc before 1.1.12 allows container escape through /proc/self/fd manipulation.',
     'critical', 8.6, '2024-01-31'),

    ('CVE-2023-38545', 'curl SOCKS5 Heap Buffer Overflow',
     'curl before 8.4.0 allows heap-based buffer overflow in SOCKS5 proxy handling.',
     'high', 7.5, '2023-10-11'),

    ('CVE-2024-3094',  'XZ Utils Backdoor',
     'Malicious code in xz/liblzma allows unauthorized access through compromised SSH.',
     'critical', 10.0, '2024-03-29'),

    ('CVE-2023-45853', 'zlib Integer Overflow',
     'MiniZip in zlib through 1.3 has an integer overflow affecting ZIP archive processing.',
     'medium', 5.3, '2023-10-14'),

    ('CVE-2024-0567',  'GnuTLS Certificate Verification Bypass',
     'GnuTLS fails to verify certificate chains with a specific combination of constraints.',
     'high', 7.4, '2024-01-16'),

    ('CVE-2023-48795', 'Terrapin Attack on SSH Protocol',
     'SSH protocol allows prefix truncation attack compromising channel integrity.',
     'medium', 5.9, '2023-12-18');

-- Findings (mix of statuses across assets)
INSERT INTO findings (asset_id, vulnerability_id, status, detected_at, resolved_at, scanner, notes) VALUES
    -- prod-web-01 findings
    (1, 1, 'confirmed',    '2024-11-15 09:30:00', NULL, 'Nessus',      'Log4j detected in application stack'),
    (1, 3, 'in_progress',  '2024-11-15 09:30:00', NULL, 'Nessus',      'Patching scheduled for next maintenance window'),
    (1, 6, 'open',         '2024-12-01 14:00:00', NULL, 'Qualys',      NULL),
    (1, 10, 'resolved',    '2024-11-15 09:30:00', '2024-11-20 16:00:00', 'Nessus', 'SSH config updated'),

    -- prod-web-02 findings
    (2, 1, 'confirmed',    '2024-11-15 09:35:00', NULL, 'Nessus',      'Same Log4j issue as prod-web-01'),
    (2, 3, 'open',         '2024-11-15 09:35:00', NULL, 'Nessus',      NULL),
    (2, 9, 'false_positive', '2024-11-15 09:35:00', NULL, 'Nessus',    'Not applicable - GnuTLS not in use'),

    -- staging-api-01 findings
    (3, 2, 'open',         '2024-12-01 10:00:00', NULL, 'Qualys',      'Spring Framework needs upgrade'),
    (3, 4, 'open',         '2024-12-01 10:00:00', NULL, 'Qualys',      'Requests library outdated'),
    (3, 8, 'resolved',     '2024-12-01 10:00:00', '2024-12-05 11:30:00', 'Qualys', 'zlib updated to 1.3.1'),

    -- k8s-payments container findings
    (4, 5, 'confirmed',    '2024-12-10 08:00:00', NULL, 'Trivy',       'Critical - container runtime vulnerable'),
    (4, 7, 'open',         '2024-12-10 08:00:00', NULL, 'Trivy',       'XZ utils backdoor detected in base image'),

    -- dev-backend-01 findings
    (5, 4, 'open',         '2024-12-15 16:00:00', NULL, 'Snyk',        NULL),
    (5, 8, 'open',         '2024-12-15 16:00:00', NULL, 'Snyk',        NULL),

    -- auth-service findings
    (6, 2, 'in_progress',  '2024-12-20 09:00:00', NULL, 'Snyk',        'Upgrading Spring Boot version'),
    (6, 10, 'open',        '2024-12-20 09:00:00', NULL, 'Snyk',        NULL);

-- Scans
INSERT INTO scans (asset_id, scanner_name, status, started_at, completed_at, findings_count) VALUES
    (1, 'Nessus',  'completed', '2024-11-15 09:30:00', '2024-11-15 09:45:00', 4),
    (4, 'Trivy',   'completed', '2024-12-10 08:00:00', '2024-12-10 08:02:00', 2),
    (5, 'Snyk',    'completed', '2024-12-15 16:00:00', '2024-12-15 16:10:00', 2);
