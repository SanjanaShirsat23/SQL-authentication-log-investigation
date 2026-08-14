-- ============================================================
-- SQL Authentication Log Investigation
-- ============================================================
-- Purpose:
-- Analyze authentication logs to identify suspicious
-- login activity and potential credential-based attacks.
--
-- Dataset:
-- login_events.csv
--
-- ============================================================


-- ------------------------------------------------------------
-- Investigation 1: Count failed login attempts
-- ------------------------------------------------------------
-- Determine the total number of failed authentication attempts.

SELECT COUNT(*) AS failed_attempts
FROM login_events
WHERE status = 'failed';


-- ------------------------------------------------------------
-- Investigation 2: Identify users with repeated failures
-- ------------------------------------------------------------
-- Find users who experienced three or more failed
-- authentication attempts.

SELECT username, COUNT(*) AS failed_attempts
FROM login_events
WHERE status = 'failed'
GROUP BY username
HAVING COUNT(*) >= 3;


-- ------------------------------------------------------------
-- Investigation 3: Identify suspicious IP addresses
-- ------------------------------------------------------------
-- Find IP addresses associated with three or more
-- failed authentication attempts.

SELECT ip_address, COUNT(*) AS failed_attempts
FROM login_events
WHERE status = 'failed'
GROUP BY ip_address
HAVING COUNT(*) >= 3;


-- ------------------------------------------------------------
-- Investigation 4: Investigate successful login after
-- repeated failures
-- ------------------------------------------------------------
-- Examine activity from an IP address that generated
-- multiple failed attempts followed by a successful login.

SELECT *
FROM login_events
WHERE ip_address = '185.22.44.10'
ORDER BY timestamp;


-- ------------------------------------------------------------
-- Investigation 5: Review all failed authentication events
-- ------------------------------------------------------------
-- Display failed authentication events for further analysis.

SELECT timestamp, username, ip_address, location
FROM login_events
WHERE status = 'failed'
ORDER BY timestamp;
