-- Delete processed messages older than 30 days
DELETE FROM inbox
 WHERE processed_at IS NOT NULL
   AND processed_at < NOW() - INTERVAL '30 days';

-- Delete acknowledged messages older than 7 days
DELETE FROM inbox
 WHERE acknowledged_at IS NOT NULL
   AND acknowledged_at < NOW() - INTERVAL '7 days';
