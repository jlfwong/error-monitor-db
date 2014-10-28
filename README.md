error-monitor-db
================

Error database for automatically categorizing and collecting errors from the 
Khan Academy webapp logs.

Data collection for errors comes from two sources: logs via the hourly logs 
tables in BigQuery, and logs send directly from the live running webapp during 
the monitoring phase.

Log parsing form the tables is done on a cron hourly, and logs roll in direct 
from webapp only during monitoring of deploys.
