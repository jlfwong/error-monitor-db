import datetime
from flask import Flask
from flask import request
import json
import numpy
import os
import redis
import scipy.stats
import sys

import error_parser

app = Flask("Khan Academy Error Monitor")
r = redis.StrictRedis(host='localhost', port=6379, db=0)

# We need to load python-phabricator.  On the error-monitor-db
# install, it lives in a particular place we know about.  We take
# advantage of the knowledge that this file lives in the root-dir
# of error-monitor-db.
_INTERNAL_WEBSERVER_ROOT = os.path.abspath(os.path.dirname(__file__))
sys.path.append(os.path.join(_INTERNAL_WEBSERVER_ROOT, 'python-phabricator'))
import phabricator


def _count_is_elevated_probability(historical_counts, recent_count):
    """Give the probability recent_count is elevated over the norm.

    We are given a collection of recent counts, each over a 1-minute time
    frame, and must decide how likely the new count is to be within a normal
    distribution represented by the historical counts.

    Arguments:
       historical_count: a list of the number of errors seen in each time
           window in 'the past'.
       recent_count: the number of errors seen in 'the present'.

    Returns:
       A pair: the expected number of errors we would have seen this period,
          and the probability that the number of errors we actually saw
          is actually higher than the expected number, both as floats.
    """
    if not historical_counts:
        # We don't have any history, so we can't make any guesses
        return (0, 0)

    if len(historical_counts) == 1:
        # We only have one data point, so do a simple threshold check
        return (historical_counts[0],
                1 if recent_count > historical_counts[0] else 0)

    counts = numpy.array(historical_counts)
    mean = numpy.mean(counts)

    if recent_count < mean:
        # If the error count went down, we don't care about the probability
        return (mean, 0)

    stdev = numpy.std(counts)

    if stdev < 1:
        # Avoid a division by zero error
        return (mean, 1 if recent_count > mean else 0)

    pvalue = (recent_count - mean) / stdev
    zscore = scipy.stats.norm.cdf(pvalue)

    return (mean, zscore)


@app.route("/errors")
@app.route("/errors/<version>")
def errors(version=None):
    errors = []

    # Get error data from Phabricator
    phabricator_domain = 'http://phabricator.khanacademy.org'
    phabctl = phabricator.Phabricator(host=phabricator_domain + '/api/')
    tasks = phabctl.maniphest.maniphest.query(
            projectPHIDs=["PHID-PROJ-wac5cp5twq6xcgubphie"])
    error_status_by_key = {}
    for task_id in tasks.keys():
        task = tasks[task_id]
        task_key = task["auxiliary"]["std:maniphest:khan:errorkey"]
        error_status_by_key[task_key] = (task["objectName"], task["status"])
    
    # Create buckets for each hour in last 24 hours
    start = datetime.datetime.now() - datetime.timedelta(1, 0, 0, 0, 0, 0)
    day_buckets = [
        [(start + datetime.timedelta(0, 0, 0, 0, 0, h)).strftime("%Y%m%d_%H")]
         for h in xrange(0, 24)]

    # Create 4 buckets a day (6 hours each) for 7 days
    start = datetime.datetime.now() - datetime.timedelta(7, 0, 0, 0, 0, 1)
    week_buckets = [
        [(start +
            datetime.timedelta(0, 0, 0, 0, 0, h1+h2)).strftime("%Y%m%d_%H")
         for h2 in xrange(0, 6)]
         for h1 in xrange(0, 7*24, 6)]

    for key in r.smembers("errors"):
        err_def = error_parser.RedisErrorDef.get_by_key(key)
        task_info = error_status_by_key.get(key, ("", "No task created"))
        if version and err_def.get("monitor_count:%s" % version):
            errors.append({
                "key": err_def.key,
                "monitoring": version,
                "count": int(err_def.get("monitor_count:%s" % version)),
                "status": int(err_def.get("status")),
                "level": error_parser.LEVELS[int(err_def.get("level"))],
                "stack": json.loads(err_def.get("stack")),
                "message": err_def.get("message:title"),
                "ips": list(err_def.members("monitor_ips")),
                "uris": {uri: 0 for uri in err_def.members("monitor_uris")},
                "versions": {version: 0},
                "newInVersion": len(err_def.get_versions()) == 0,
                "dayTimeSeries": [],
                "weekTimeSeries": [],
                "taskId": task_info[0],
                "taskStatus": task_info[1],
            })

        if int(err_def.get("count")) and (
                not version or version in err_def.get_versions()):
            errors.append({
                "key": err_def.key,
                "count": int(err_def.get("count")),
                "status": int(err_def.get("status")),
                "level": error_parser.LEVELS[int(err_def.get("level"))],
                "firstSeen": err_def.get("first_seen"),
                "lastSeen": err_def.get("last_seen"),
                "stack": json.loads(err_def.get("stack")),
                "message": err_def.get("message:title"),
                "ips": list(err_def.members("ips")),
                "uris": err_def.get_uris(),
                "versions": err_def.get_versions(),
                "newInVersion": version == err_def.get_earliest_version(),
                "dayTimeSeries": err_def.get_time_series(day_buckets, version),
                "weekTimeSeries": err_def.get_time_series(
                    week_buckets, version),
                "taskId": task_info[0],
                "taskStatus": task_info[1],
            })

    return json.dumps({
        "errors": errors,
        "dayTimeCategories": [b[0] for b in day_buckets],
        "weekTimeCategories": [b[0] for b in week_buckets],
        "lastHour": error_parser.latest_hour()
    })


@app.route("/monitor", methods=["post"])
def monitor():
    # Fetch all previous errors that were not encountered during previous
    # monitoring
    params = request.get_json()
    error_logs = params['logs']
    log_hour = params['log_hour']
    minute = params['minute']
    version = params['version']
    verify_versions = params['verify_versions']

    for log in error_logs:
        if any(log['resource'].startswith(uri)
               for uri in error_parser.URI_BLACKLIST):
            continue

        message_def = error_parser.MessageDef(log['message'])
        status = str(log['status'])
        level = str(log['level'])
        err_def = error_parser.RedisErrorDef.get_or_create_def(
                log_hour, message_def, status, level)
        err_def.add_monitoring_instance(
                version, minute, log['ip'], log['resource'])

    if not verify_versions:
        return json.dumps({"status": "ok", "version": version})

    significant_errors = []
    for key in r.smembers("errors"):
        err_def = error_parser.RedisErrorDef.get_by_key(key)
        monitor_count = int(
            err_def.get("monitor_count:%s:%s" % (version, minute)) or 0)
        if monitor_count == 0:
            continue

        print "MONITORING ERROR IN %s: %s" % (
                version, err_def.get("message:title"))
        version_counts = [
            int(err_def.get("monitor_count:%s:%s" % (verify_version, minute))
            or 0) for verify_version in verify_versions]

        (expected_count, probability) = _count_is_elevated_probability(
                version_counts, monitor_count)

        if probability >= 0.9995:
            significant_errors.append({
                "key": err_def.key,
                "status": int(err_def.get("status")),
                "level": error_parser.LEVELS[int(err_def.get("level"))],
                "stack": err_def.get("stack"),
                "message": err_def.get("message:title"),
                "minute": minute,
                "monitor_count": monitor_count,
                "expected_count": expected_count,
                "probability": probability
            })

    if not significant_errors:
        return json.dumps({"status": "ok", "version": version})

    return json.dumps({"status": "found", "version": version,
        "errors": significant_errors})


if __name__ == "__main__":
    app.debug = True
    app.run(host="0.0.0.0", port=80)

