import datetime
from flask import Flask
from flask import request
import json
import redis

import error_parser
import statistics_util

app = Flask("Khan Academy Error Monitor")
r = redis.StrictRedis(host='localhost', port=6379, db=0)


@app.route("/errors")
@app.route("/errors/<version>")
def errors(version=None):
    errors = []
    
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
        if version and err_def.get("monitor_count:%s" % version):
            errors.append({
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
            })

        if int(err_def.get("count")) and (
                not version or version in err_def.get_versions()):
            errors.append({
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
        max_version_count = max(
            [int(err_def.get("monitor_count:%s:%s" % (verify_version, minute))
                or 0) for verify_version in verify_versions])

        # TODO(tom) Use all 5 values to do a chi-squared test or something
        # smarter
        (_, probability) = statistics_util.count_is_elevated_probability(
                max_version_count, 1, monitor_count, 1)

        if probability >= 0.9995:
            significant_errors.append({
                "key": err_def.key,
                "status": int(err_def.get("status")),
                "level": error_parser.LEVELS[int(err_def.get("level"))],
                "stack": err_def.get("stack"),
                "message": err_def.get("message:title"),
                "minute": minute,
                "monitor_count": monitor_count,
                "expected_count": max_version_count,
                "probability": probability
            })

    if not significant_errors:
        return json.dumps({"status": "ok", "version": version})

    return json.dumps({"status": "found", "version": version,
        "errors": significant_errors})


if __name__ == "__main__":
    app.debug = True
    app.run(host="0.0.0.0", port=80)

