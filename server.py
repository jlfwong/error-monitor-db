import datetime
from flask import Flask
from flask import request
import json
import redis

import error_parser

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
        err_def = error_parser.RedisErrorDef(key)
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
                "dayTimeSeries": err_def.get_time_series(day_buckets),
                "weekTimeSeries": err_def.get_time_series(week_buckets),
            })

    return json.dumps({
        "errors": errors,
        "dayTimeCategories": [b[0] for b in day_buckets],
        "weekTimeCategories": [b[0] for b in week_buckets],
        "lastHour": error_parser.latest_hour()
    })


@app.route("/monitor", methods=["post"])
def monitor():
    previous_errors = error_parser.RedisErrorDef.get_all()
    new_errors = {}
    params = request.get_json()
    error_logs = params['logs']
    log_hour = params['log_hour']
    error_counts = {}

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
                log['version_id'], log['ip'], log['resource'])

        if err_def.key not in previous_errors:
            new_errors[err_def.key] = err_def

        error_counts[err_def.key] = error_counts.get(err_def.key, 0) + 1

    previous_errors = {
        key: err_def
        for key, err_def in previous_errors.iteritems()
        if key in error_counts
    }

    return json.dumps({
        "new_errors": [
            {
                "key": err_def.key,
                "status": int(err_def.get("status")),
                "level": error_parser.LEVELS[int(err_def.get("level"))],
                "stack": err_def.get("stack"),
                "message": err_def.get("message:title"),
                "count": error_counts[err_def.key]
            }
            for err_def in new_errors.values()
        ],
        "existing_errors": [
            {
                "key": err_def.key,
                "status": int(err_def.get("status")),
                "level": error_parser.LEVELS[int(err_def.get("level"))],
                "stack": err_def.get("stack"),
                "message": err_def.get("message:title"),
                "count": error_counts[err_def.key]
            }
            for err_def in previous_errors.values()
        ]
    })


if __name__ == "__main__":
    app.debug = True
    app.run(host="0.0.0.0", port=80)

