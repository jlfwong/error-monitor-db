import datetime
import json
import os
import sys

import flask
import numpy
import redis
import scipy.stats

import error_parser

app = flask.Flask("Khan Academy Error Monitor")
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


def build_recent_buckets():
    """Return buckets for the last 24 hours and the last 7 days."""
    # Create buckets for each hour in last 24 hours
    start = datetime.datetime.now() - datetime.timedelta(1, 0, 0, 0, 0, 0)
    day_buckets = [
        [(start + datetime.timedelta(0, 0, 0, 0, 0, h)).strftime("%Y%m%d_%H")]
         for h in xrange(0, 24)]

    # Create 4 buckets a day (6 hours each) for 7 days
    start = datetime.datetime.now() - datetime.timedelta(7, 0, 0, 0, 0, 1)
    week_buckets = [
        [(start +
            datetime.timedelta(0, 0, 0, 0, 0, h1 + h2))
                .strftime("%Y%m%d_%H")
         for h2 in xrange(0, 6)]
         for h1 in xrange(0, 7 * 24, 6)]

    return day_buckets, week_buckets


@app.route("/errors/<errorkey>")
def error_details(errorkey, version=None):
    # TODO(jlfwong): Deal with monitoring
    # TODO(jlfwong): Deal with specific versions
    err_def = error_parser.RedisErrorDef.get_by_key(errorkey)

    day_buckets, week_buckets = build_recent_buckets()

    return json.dumps({
        "key": err_def.key,
        "count": err_def.get_total_count(),
        "status": int(err_def.get("status") or 0) or None,
        "level": error_parser.LEVELS[int(err_def.get("level"))],
        "firstSeen": err_def.get("first_seen"),
        "lastSeen": err_def.get("last_seen"),
        "message": err_def.get("message:title"),
        "mostCommonRoute": err_def.get_most_common_route(),
        "uniqueRouteCount": err_def.get_num_unique_routes(),
        "uniqueIpCount": err_def.get_num_unique_ips(),
        "versions": err_def.get_versions(),
        "newInVersion": version == err_def.get_earliest_version(),
        "dayTimeSeries": err_def.get_time_series(day_buckets, version),
        "weekTimeSeries": err_def.get_time_series(week_buckets, version),
        # Detail only information starts here
        "routes": err_def.get_routes(),
        "stacks": err_def.get_stacks()
    })


@app.route("/errors")
@app.route("/versions/<version>/errors")
def errors(version=None):
    # Get task data from Phabricator
    #
    # TODO(jlfwong): Cache this, and invalidate whenever someone clicks to
    # create a new task
    #
    # phabricator_domain = 'http://phabricator.khanacademy.org'
    # phabctl = phabricator.Phabricator(host=phabricator_domain + '/api/')
    # tasks = phabctl.maniphest.maniphest.query(
    #         projectPHIDs=["PHID-PROJ-wac5cp5twq6xcgubphie"])
    # error_status_by_key = {}
    # for task_id in tasks.keys():
    #     task = tasks[task_id]
    #     task_key = task["auxiliary"]["std:maniphest:khan:errorkey"]
    #     error_status_by_key[task_key] = (task["objectName"], task["status"])

    day_buckets, week_buckets = build_recent_buckets()

    # TODO(jlfwong): Pagination. Right now we just either display *all* errors
    # during monitoring, or the top 20 errors otherwise.
    error_defs = []

    monitoring = flask.request.args.get('monitoring')

    if monitoring:
        if not version:
            # If you want monitoring, you have to specify a version!
            flask.abort(400)

        error_defs = error_parser.RedisErrorDef.get_errors_during_monitoring(
                                                    version)
    elif version:
        error_defs = error_parser.RedisErrorDef.get_errors_for_version(
                                                    version, 20)
    else:
        error_defs = error_parser.RedisErrorDef.get_errors(20)

    error_dicts = []
    for err_def in error_defs:
        err_dict = {
            "key": err_def.key,
            "count": err_def.get_total_count(),
            "status": int(err_def.get("status") or 0) or None,
            "level": error_parser.LEVELS[int(err_def.get("level"))],
            "firstSeen": err_def.get("first_seen"),
            "lastSeen": err_def.get("last_seen"),
            "message": err_def.get("message:title"),
            "mostCommonRoute": err_def.get_most_common_route(),
            "uniqueRouteCount": err_def.get_num_unique_routes(),
            "uniqueIpCount": err_def.get_num_unique_ips(),
            "versions": err_def.get_versions(),
            "newInVersion": version == err_def.get_earliest_version(),
            "dayTimeSeries": err_def.get_time_series(day_buckets, version),
            "weekTimeSeries": err_def.get_time_series(week_buckets, version)
        }

        # TODO(jlfwong): All of this special casing for monitoring is done
        # because if we don't do this, we'll double count errors, because we'll
        # read them once from monitoring, and again from loading errors from
        # BigQuery. This whole problem would go away if
        #
        #   1. We had a way of tracking whether we'd recorded a specific error
        #      instance before. Perhaps this is possible by timestamp.
        #
        #   or
        #
        #   2. We streamed errors all the time instead of loading from
        #      BigQuery.
        if monitoring:
            err_dict['monitoring'] = {
                "count": err_def.get_count_during_monitoring(version),
                "mostCommonRoute":
                    err_def.get_most_common_route_during_monitoring(version),
                "uniqueRouteCount":
                    err_def.get_num_unique_routes_during_monitoring(version),
                "uniqueIpCount":
                    err_def.get_num_unique_ips_during_monitoring(version),
            }

        error_dicts.append(err_dict)

    return json.dumps({
        "errors": error_dicts,
        "dayTimeCategories": [b[0] for b in day_buckets],
        "weekTimeCategories": [b[0] for b in week_buckets],
        "lastHour": error_parser.latest_hour()
    })


@app.route("/createtask/<error_key>")
def create_task(error_key):
    # Search for an existing task associated with this error key
    phabricator_domain = 'http://phabricator.khanacademy.org'
    phabctl = phabricator.Phabricator(host=phabricator_domain + '/api/')
    tasks = phabctl.maniphest.maniphest.query(
            projectPHIDs=["PHID-PROJ-wac5cp5twq6xcgubphie"])
    for task_id in tasks.keys():
        task = tasks[task_id]
        task_key = task["auxiliary"]["std:maniphest:khan:errorkey"]
        if task_key == error_key:
            return json.dumps({
                "status": "already_exists"
            })

    err_def = error_parser.RedisErrorDef.get_by_key(error_key)
    title = "%s (%s): %s" % (
       error_parser.LEVELS[int(err_def.get("level"))],
       err_def.get("status"),
       err_def.get("message:title"))
    projectPHIDs = ["PHID-PROJ-wac5cp5twq6xcgubphie"]
    auxiliary = {"std:maniphest:khan:errorkey": error_key}
    res = phabctl.maniphest.createtask(title=title,
                                       projectPHIDs=projectPHIDs,
                                       auxiliary=auxiliary)
    return json.dumps({
        "status": "ok",
        "url": "http://phabricator.khanacademy.org/%s" % res['objectName']
    })


@app.route("/monitor", methods=["post"])
def monitor():
    # Fetch all previous errors that were not encountered during previous
    # monitoring
    params = flask.request.get_json()
    error_logs = params['logs']
    log_hour = params['log_hour']
    minute = params['minute']
    version = params['version']
    verify_versions = params['verify_versions']

    errs_to_check = set()

    for log in error_logs:
        if any(log['resource'].startswith(uri)
               for uri in error_parser.URI_BLACKLIST):
            continue

        message_def = error_parser.MessageDef(log['message'])
        status = str(log['status'])
        level = str(log['level'])
        err_def = error_parser.RedisErrorDef.get_or_create(
                log_hour, message_def, status, level)
        err_def.record_occurrence_from_monitoring(message_def, minute,
                version, log['ip'], log['resource'], log['route'],
                log['module_id'])

        errs_to_check.add(err_def)

    if not verify_versions:
        return json.dumps({"status": "ok", "version": version})

    significant_errors = []
    for err_def in errs_to_check:
        monitor_count = err_def.get_count_during_monitoring_minute(version,
                                                                   minute)
        if monitor_count == 0:
            continue

        print "MONITORING ERROR IN %s: %s" % (
                version, err_def.get("message:title"))
        version_counts = [
            err_def.get_count_during_monitoring_minute(verify_version, minute)
            for verify_version in verify_versions]

        (expected_count, probability) = _count_is_elevated_probability(
                version_counts, monitor_count)

        if probability >= 0.9995:
            significant_errors.append({
                "key": err_def.key,
                "status": int(err_def.get("status")),
                "level": error_parser.LEVELS[int(err_def.get("level"))],
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

