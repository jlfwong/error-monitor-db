import datetime
import json
import md5
import re
import redis
import sys

import bigquery

# TODO: Run this on a cron

LEVELS = ["", "", "", "ERROR", "CRITICAL"]

# URIs to ignore because they spam irrelevant errors
URI_BLACKLIST = [
    '/api/internal/translate/lint_poentry'
    ]

r = redis.StrictRedis(host='localhost', port=6379, db=0)

# TODO(jlfwong): If we don't change this to be an LRU cache of some sort, this
# will eventually just get too big and the process will run out of memory.
_error_cache = {}


# Each different version has a different file path. When we're deciding
# whether two stacks are unique or not, we don't care about those, so
# get rid of them.
#
#
# The original file paths start like this:
# /base/data/home/apps/s~khan-academy/1029-2305-f48a12e2b9ba.379742046073152437/api/errors.py @Nolint
_VERSION_PATH_PREFIX_RE = re.compile(r'^.*\d{4}-\d{4}-[a-z0-9]{12}\.\d+/')


class MessageDef(object):
    def __init__(self, message):
        msg_lines = message.split("\n")

        self.title = msg_lines[0].encode('utf-8')

        # Various identifying traits
        #
        # The title with numbers removed
        self.id0 = re.sub(r'\d+', '%%', self.title)

        # The first 3 words of the title
        self.id1 = " ".join(self.id0.split(" ")[:3])

        # The last 3 words of the title
        self.id2 = " ".join(self.id0.split(" ")[-3:])
        self.id3 = None

        h = md5.md5()
        id_str = "%s%s%s%s" % (self.id0, self.id1, self.id2, self.id3)
        h.update(id_str)
        self.hash = h.hexdigest()[:8]

        # Special-cases
        if self.title.startswith("{'report_url':"):
            self.id3 = 'report_url'

        self.stack = []

        for line in msg_lines[1:]:
            if line.startswith("Traceback"):
                continue
            if line.startswith("  File "):
                match = re.match(
                    r'  File "([^"]*)", line (\d*), in (.*)', line)
                if not match:
                    print "Bad TB line: %s" % line
                    continue
                (filename, lineno, function) = match.groups()
                filename = _VERSION_PATH_PREFIX_RE.sub('', filename)
                self.stack.append({
                    "filename": filename,
                    "lineno": lineno,
                    "function": function
                })

        # We want to de-duplicate storage of stacks, but be resilient to line
        # number changes, so we ignore line numbers when doing the hashing.
        self.stack_key = hash("|".join("%(filename)s:%(function)s" % s
                                        for s in self.stack))


class RedisErrorDef(object):
    def __init__(self, key, count=None):
        self.key = key
        self._cache = {}

    @staticmethod
    def get_occurrence_count(key):
        return int(r.zscore("errors", key) or 0)

    @staticmethod
    def create(log_hour, message_def, status, level):
        key = message_def.hash
        r.set("%s:status" % key, status)
        r.set("%s:level" % key, level)
        r.set("%s:first_seen" % key, log_hour)
        r.set("%s:last_seen" % key, log_hour)
        r.set("%s:message:title" % key, message_def.title)

        r.hset("message:id0:%s:%s" % (status, level), message_def.id0, key)
        r.hset("message:id1:%s:%s" % (status, level), message_def.id1, key)
        r.hset("message:id2:%s:%s" % (status, level), message_def.id2, key)
        r.hset("message:id3:%s:%s" % (status, level), message_def.id3, key)

        r.zadd("errors", 0, key)

        return RedisErrorDef(key)

    @classmethod
    def get_errors_during_monitoring(cls, version):
        """Return a list of all errors found during monitoring.

        The returned list will be ordered by number of occurences during
        monitoring.
        """
        keys = r.zrevrange("monitoring:%s:errors" % version, 0, -1)
        return [RedisErrorDef.get_by_key(k) for k in keys]

    @classmethod
    def get_errors_for_version(cls, version, count, offset=0):
        """Return a list of the top errors found in a specific version.

        The returned list will be ordered by the number of occurrences in the
        requested version.
        """
        keys = r.zrevrange("errors:version:%s" % version,
                           offset, count + offset)
        return [RedisErrorDef.get_by_key(k) for k in keys]

    @classmethod
    def get_errors(cls, count, offset=0):
        """Return a list of RedisErrorDef instances ranked by occurrences."""
        keys = r.zrevrange("errors", offset, count + offset - 1)
        return [RedisErrorDef.get_by_key(k) for k in keys]

    @staticmethod
    def get_by_key(key):
        if key not in _error_cache:
            # If nobody's requested this error before, load it
            _error_cache[key] = RedisErrorDef(key)
        else:
            old_cache_count = _error_cache[key].get_total_count()
            _error_cache[key]._cache.pop("count")
            new_cache_count = _error_cache[key].get_total_count()

            if new_cache_count != old_cache_count:
                # If the count has increased since we loaded the error last
                # time from redis, we need to reload it to get new information
                # about it. This happens when we load new logs from BigQuery.
                _error_cache[key] = RedisErrorDef(key)

        return _error_cache[key]

    @staticmethod
    def get_or_create(log_hour, message_def, status, level):
        err_def = RedisErrorDef.find_match(message_def, status, level)
        if err_def:
            return err_def

        return RedisErrorDef.create(log_hour, message_def, status, level)

    _CACHE_BUST_QUERY_PARAM_RE = re.compile(r'_=\d+')

    @classmethod
    def _record_occurrence_common(cls, key_prefix, message_def, ip,
                                  resource, route, module_id):
        # We append cache-busting query params that we want to ignore for the
        # sake of de-duplication
        resource = cls._CACHE_BUST_QUERY_PARAM_RE.sub('', resource)

        # Record how many unique IPs have hit this endpoint, and also how many 
        # times each of them hit the error.
        r.zincrby("%s:ips" % key_prefix, ip)

        # Record all the unique stack traces we get, and count how many times
        # each of them is hit.
        #
        # TODO(jlfwong): It might be useful to classify stack traces under
        # routes.
        r.hset("%s:stacks:msgs" % key_prefix,
               message_def.stack_key,
               json.dumps(message_def.stack))
        r.zincrby("%s:stacks:counts" % key_prefix,
                  message_def.stack_key)

        # TODO(jlfwong): Record the last time (or version) each stack or route
        # was seen

        # Record all of the routes causing this error, and also how many times
        # each of them is being hit.
        r.zincrby("%s:routes" % key_prefix, route)

        # Record hits for a specific URL. We classify URLs hierarchically under
        # routes.
        r.zincrby("%s:uris:%s" % (key_prefix, route), resource)

        # Record a hit for a specific module id
        r.zincrby("%s:modules" % key_prefix, module_id)

    def record_occurrence(self, message_def, log_hour, version,
                          ip, resource, route, module_id):

        # Record a hit on this error
        r.zincrby("errors", self.key)

        # Record a hit on this error by version so we can look up the most
        # common errors for a given version
        r.zincrby("errors:version:%s" % version, self.key)

        self._record_occurrence_common(self.key, message_def, ip,
                                       resource, route, module_id)

        # Record a hit for the version
        r.zincrby("%s:versions" % self.key, version)

        # Record a hit for a specific hour on a specific version
        r.incr("%s:seen_on:%s:%s" % (self.key, log_hour, version))

        # Record the first and last time we've seen the error.
        if log_hour < r.get("%s:first_seen" % self.key):
            r.set("%s:first_seen" % self.key, log_hour)
        if log_hour > r.get("%s:last_seen" % self.key):
            r.set("%s:last_seen" % self.key, log_hour)

    def record_occurrence_from_monitoring(self, message_def, log_minute,
                                          version, ip, resource, route,
                                          module_id):
        # To make our monitoring errors easy to clean up when we don't care
        # about them any more, we prefix all of the keys with
        # monitoring:version
        monitoring_key_prefix = "monitoring:%s:%s" % (version, self.key)

        r.zincrby("monitoring:%s:errors" % version, self.key)

        # Record a hit during monitoring for a given minute
        r.hincrby("monitoring:%s:seen_on:%s" % (version, self.key),
                  log_minute)

        self._record_occurrence_common(monitoring_key_prefix, message_def, ip,
                                       resource, route, module_id)

    @staticmethod
    def find_match(message_def, status, level):
        status = str(status)
        level = str(level)

        key = r.hget("message:id0:%s:%s" % (status, level), message_def.id0)
        if key:
            return RedisErrorDef.get_by_key(key)

        key = r.hget("message:id1:%s:%s" % (status, level), message_def.id1)
        if key:
            return RedisErrorDef.get_by_key(key)

        key = r.hget("message:id2:%s:%s" % (status, level), message_def.id2)
        if key:
            return RedisErrorDef.get_by_key(key)

        if message_def.id3:
            key = r.hget("message:id3:%s:%s" % (status, level),
                    message_def.id3)
            if key:
                return RedisErrorDef.get_by_key(key)

        return None

    def get_count_during_monitoring(self, version):
        cache_key = 'monitoring:%s:count' % version
        if cache_key not in self._cache:
            redis_key = 'monitoring:%s:errors' % version
            self._cache[cache_key] = int(r.zscore(redis_key, self.key) or 0)
        return self._cache[cache_key]

    def get_count_during_monitoring_minute(self, version, minute):
        # We don't bother caching this because it's so rarely queried
        return int(r.hget("monitoring:%s:seen_on:%s" % (version, self.key),
                          minute) or 0)

    def get_total_count(self):
        cache_key = 'count'
        if cache_key not in self._cache:
            self._cache[cache_key] = int(r.zscore('errors', self.key) or 0)
        return self._cache[cache_key]

    def get(self, field):
        if field not in self._cache:
            self._cache[field] = r.get("%s:%s" % (self.key, field))
        return self._cache[field]

    # TODO(jlfwong): This caching pattern is getting realllly repetetive. It
    # could be cleaned up a lot with a good decorator.

    def get_most_common_route_during_monitoring(self, version):
        """Return biggest culprit route while monitoring."""
        cache_key = 'monitoring:%s:toproute' % version
        if cache_key not in self._cache:
            routes = r.zrevrange(("monitoring:%s:%s:routes" %
                                  (version, self.key)), 0, 0)
            if len(routes):
                self._cache[cache_key] = routes[0]
            else:
                self._cache[cache_key] = None
        return self._cache[cache_key]

    def get_most_common_route(self):
        """Return biggest culprit route."""
        cache_key = "toproute"
        if cache_key not in self._cache:
            routes = r.zrevrange("%s:routes" % self.key, 0, 0)
            if len(routes):
                self._cache[cache_key] = routes[0]
            else:
                self._cache[cache_key] = None
        return self._cache[cache_key]

    def get_num_unique_routes_during_monitoring(self, version):
        """Return the number of unique routes hit while monitoring."""
        cache_key = 'monitoring:%s:routecount' % version
        if cache_key not in self._cache:
            self._cache[cache_key] = r.zcard("monitoring:%s:%s:routes" %
                                             (version, self.key))
        return self._cache[cache_key]

    def get_num_unique_routes(self):
        """Return the number of unique routes hitting this error."""
        cache_key = "unique_route_count"
        if cache_key not in self._cache:
            self._cache[cache_key] = r.zcard("%s:routes" % self.key)
        return self._cache[cache_key]

    def get_num_unique_ips_during_monitoring(self, version):
        cache_key = "monitoring:%s:uniqueipcount"
        if cache_key not in self._cache:
            self._cache[cache_key] = r.zcard("monitoring:%s:%s:ips" %
                                             (self.key, version))
        return self._cache[cache_key]

    def get_num_unique_ips(self):
        cache_key = "uniqueipcount"
        if cache_key not in self._cache:
            self._cache[cache_key] = r.zcard("%s:ips" % self.key)
        return self._cache[cache_key]

    def get_versions(self):
        """Return {version: hitcount} for all versions."""
        cache_key = "versions"
        if cache_key not in self._cache:
            versions = r.zrange("%s:versions" % self.key, 0, -1,
                                withscores=True,
                                score_cast_func=int)
            self._cache[cache_key] = dict(versions)
        return self._cache[cache_key]

    def get_earliest_version(self):
        """Return the earliest known version with an occurrence."""
        versions = self.get_versions()
        if not versions:
            return None
        return min(versions.keys())

    def get_time_series(self, hour_buckets, version=None):
        """TODO(jlfwong)."""
        # This is a lot of data, and the requested time data will change
        # frequently, so we don't cache this to avoid filling up memory.
        version_set = [version] if version else self.get_versions().keys()
        time_series = []
        for bucket in hour_buckets:
            version_counts = {}
            for log_hour in bucket:
                for version in version_set:
                    count = self.get("seen_on:%s:%s" % (log_hour, version))
                    if count:
                        version_counts[version] = (
                            version_counts.get(version, 0) + int(count))
            time_series.append(version_counts)
        return time_series

    def get_routes(self):
        """Return info for all routes, including the URLs beneath them."""
        ret = []
        routes_and_counts = r.zrevrange("%s:routes" % self.key, 0, -1,
                                        withscores=True,
                                        score_cast_func=int)
        for route, count in routes_and_counts:
            ret.append({
                "count": count,
                "route": route,
                "urls": r.zrevrange("%s:uris:%s" % (self.key, route), 0, -1,
                                    withscores=True,
                                    score_cast_func=int)
            })

        return ret

    def get_stacks(self):
        """Return a list of stack traces with their hitcounts."""
        ret = []
        stack_keys_and_counts = r.zrevrange("%s:stacks:counts" % self.key,
                                            0, -1,
                                            withscores=True,
                                            score_cast_func=int)
        for stack_key, count in stack_keys_and_counts:
            ret.append({
                "count": count,
                "stack": json.loads(r.hget("%s:stacks:msgs" % self.key,
                                           stack_key))
            })

        return ret


def logs_from_biguery(bq_util, log_hour):
    if r.sismember("processed_datasets", log_hour):
        print "Already fetched logs for %s" % log_hour
        return True

    old_defs = r.zcard("errors")

    lines = 0
    print "Fetching hourly logs for %s" % log_hour
    records = bq_util.run_query(
            ('SELECT version_id, ip, resource, status, app_logs.level, '
             'app_logs.message, elog_url_route, module_id '
             'FROM [logs_hourly.requestlogs_%s] WHERE '
             'app_logs.level >= 3') % log_hour)
    if records == None:
        return False

    for record in records:
        [
            version_id, ip, resource, status, level, message, route, module_id
        ] = [v['v'] for v in record['f']]

        if any(resource.startswith(uri) for uri in URI_BLACKLIST):
            continue

        if version_id.startswith("znd"):
            continue

        message_def = MessageDef(message)
        error_def = RedisErrorDef.get_or_create(log_hour, message_def,
                                                status, level)
        error_def.record_occurrence(message_def, log_hour, version_id,
                                    ip, resource, route, module_id)
        lines += 1

    new_defs = r.zcard("errors")

    print "Unique errors: %d out of %d" % (new_defs - old_defs, lines)
    r.sadd("processed_datasets", log_hour)
    return True


def latest_hour():
    return sorted(list(r.smembers("processed_datasets")))[-1]


if __name__ == "__main__":
    if len(sys.argv) > 1:
        date_str = sys.argv[1]
    else:
        date_str = datetime.datetime.now().strftime("%Y%m%d")
    bq = bigquery.BigQueryUtil()
    for hour in xrange(0, 24):
        if not logs_from_biguery(bq, "%s_%02d" % (date_str, hour)):
            print "Could not fetch logs."
            break
    print "Done fetching logs."

