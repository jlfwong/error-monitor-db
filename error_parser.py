import datetime
import json
import md5
import re
import redis
import sys

import bigquery

# TODO: Run this on a cron

LEVELS = [ "", "", "", "ERROR", "CRITICAL" ]

# URIs to ignore because they spam irrelevant errors
URI_BLACKLIST = [
    '/api/internal/translate/lint_poentry'
    ]

r = redis.StrictRedis(host='localhost', port=6379, db=0)

error_cache = {}
error_cache_id = None

class MessageDef(object):
    def __init__(self, message):
        msg_lines = message.split("\n")

        self.title = msg_lines[0].encode('utf-8')

        # Various identifying traits
        self.id0 = re.sub(r'\d+', '%%', self.title)
        self.id1 = " ".join(self.id0.split(" ")[:3])
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
                (filename, line_no, function) = match.groups()
                self.stack.append({
                    "filename": filename,
                    "line_no": line_no,
                    "function": function
                })


class RedisErrorDef(object):
    def __init__(self, key):
        self.key = key
        self.cache = {}
        self.cache["count"] = r.get("%s:count" % key)

    @staticmethod
    def create(log_hour, message_def, status, level):
        key = message_def.hash
        r.set("%s:count" % key, "0")
        r.set("%s:status" % key, status)
        r.set("%s:level" % key, level)
        r.set("%s:first_seen" % key, log_hour)
        r.set("%s:last_seen" % key, log_hour)
        r.set("%s:message:title" % key, message_def.title)
        r.set("%s:stack" % key, json.dumps(message_def.stack))

        r.hset("message:id0:%s:%s" % (status, level), message_def.id0, key)
        r.hset("message:id1:%s:%s" % (status, level), message_def.id1, key)
        r.hset("message:id2:%s:%s" % (status, level), message_def.id2, key)
        r.hset("message:id3:%s:%s" % (status, level), message_def.id3, key)

        r.sadd("errors", key)

        return RedisErrorDef(key)

    @staticmethod
    def get_by_key(key):
        if key not in error_cache:
            error_cache[key] = RedisErrorDef(key)

        elif r.get("%s:count" % key) != error_cache[key].cache["count"]:
            error_cache[key] = RedisErrorDef(key)

        return error_cache[key]

    @staticmethod
    def get_all():
        return {key: RedisErrorDef.get_by_key(key)
                for key in r.smembers("errors")}

    @staticmethod
    def get_or_create_def(log_hour, message_def, status, level):
        err_def = RedisErrorDef.find_match(message_def, status, level)
        if err_def:
            return err_def

        return RedisErrorDef.create(log_hour, message_def, status, level)

    def add_instance(self, log_hour, version, ip, resource):
        r.sadd("%s:ips" % self.key, ip)
        r.sadd("%s:uris" % self.key, resource)
        r.sadd("%s:versions" % self.key, version)
        r.incr("%s:uris:%s" % (self.key, resource))
        r.incr("%s:versions:%s" % (self.key, version))
        r.incr("%s:count" % self.key)
        r.incr("%s:seen_on:%s:%s" % (self.key, log_hour, version))

        if log_hour < r.get("%s:first_seen" % self.key):
            r.set("%s:first_seen" % self.key, log_hour)
        if log_hour > r.get("%s:last_seen" % self.key):
            r.set("%s:last_seen" % self.key, log_hour)

    def add_monitoring_instance(self, version, ip, resource):
        r.incr("%s:monitor_count:%s" % (self.key, version))
        r.sadd("%s:monitor_ips" % self.key, ip)
        r.sadd("%s:monitor_uris" % self.key, resource)

    @staticmethod
    def find_match(message_def, status, level):
        status = str(status)
        level = str(level)

        key = r.hget("message:id0:%s:%s" % (status, level), message_def.id0)
        if key:
            return RedisErrorDef(key)

        key = r.hget("message:id1:%s:%s" % (status, level), message_def.id1)
        if key:
            return RedisErrorDef(key)

        key = r.hget("message:id2:%s:%s" % (status, level), message_def.id2)
        if key:
            return RedisErrorDef(key)

        if message_def.id3:
            key = r.hget("message:id3:%s:%s" % (status, level),
                    message_def.id3)
            if key:
                return RedisErrorDef(key)

        return None

    def get(self, field):
        if field not in self.cache:
            self.cache[field] = r.get("%s:%s" % (self.key, field))
        return self.cache[field]

    def members(self, field):
        if field not in self.cache:
            self.cache[field] = r.smembers("%s:%s" % (self.key, field))
        return self.cache[field]

    def get_uris(self):
        uri_set = self.members("uris")
        return {
            uri: int(self.get("uris:%s" % uri))
            for uri in uri_set
        }

    def get_versions(self):
        version_set = self.members("versions")
        return {
            version: int(self.get("versions:%s" % version))
            for version in version_set
        }

    def get_earliest_version(self):
        versions = self.members("versions")
        if versions:
            return sorted(list(versions))[0]
        return None

    def get_time_series(self, hour_buckets, version=None):
        version_set = [version] if version else self.members("versions")
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


def logs_from_biguery(bq_util, log_hour):
    if r.sismember("processed_datasets", log_hour):
        print "Already fetched logs for %s" % log_hour
        return True

    old_defs = len(r.smembers("errors"))

    lines = 0
    print "Fetching hourly logs for %s" % log_hour
    records = bq_util.run_query(
            ('SELECT version_id, ip, resource, status, app_logs.level, '
             'app_logs.message FROM [logs_hourly.requestlogs_%s] WHERE '
             'app_logs.level >= 3') % log_hour)
    if records == None:
        return False

    for record in records:
        [version_id, ip, resource, status, level, message] = [
            v['v'] for v in record['f']]

        if any(resource.startswith(uri) for uri in URI_BLACKLIST):
            continue

        if version_id.startswith("znd"):
            continue

        message_def = MessageDef(message)
        error_def = RedisErrorDef.get_or_create_def(
                log_hour, message_def, status, level)
        error_def.add_instance(
                log_hour, version_id, ip, resource)
        lines += 1

    new_defs = len(r.smembers("errors"))

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

