import time
import datetime
from itertools import groupby
import logging
import copy

log = logging.getLogger("Eviction")
limit_type = 'limit'
start_interval_type = 'start/interval'


class Rule:
    magnifiers = {
        "min": 60,
        "h": 60 * 60,
        "d": 60 * 60 * 24,
        "m": 60 * 60 * 24 * 30,
        "y": 60 * 60 * 24 * 30 * 12,
    }

    def __init__(self, rule):
        (first, second) = rule.strip().split("/")
        self.first = self.__parseSpec(first)
        self.second = "delete" if (second == "delete") else self.__parseSpec(second)

    def __parseSpec(self, spec):
        import re
        if spec == "0":
            return 0

        limit_match = re.match("^(\\d+)$", spec)
        start_interval_match = re.match("^(\\d+)(%s)$" % "|".join(list(self.magnifiers.keys())), spec)

        if limit_match:
            self.type = limit_type
            return int(limit_match.groups()[0])
        elif start_interval_match:
            self.type = start_interval_type
            digit = int(start_interval_match.groups()[0])
            magnifier = self.magnifiers[start_interval_match.groups()[1]]

            return digit * magnifier
        else:
            raise Exception("Incorrect eviction specification: %s" % spec)

    def __str__(self):
        if self.interval == "delete":
            return "%d/%s" % (self.start, self.interval)
        else:
            return "%d/%d" % (self.start, self.interval)


def parse(rules):
    rules = [Rule(r) for r in rules.split(",")]
    return rules


def evict(items, rules, to=None, accessor=lambda x: x, exclude=None):
    """
        Calculate what to evict from given list of versions (version is timestamp value, when each backup was created)
    """

    parsed_rules = parse(rules)

    if parsed_rules[0].type == limit_type:
        limit = parsed_rules[0].first
        return sorted(list(set(items)), reverse=True)[limit:len(items)]
    elif parsed_rules[0].type == start_interval_type:
        evictionVersions = []
        if not to:
            to = time.time()
        iter_rules = iter(rules.split(","))
        for rule in parsed_rules:
            #		log.debug("Rule.to: %s; Rule.Start: %s" % (to, rule.start))
            #		log.debug("Exclude: %s" % exclude)

            if not exclude:
                exclude = []

            operateVersions = [x for x in items if accessor(x) <= to - rule.first and x not in exclude]
            log.debug("Eviction operate versions with rule %s : %s\n %s" % (next(iter_rules), operateVersions, [
                datetime.datetime.utcfromtimestamp(accessor(x)).strftime('%Y%m%dT%H%M') for x in operateVersions]))
            operateVersions.sort()
            if rule.second == "delete":
                # all versions should be evicted catched by this interval
                evictionVersions.extend(operateVersions)
            else:
                # group by interval and leave only first on each
                thursday = 4 * 24 * 60 * 60
                group = groupby(operateVersions, lambda t: int((accessor(t) - thursday) / rule.second))
                for key, versionsIt in group:
                    grouped = sorted(list(versionsIt), key=lambda t: accessor(t))
                    # listgrouped = copy.deepcopy(grouped)
                    # for gr in listgrouped:
                    #		log.debug("Eviction sorted groups: Key: %s; Vaultname %s; DateTime from accessor %s" % (key, gr, datetime.datetime.utcfromtimestamp(accessor(gr)).strftime('%Y%m%dT%H%M')))
                    evictionVersions.extend(grouped[:-1])
        # log.debug ("Eviction versions: %s" % evictionVersions)

        return sorted(list(set(evictionVersions)), reverse=True)
    return []
