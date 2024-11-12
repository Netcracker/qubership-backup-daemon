# Copyright 2024-2025 NetCracker Technology Corporation
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import time
import unittest
import calendar

############## import files ##############
import eviction


class EvictionTests(unittest.TestCase):
    def testRuleParse(self):
        print("------------------------------------------------")
        print("Test Rule Parse")
        rules = eviction.parse("0/1h,3d/1d,7d/7d,1m/1m,1y/delete")
        self.assertEqual(0, rules[0].first)
        self.assertEqual(60 * 60, rules[0].second)

        self.assertEqual(60 * 60 * 24 * 3, rules[1].first)
        self.assertEqual(60 * 60 * 24, rules[1].second)

        self.assertEqual(60 * 60 * 24 * 7, rules[2].first)
        self.assertEqual(60 * 60 * 24 * 7, rules[2].second)

        self.assertEqual(60 * 60 * 24 * 30, rules[3].first)
        self.assertEqual(60 * 60 * 24 * 30, rules[3].second)

        self.assertEqual(60 * 60 * 24 * 30 * 12, rules[4].first)
        self.assertEqual("delete", rules[4].second)

    def testEviction1(self):
        print("------------------------------------------------")
        print("Test Eviction1")
        now = time.time()

        versions = [
            now - 1,  # should stay
            now - (60 * 60 + 1),  # should be evicted
            now - (60 * 60 * 2 + 1),  # should be evicted
            now - (24 * 60 * 60 + 1)  # should stay
        ]
        print(f'All versions: {versions}')
        evicted_versions = eviction.evict(versions, "0/1d", now)
        print(f'Evicted: {evicted_versions}')
        self.assertEqual(versions[1], evicted_versions[0])
        self.assertEqual(versions[2], evicted_versions[1])
        self.assertEqual(2, len(evicted_versions))

    def testWeeklyEviction(self):
        print("------------------------------------------------")
        print("Test Weekly Eviction")
        now = calendar.timegm(time.strptime("23 Jan 17", "%d %b %y"))
        versions = [
            calendar.timegm(time.strptime("10 Jan 17", "%d %b %y")),
            calendar.timegm(time.strptime("12 Jan 17", "%d %b %y")),
            calendar.timegm(time.strptime("14 Jan 17", "%d %b %y")),

            calendar.timegm(time.strptime("21 Jan 17", "%d %b %y")),  # test incorrect version sorting
            calendar.timegm(time.strptime("19 Jan 17", "%d %b %y")),
            calendar.timegm(time.strptime("22 Jan 17", "%d %b %y"))
        ]
        evicted_version = eviction.evict(versions, "0/7d", now)
        print([time.strftime("%d %b %y", time.localtime(t)) for t in evicted_version])
        from operator import itemgetter
        self.assertEqual(list(itemgetter(3, 4, 1, 0)(versions)), evicted_version)

    def testEviction2(self):
        print("------------------------------------------------")
        print("Test Eviction2")
        # emulate 1 dump per hour during 24 hour
        now = 60 * 60 * 24 * 2
        versions = list(range(now, 0, -60 * 60))
        print(f'All versions: {list(versions)}')
        evicted_versions = eviction.evict(versions, "0/1h,4h/1d", now)
        print(f'To eviction: {evicted_versions}')
        print(f'Leave: {(set(versions) - set(evicted_versions))}')
        self.assertEqual({172800, 169200, 165600, 162000, 158400, 86400}, set(versions) - set(evicted_versions))

    def testDelete(self):
        print("------------------------------------------------")
        print("Test Delete")
        # emulate 1 dump per hour during 24 hour
        now = 60 * 60 * 2
        versions = list(range(now, 0, -60 * 60))

        print(f'All versions: {versions}')
        evicted_versions = eviction.evict(versions, "1h/delete", now + 5)
        print(f'To eviction: {evicted_versions}')
        print(f'Leave: {(set(versions) - set(evicted_versions))}')
        self.assertEqual(set(versions[:1]), set(versions) - set(evicted_versions))

    def testAccessor(self):
        print("------------------------------------------------")
        print("Test Accessor")
        versions = [Item('A', 60 * 60), Item('B', 60 * 60 * 2)]

        print(f'All versions: {versions}')
        evicted_versions = eviction.evict(versions, "1h/delete", 60 * 60 * 2 + 5, accessor=lambda x: x.ts)
        print(f'To eviction: {evicted_versions}')
        print(f'Leave: {(set(versions) - set(evicted_versions))}')

    def testMassiveEviction(self):
        print("------------------------------------------------")
        print("Test Massive Eviction")
        # prepare sample data: four backups each day of month
        time_format = "%d %b %y %H:%M"
        time_format2 = "%Y%m%dT%H%M%S"
        flatten = lambda l: [item for sublist in l for item in sublist]
        to_ts = lambda s: calendar.timegm(time.strptime(s, time_format))
        versions = flatten(
            [["%d Jun 16 13:00" % d, "%d Jun 16 13:20" % d, "%d Jun 16 15:00" % d, "%d Jun 16 16:00" % d] for d in
             range(30, 1, -1)])
        # versions2 = [to_ts2(s) for s in versions]

        # calculate evictions
        now = to_ts("21 Sep 17 11:11")
        evicted_versions = eviction.evict(versions, "0/1h,1d/7d,1m/1m", now, accessor=lambda x: to_ts(x))

        # debug output
        survivors = set([to_ts(s.strip()) for s in set(versions) - set(evicted_versions)])
        print(("\n".join([time.strftime(time_format, time.localtime(ts)) for ts in sorted(list(survivors))])))
        expected = set([to_ts(s.strip()) for s in """30 Jun 16 16:00""".split("\n")])

        self.assertEqual(survivors, expected)


class Item:
    def __init__(self, name, ts):
        self.name = name
        self.ts = ts

    def __repr__(self):
        return "%s:%d" % (self.name, self.ts)


if __name__ == '__main__':
    unittest.main()
