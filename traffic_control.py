#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
traffic_control.py

Created by 4Aiur on 2011-05-30.
"""
__version__ = '0.90'


import logging
import logging.config
import json
import re
import sys
from subprocess import (call, STDOUT, PIPE, Popen)
from optparse import OptionParser
import traceback
import utils
from pdb import set_trace as breakpoints


logging.config.fileConfig('conf/logging.cfg')


class TrafficControl(object):

    def __init__(self):
        self.logger = logging.getLogger(self.__class__.__name__)
        self.logger.debug('initialization')
        self.rate_file = 'conf/rate.json'
        self.filter_rule_file = 'conf/filter.json'
        self.classifier = 'u32'
        self.parent = '1:0'
        self.priority = 2
        self.nics = ['eth0', 'eth1', 'eth2', 'eth3']
        self.filters = self.load_filter()

    def pick_class_id(self, rates):
        i = 10
        ids = [int(x) for x in rates.values()]
        while True:
            if i not in ids:
                class_id = i
                break
            i += 5
        return unicode(class_id)

    def get_class_id(self, rate):
        rates = self.load_rate()
        if rate in rates:
            class_id = rates[rate]
        else:
            class_id = self.pick_class_id(rates)
            rates[rate] = class_id
            self.save_rate(rates)
            for ifname in self.nics:
                self.add_class(ifname, rate, class_id)
        return class_id

    def add_class(self, ifname, rate, class_id):
        self.logger.debug('add class ifname: %s, rate: %s, class_id: %s'
                % (ifname, rate, class_id))
        self.logger.debug('/sbin/tc class add dev %s parent 1:0 classid 1:%s '
                'htb rate %s burst 15Kb' % (ifname, class_id, rate))
        call('/sbin/tc class add dev %s parent 1:0 classid 1:%s htb '
                'rate %s burst 15Kb' % (ifname, class_id, rate),
                shell=True, stderr=STDOUT, stdout=None)
        self.logger.debug('/sbin/tc qdisc add dev %s parent 1:%s handle %s:0 '
                'sfq perturb 10' % (ifname, class_id, class_id))
        call('/sbin/tc qdisc add dev %s parent 1:%s handle %s:0 sfq perturb 10'
                % (ifname, class_id, class_id),
                shell=True, stderr=STDOUT, stdout=None)
        return

    def load_rate(self):
        try:
            fp = open(self.rate_file)
            rates = json.loads(fp.read())
            fp.close()
        except Exception, err:
            self.logger.error(err)
            rates = {}
        return rates

    def save_rate(self, rates):
        try:
            fp = open(self.rate_file, 'w')
            result = json.dumps(rates, sort_keys=True, indent=4)
            fp.write(result + '\n')
            fp.close()
        except Exception, err:
            self.logger.error(err)
        return

    def load_filter(self):
        try:
            fp = open(self.filter_rule_file)
            filter_rules = json.loads(fp.read())
            fp.close()
        except Exception, err:
            self.logger.error(err)
            filter_rules = {}
        filters = {}
        for ipaddress in filter_rules:
            flowid = filter_rules[ipaddress]['flowid']
            ifname = filter_rules[ipaddress]['ifname']
            rate = filter_rules[ipaddress]['rate']
            filters[ipaddress] = FilterRule(flowid, ifname, rate)
        return filters

    def save_filter(self, filters):
        try:
            filter_rules = {}
            for ipaddress in filters:
                filter_rule = filters[ipaddress]
                filter_rules[ipaddress] = {}
                filter_rules[ipaddress]['flowid'] = filter_rule.flowid
                filter_rules[ipaddress]['ifname'] = filter_rule.ifname
                filter_rules[ipaddress]['rate'] = filter_rule.rate
            fp = open(self.filter_rule_file, 'w')
            result = json.dumps(filter_rules, sort_keys=True, indent=4)
            fp.write(result + '\n')
            fp.close()
        except Exception, err:
            exstr = traceback.format_exc()
            self.logger.error(err)
            self.logger.error(exstr)
        return

    def add_filter(self, ipaddress, ifname, rate, save=True):
        self.logger.debug('add filter ifname: %s, ip: %s, rate: %s'
            % (ifname, ipaddress, rate))
        utils.check_ip(ipaddress)
        if ipaddress in self.filters:
            self.delete_filter(ipaddress, save=save)
        flowid = self.get_class_id(rate)
        flowid = "1:" + str(flowid)
        self.filters[ipaddress] = FilterRule(flowid, ifname, rate)
        # run add tc filter command
        self.logger.debug('/sbin/tc filter add dev %s parent %s protocol ip '
                'prio %d %s match ip src %s match ip dst 0.0.0.0/0 flowid %s'
                % (ifname, self.parent, self.priority, self.classifier,
                    ipaddress, flowid))
        call('/sbin/tc filter add dev %s parent %s protocol ip prio %d '
                '%s match ip src %s match ip dst 0.0.0.0/0 flowid %s'
                % (ifname, self.parent, self.priority, self.classifier,
                    ipaddress, flowid),
                shell=True, stderr=STDOUT, stdout=None)
        self.logger.debug('/sbin/tc filter add dev %s parent %s protocol ip '
                'prio %d %s match ip src 0.0.0.0/0 match ip dst %s flowid %s'
                % (ifname, self.parent, self.priority, self.classifier,
                    ipaddress, flowid))
        call('/sbin/tc filter add dev %s parent %s protocol ip prio %d '
                '%s match ip src 0.0.0.0/0 match ip dst %s flowid %s'
                % (ifname, self.parent, self.priority, self.classifier,
                    ipaddress, flowid),
                shell=True, stderr=STDOUT, stdout=None)
        if save:
            self.save_filter(self.filters)
        return

    def search_real_filter(self, ifname, ipaddress):
        '''
        # tc filter list dev eth0
        filter parent 1: protocol ip pref 2 u32
        filter parent 1: protocol ip pref 2 u32 fh 800: ht divisor 1
        filter parent 1: protocol ip pref 2 u32 fh 800::800 order 2048 key \
            ht 800 bkt 0 flowid 1:15
          match 01020305/ffffffff at 12
          match 00000000/00000000 at 16
        filter parent 1: protocol ip pref 2 u32 fh 800::801 order 2049 key \
            ht 800 bkt 0 flowid 1:15
          match 00000000/00000000 at 12
          match 01020305/ffffffff at 16
        filter parent 1: protocol ip pref 2 u32 fh 800::802 order 2050 key \
            ht 800 bkt 0 flowid 1:40
          match 01020307/ffffffff at 12
          match 00000000/00000000 at 16
        filter parent 1: protocol ip pref 2 u32 fh 800::803 order 2051 key \
            ht 800 bkt 0 flowid 1:40
          match 00000000/00000000 at 12
          match 01020307/ffffffff at 16
        '''
        real_filters = []
        re_filter = re.compile(r'.*filter parent (.*) protocol ip pref (\d+) (.*) fh (.*) order .* flowid .*')
        convert_ip = utils.ConvertIP()
        ip_hex = convert_ip.ip2hex(ipaddress)
        re_ipaddress = re.compile(r'match %s/ffffffff at .*' % (ip_hex))
        report = Popen('tc filter list dev %s' % (ifname),
                        shell=True, stderr=STDOUT, stdout=PIPE)
        result = [x.strip() for x in report.stdout.readlines()]
        #breakpoints()
        for x in range(len(result)):
            try:
                if (re.search(re_filter, result[x]) and
                    (re.search(re_ipaddress, result[x + 1]) or
                    re.search(re_ipaddress, result[x + 2]))):
                    matchs = re.search(re_filter, result[x])
                    (parent, priority, classifier, handle) = matchs.groups()
                    real_filters.append(
                        RealFilter(parent, int(priority), classifier, handle))
            except Exception, err:
                break
        return real_filters

    def delete_filter(self, ipaddress, save=True):
        '''
        destroy a single filter
        # tc filter del dev eth0 parent 1:0 prio 2 handle 800::801 u32
        '''
        self.logger.debug('delete filter ip: %s rate' % (ipaddress))
        for ifname in self.nics:
            real_filters = self.search_real_filter(ifname, ipaddress)
            for real_filter in real_filters:
                # destroy a filter
                call('/sbin/tc filter del dev %s parent %s prio %d '
                        'handle %s %s' % (ifname, real_filter.parent,
                            real_filter.priority, real_filter.handle,
                            real_filter.classifier),
                    shell=True, stderr=STDOUT, stdout=None)
        try:
            del(self.filters[ipaddress])
        except Exception, err:
            pass
        if save:
            self.save_filter(self.filters)
        return

    def show_filter(self, ipaddress):
        self.logger.debug('show filter %s' % (ipaddress))
        utils.check_ip(ipaddress)
        if ipaddress in self.filters:
            filter_rule = self.filters[ipaddress]
            flowid = filter_rule.flowid
            ifname = filter_rule.ifname
            rate = filter_rule.rate
            print('ifname: %s, ip: %s, priority: %s, rate: %s, flowid: %s'
                % (ifname, ipaddress, self.priority, rate, flowid))
        else:
            print("no such filter %s" % (ipaddress))
        return

    def show_all_filter(self):
        self.logger.debug('show all filters')
        for ipaddress in self.filters:
            self.show_filter(ipaddress)
        return

    def reload(self):
        rates = self.load_rate()
        for ifname in self.nics:
            self._init_root_rule(ifname)
            for rate in rates:
                class_id = rates[rate]
                self.add_class(ifname, rate, class_id)
        for ipaddress in self.filters:
            filter_rule = self.filters[ipaddress]
            ifname = filter_rule.ifname
            rate = filter_rule.rate
            self.add_filter(ipaddress, ifname, rate, save=False)
        return

    def _init_root_rule(self, ifname):
        try:
            # delete root qdisc
            call('/sbin/tc qdisc del dev %s root 2>/dev/null' % ifname,
                shell=True, stderr=STDOUT, stdout=None)
            # add root qdisc
            call('/sbin/tc qdisc add dev %s root handle 1:0 htb default 5'
                % ifname, shell=True, stderr=STDOUT, stdout=None)
        except Exception, err:
            exstr = traceback.format_exc()
            self.logger.error(err)
            self.logger.error(exstr)
        return


class FilterRule(object):

    def __init__(self, flowid, ifname, rate):
        self.flowid = flowid
        self.ifname = ifname
        self.rate = rate
        return


class RealFilter(object):

    def __init__(self, parent, priority, classifier, handle):
        self.parent = parent
        self.priority = priority
        self.classifier = classifier
        self.handle = handle
        return


def controller():
    """Spawn Many Commands"""
    usage = """usage: %prog [options]
        -a -n ifname -i ipaddress -r rate
        -d -i ipaddress
        -s -i ipaddress"""
    parser = OptionParser(usage=usage, version="%%prog %s" % (__version__))
    parser.add_option('-a', '--add', action='store_true', dest='add',
            help='add or replace filter')
    parser.add_option('-d', '--delete', action='store_true', dest='delete',
            help='delete filter')
    parser.add_option('-n', action="store", type="string", dest='ifname',
            help='network interface card')
    parser.add_option('-s', '--show', action='store_true', dest='show',
            help='list exist filter')
    parser.add_option('-i', action="store", type="string", dest='ipaddress',
            help='ipaddress')
    parser.add_option('-R', action='store_true', dest='reload',
            help='reload config')
    parser.add_option('-r', '--rate', action="store", type='int', dest='rate',
            help='limit rate in mbit')
    parser.set_defaults(rate=1)
    (options, args) = parser.parse_args()
    traffic_control = TrafficControl()
    traffic_control.reload()
    if options.add and options.ipaddress and options.rate and options.ifname:
        rate = str(int(options.rate)) + "Mbit"
        traffic_control.add_filter(options.ipaddress, options.ifname, rate)
    elif options.delete and options.ipaddress:
        traffic_control.delete_filter(options.ipaddress)
    elif options.show == True and options.ipaddress:
        traffic_control.show_filter(options.ipaddress)
    elif options.show == True:
        traffic_control.show_all_filter()
    elif options.reload == True:
        traffic_control.reload()
    else:
        parser.print_help()
        sys.exit(1)


def main():
    controller()


if __name__ == "__main__":
    sys.exit(main())
