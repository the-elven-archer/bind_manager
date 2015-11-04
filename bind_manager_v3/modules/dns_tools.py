#!/usr/bin/env python2

import dns.query
import dns.zone
import dns.rdtypes
import dns.rdatatype
import dns.rdataclass
import dns.rdata
import dns.update
import dns.tsigkeyring
import IPy

import urllib
from operator import itemgetter
import time
from .models import *
from .main import *


class dns_utils():
    def __init__(self):
        pass

    def get_transfer(self, master, zone):
        """ Get the zone AXFR """
        lista = []
        try:
            zone_xfr = dns.zone.from_xfr(dns.query.xfr(master, zone, relativize=False), relativize=False)
            for name, node in zone_xfr.nodes.items():
                rdatasets = node.rdatasets
                for rdataset in rdatasets:
                    for rdata in rdataset:
                        lista.append({'name': name.to_text(),
                                      'id': id,
                                      'type': dns.rdatatype.to_text(rdataset.rdtype),
                                      'ttl': rdataset.ttl,
                                      'data': rdata,
                                      'urlsafe_data': urllib.quote_plus(str(rdata))})
            lista.sort(key=itemgetter('name'), reverse=False)
            return lista
        except dns.exception.FormError:
            return None

    def process_dns_queue(self, user=None, zone=None, view=None):
        """ Process the list for the user and adds/removes DNS records """
        # Getting key from view
        tsigkey = get_view_key(view)
        master = get_view_server(view)
        zona = zones.select().where(zones.zone == zone).get()
        update_list = change_cache.select().where(change_cache.zone_id == zona.id,
                                                  change_cache.username == user)

        dns_keyring = dns.tsigkeyring.from_text(tsigkey)
        dns_update = dns.update.Update(zone, keyring=dns_keyring)
        for modification in update_list:
            if modification.rr:
                update_fqdn = "%s.%s." % (modification.rr, zone)
            else:
                update_fqdn = "%s." % (zone)

            print modification.rr
            print zone
            if modification.action == "add":
                dns_update.add(update_fqdn,
                               modification.ttl,
                               str(modification.type),
                               str(modification.data))
                change_logs.create(action="add",
                                   username=user,
                                   date=time.strftime("%c"),
                                   message="Zone %s - Add %s %s -> %s" % (zone,
                                                                          str(update_fqdn),
                                                                          str(modification.type),
                                                                          str(modification.data)))

            elif modification.action == "del":
                dns_update.delete(modification.rr,
                                  str(modification.type),
                                  str(modification.data))
                change_logs.create(action="delete",
                                   username=user,
                                   date=time.strftime("%c"),
                                   message="Zone %s - Del %s %s -> %s" % (zone,
                                                                          str(modification.rr),
                                                                          str(modification.type),
                                                                          str(modification.data)))
            # Clean queue
            delete_query = change_cache.delete().where(change_cache.id == modification.id)
            delete_query.execute()

        dns_response = dns.query.tcp(dns_update, master)
        return True
