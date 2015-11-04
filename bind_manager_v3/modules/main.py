#!/usr/bin/env python2

from flask import Response
from dns import query, zone, rdtypes, rdatatype, rdataclass, rdata, update, tsigkeyring
import dns.query
import dns.message
import dns.rdatatype
import dns.rdata
import dns.rdtypes
import dns.tsigkeyring
import dns.update

from .models import *
import urllib
import IPy
import json
import re


class Usuario(UserMixin):
    def __init__(self, username, password):
        self.id = username
        self.password = password

    def is_active(self):
        return True

    @staticmethod
    def get(userid):
        # user_database = [("sbuczak","qwe123")]
        user_database = users.select().where(users.username == userid)
        for users_get in user_database:
            if users_get.username == userid:
                return Usuario(users_get.username, users_get.password)
        return None


def get_zone_changes(zona):
    """ Get the list of modifications in queue """
    modlist = []
    for item in zones.select().where(zones.zone == zona):
        zona_id = item.id
    for mod in change_cache.select().where(change_cache.zone_id == zona_id):
        # safeurl_data = urllib.quote_plus(mod.data)
        modlist.append({'id': mod.id,
                        'username': mod.username,
                        'rr': mod.rr,
                        'zone_id': mod.zone_id,
                        'type': mod.type,
                        'ttl': mod.ttl,
                        'data': mod.data,
                        'action': mod.action})
    return modlist


def mod_change_cache(zona=None, rr=None, rtype=None, ttl=1800, data=None, action=None, username=None, del_id=None, operation=None):
    """Modify the publish queue"""
    zone_id = zones.select().where(zones.zone == zona).get()
    if rtype == "A" or rtype == "NS":
        try:
            IPy.parseAddress(data)
        except ValueError:
            return False

    if operation == "add_unpub":
        for item in [zona, rr, rtype, ttl, data, action, operation]:
            if item is None:
                return False

        if change_cache.select().where(change_cache.rr == rr,
                                       change_cache.zone_id == zone_id,
                                       change_cache.type == rtype,
                                       change_cache.data == data,
                                       change_cache.action == "add").count():
                return True
        change_cache.create(username=username,
                            rr=rr,
                            zone_id=zone_id,
                            type=rtype,
                            ttl=ttl,
                            data=data,
                            action=action)
        return True

    elif operation == "del_unpub":
        delete_query = change_cache.delete().where((change_cache.id == del_id) & (change_cache.zone_id == zone_id))
        delete_query.execute()
        return True


def get_view_server(view=None):
    """ Gets the view's master server """
    if view is not None:
        view_server = views.select().where(views.name == view).get()
        return view_server.server


def get_view_key(view=None):
    """ Gets the view's tsig key """
    if view is not None:
        view_server = views.select().where(views.name == view).get()
        view_key_dict = {str(view_server.tsig_key).split(" ", 1)[0]: str(view_server.tsig_key).split(" ", 1)[1]}
        return view_key_dict


def get_zone_view(zone=None):
    """ Gets the zone's view """
    if zone is not None:
        zone_view = zones.select().where(zones.zone == zone).get()
        return zone_view.view


def get_zone_id(zone=None):
    """ Gets zone id """
    if zone is not None:
        zone_get = zones.select().where(zones.zone == zone).get()
        return zone_get.id

def get_zone_name(zone_id=None):
    """ Gets zone name from id """
    if zone is not None:
        zone_get = zones.select().where(zones.id == zone_id).get()
        return zone_get.zone

def get_zone_pools(zone=None):
    """ Get zone Pools """
    if zone is not None:
        zone_id = get_zone_id(zone=zone)
        pool_get = pools.select().where(pools.zone == zone)
        for item in pool_get:
            print item
        return ""

def get_user_permissions(user=None):
    """ Gets permissions for user """
    if user is not None:
        return_list = []
        user_query = users.select().where(users.username == user).get()
        for item in permissions.select().where(permissions.user_id == user_query.id):
            return_list.append(item.zone_id)
        return return_list


def get_user_list():
    """ Get user list """
    return_list = []
    list_query = users.select()
    for item in list_query:
        return_list.append({'id': item.id,
                           'username': item.username})
    return return_list


def get_user_role(user=None):
    """ Gets role for user """
    if user is not None:
        role_query = roles.select(roles.role).where(roles.user == user).get()
        return role_query.role


def get_zone_list(username=None):
    """ Gets zone list """
    if username is not None:
        zone_list = []
        authorized_zone_list = get_user_permissions(username)
        for zone in zones.select().order_by(zones.zone):
            if zone.id in authorized_zone_list:
                change_qty = change_cache.select().where(change_cache.zone_id == zone.id).count()
                zone_list.append({'id': zone.id,
                                  'name': zone.zone,
                                  'view': zone.view,
                                  'change_qty': change_qty})
        return zone_list
    return []

#


def api_response(dictionary=None):
    """ Return dictionary as a json Response object """
    if dictionary is not None:
        return Response(json.dumps(dictionary, indent=4, sort_keys=True), mimetype="application/json")


def search_record(record=None, user=None):
    for zone_id in get_user_permissions(user=user):
        zone_name = get_zone_name(zone_id=zone_id)
        pattern = re.compile("^[(\w+).](\w+).%s" % zone_name)
        result = {}
        if pattern.match(record):
            zone_view = get_zone_view(zone=zone_name)
            master = get_view_server(view=zone_view)
            dns_query = dns.message.make_query(record, dns.rdatatype.ANY)
            dns_response = dns.query.tcp(dns_query, str(master), timeout=10)
            if dns_response is not None:
                for record in dns_response.answer:
                    record_items = str(record).split(" ")
                    result[zone_name] = {'rr': record_items[0],
                                         'data': record_items[4],
                                         'type': record_items[3],
                                         'ttl': record_items[1]}
            return result
