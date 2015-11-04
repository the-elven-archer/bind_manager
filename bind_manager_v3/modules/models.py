#!/usr/bin/env python2

from peewee import *
from flask.ext.login import UserMixin

db = "bind_manager_v3"
db_user = "bind_manager"
db_passwd = "password"
db_host = "localhost"


mysql_db = MySQLDatabase(db, user=db_user, passwd=db_passwd, host=db_host)


class DBModel(Model):
    class Meta:
        database = mysql_db


class zones(DBModel):
    id = IntegerField(index=True, primary_key=True, null=False)
    zone = CharField()
    view = CharField()


class change_cache(DBModel):
    id = IntegerField(index=True, primary_key=True, null=False)
    username = CharField(null=False)
    rr = CharField(null=False)
    zone_id = IntegerField(null=False)
    type = CharField(null=False)
    ttl = IntegerField(null=False)
    data = CharField(null=False)
    action = CharField(null=False)


class change_logs(DBModel):
    id = IntegerField(index=True, primary_key=True, null=False)
    action = CharField(null=False)
    username = CharField(null=False)
    date = CharField(null=False)
    message = CharField(null=False)


class pools_aa(DBModel):
    id = IntegerField(index=True, primary_key=True, null=False)
    name = CharField(null=False)
    members = CharField(null=False)
    check_type = CharField(null=False)
    check_parms = CharField(null=False)
    records = CharField(null=False)
    enabled = CharField(null=False)


class pools_ap(DBModel):
    id = IntegerField(index=True, primary_key=True, null=False)
    name = CharField(null=False)
    active = CharField(null=False)
    fallback = CharField(null=False)
    check_type = CharField(null=False)
    check_parms = CharField(null=False)
    records = CharField(null=False)
    enabled = CharField(null=False)


class users(DBModel):
    id = IntegerField(index=True, primary_key=True, null=False)
    username = CharField(null=False)
    password = CharField(null=False)


class config(DBModel):
    id = IntegerField(index=True, primary_key=True, null=False)
    item = CharField(null=False)
    value = CharField(null=False)


class views(DBModel):
    id = IntegerField(index=True, primary_key=True, null=False)
    name = CharField(null=False)
    server = CharField(null=False)
    tsig_key = CharField(null=False)


class permissions(DBModel):
    id = IntegerField(index=True, primary_key=True, null=False)
    user_id = IntegerField(null=False)
    zone_id = IntegerField(null=False)


class roles(DBModel):
    id = IntegerField(index=True, primary_key=True, null=False)
    user = CharField(null=False)
    role = CharField(null=False)

class pools(DBModel):
    id = IntegerField(index=True, primary_key=True, null=False)
    zone = CharField(null=False)
    rr = CharField(null=False)
    active = CharField(null=False)
    fallback = CharField(null=False)
    check_type = CharField(null=False)
    check_parms = CharField(null=False)
    enabled = CharField(null=False)
