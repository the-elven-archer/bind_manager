#!/usr/bin/env python2

from flask import Flask, render_template, request, session, url_for, redirect, g, jsonify, json, Response
from flask.ext.login import *
from flask.ext.login import login_required, login_user, logout_user, current_user
import urllib

from modules.models import zones
from modules.main import *
from modules.dns_tools import *

app = Flask(__name__)
app.debug = True
app.secret_key = "FiThaeHoozee6veishah"

dns_object = dns_utils()

#
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
#


@login_manager.user_loader
def load_user(userid):
    return Usuario.get(userid)


####


@app.before_request
def before_request():
    mysql_db.connect()


@app.after_request
def after_request(response):
    mysql_db.close()
    return response


####
@app.route("/")
@login_required
def index():
    zone_qty = zones.select().count()
    return render_template("index.html",
                           username=current_user.get_id(),
                           zone_qty=zone_qty)


#
@app.route("/login", methods=['GET', 'POST'])
def login():
    if request.method == "GET":
        return render_template('login.html')
    elif request.method == "POST":
        if request.content_type == "application/json":
            json_login_data = request.json
            username = json_login_data.get("username")
            password = json_login_data.get("password")
        else:
            username = request.form['username']
            password = request.form['password']
        registered_user = Usuario.get(username)
        if registered_user and password == registered_user.password:
            if request.content_type == "application/json":
                login_user(registered_user, remember=True)
                session['username'] = username
                return api_response('{"login": "OK"}')
            else:
                login_user(registered_user, remember=False)
                session['username'] = username
                session['role'] = get_user_role(username)
                return redirect(request.args.get('next') or url_for('index'))
        else:
            if request.content_type == "application/json":
                return api_response('{"login": "ERROR"}'), 403
            else:
                return render_template('login.html', alert="error")


@app.route("/logout")
def logout():
    logout_user()
    try:
        #del(session['authorized_zone_list'])
        #del(session['username'])
        session.clear()
        return redirect(url_for("index"))
    except:
        print "Todo mal"
        pass
    return redirect(url_for("index"))
###


@app.route("/list")
@login_required
def list():
    zone_list = get_zone_list(username=session['username'])
    return render_template("list.html",
                           title="Zone list",
                           zone_list=zone_list)


###
@app.route("/config", methods=['GET', 'POST'])
@login_required
def config():
    if request.method == "GET":
        return render_template("config.html",
                               title="Config for %s" % (session['username']))
    elif request.method == "POST":
        alert = ""
        if request.form['operation'] == "change_password":
            if request.form['confirm_password'] is "" or request.form['new_password'] is "":
                alert = "blank"
            elif request.form['confirm_password'] != request.form['new_password']:
                alert = "mismatch"
            elif request.form['confirm_password'] == request.form['new_password']:
                query = users.update(password=request.form['new_password']).where(users.username == session['username'])
                query.execute()
                alert = "password_changed"

        return render_template("config.html",
                               title="Config for %s" % (session['username']),
                               alert=alert)

###
@app.route("/admin", methods=['GET', 'POST'])
@login_required
def admin():
    if request.method == "GET":
        return render_template("admin.html",
                               title="Administration Page",
                               user_list=get_user_list(),
                               zone_list=get_zone_list(session['username']))
    if request.method == "POST":
        if request.form['operation'] == "add_user":
            if request.form['new_password'] == request.form['confirm_password']:
                users.create(username=request.form['username'],
                             password=request.form['new_password'])
                roles.create(user=request.form['username'],
                             role="user")

        return render_template("admin.html",
                               title="Administration Page",
                               user_list=get_user_list(),
                               zone_list=get_zone_list(username=session['username']))


###
@app.route("/zone/<zona>", methods=['GET', 'POST'])
@login_required
def get_zone_transfer(zona=None):

    master_server = get_view_server(get_zone_view(zona))
    result = False
    publishing = False

    ###
    if not any(dictionary['name'] == zona for dictionary in get_zone_list(session['username'])):
        return redirect(url_for('index'))
    ###
    if request.method == "POST":
        if request.form["operation"] == "add_unpub":
            mod_change_cache(zona=zona,
                             rr=request.form['rr'],
                             rtype=request.form['type'],
                             ttl=request.form['ttl'],
                             data=request.form['data'],
                             action=request.form['action'],
                             username=session['username'],
                             operation=request.form['operation'])
            result = True
        elif request.form["operation"] == "del_unpub":
            mod_change_cache(zona=zona,
                             del_id=request.form['del_id'],
                             action=request.form['action'],
                             operation=request.form['operation'])
            result = True
        elif request.form["operation"] == "publish":
            publishing = dns_object.process_dns_queue(user=session['username'],
                                                      zone=zona,
                                                      view=get_zone_view(zona))

    ###
    return_list = dns_object.get_transfer(master_server, zona)
    mod_list = get_zone_changes(zona)
    return render_template("zona.html",
                           modlist=mod_list,
                           zona=zona,
                           title=zona,
                           result=result,
                           publishing=publishing,
                           record_list=return_list)

@app.route("/pools", methods=['GET', 'POST'])
@login_required
def pools():
    return render_template("pools.html")


###############################################################################
@app.route("/api/zones", methods=['GET'])
@login_required
def api_zones():
    if request.content_type == "application/json":

        if request.method == "GET":
            return_dict = {'zones': get_zone_list(session['username'])}
            return api_response(return_dict)


@app.route("/api/zones/<zona>", methods=['GET', 'POST', 'PUT', 'DELETE'])
@login_required
def api_zone_get(zona):
    if request.content_type == "application/json":
        if not any(dictionary['name'] == zona for dictionary in get_zone_list(session['username'])):
            return api_response({'error': 'Denied'}), 403
        # working_dict = get_zone_list(session['username'])
        master_server = get_view_server(get_zone_view(zona))
        # zone_data = filter(lambda zona_found: zona_found['name'] == zona, working_dict)

        if request.method == "GET":
            zone_transfer = dns_object.get_transfer(master_server, zona)
            transfer_cleaning = filter(lambda transfer_record: transfer_record.pop("data", None), zone_transfer)
            transfer_cleaning = filter(lambda transfer_record: transfer_record.pop("id", None), transfer_cleaning)
            # return_dict = {'zone': zone_data, 'data': transfer_cleaning}
            return_dict = {'data': transfer_cleaning}
            return api_response(return_dict)


@app.route("/api/queues", methods=['GET'])
@login_required
def api_queues():
    if request.content_type == "application/json":
        if request.method == "GET":
            changes_dict = []
            for zone in get_zone_list(session['username']):
                if zone['change_qty'] > 0:
                    changes_dict.append(zone)
            return_dict = {'queues': changes_dict}
            return api_response(return_dict), 200


@app.route("/api/queues/<zona>", methods=['GET', 'POST', 'PUT', 'DELETE'])
@login_required
def api_queue_get(zona):
    if request.content_type == "application/json":
        if not any(dictionary['name'] == zona for dictionary in get_zone_list(session['username'])):
            return api_response({'error': 'Denied'}), 403

        if request.method == "GET":
            mod_list = get_zone_changes(zona)
            return_dict = {zona:  mod_list}
            return api_response(return_dict)

        elif request.method == "PUT":
            json_data = request.json
            for item in ['action', 'data', 'ttl', 'type']:
                if not json_data.get(item):
                    return api_response({'error': 'missing parameter %s' % item})
            mod_change_cache(zona=zona,
                             rr=json_data.get("rr"),
                             rtype=json_data.get("type"),
                             ttl=json_data.get("ttl"),
                             data=json_data.get("data"),
                             action=json_data.get("action"),
                             username=session['username'],
                             operation="add_unpub")
            return_dict = {"add": json_data}
            return api_response(return_dict), 201

        elif request.method == "DELETE":
            json_data = request.json
            for item in ['id']:
                if not json_data.get(item):
                    return api_response({'error': 'missing parameter %s' % item})
            mod_change_cache(zona=zona,
                             del_id=json_data.get("id"),
                             operation="del_unpub")
            return_dict = {"del": {"id": json_data.get("id"), "zone": zona}}
            return api_response(return_dict), 200

        elif request.method == "POST":
            if get_zone_changes(zona):
                publishing = dns_object.process_dns_queue(user=session['username'],
                                                          zone=zona,
                                                          view=get_zone_view(zona))
            else:
                publishing = False
            return_dict = {"publish": publishing}
            return api_response(return_dict)

@app.route("/api/record", methods=['GET', 'POST'])
@login_required
def api_record():
    if request.content_type == "application/json":
        json_data = request.json
        for item in ['record']:
            if not json_data.get(item):
                return api_response({'error': 'missing parameter %s' % item})
        record_list = search_record(record=json_data.get('record'), user=session['username'])
        if record_list is not None:
            return api_response(record_list)
        else:
            return api_response("{}")
