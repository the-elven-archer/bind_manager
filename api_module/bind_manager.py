#!/usr/bin/env python2

import requests
import json


class BindManager:

    def __init__(self, base_url):
        self.req = requests
        self.base_url = base_url
        self.cookies = dict()
        self.headers = {'content-type': 'application/json'}

    def login(self, username, password):
        """ Login function """
        self.user = username
        self.passw = password

        json_users = json.dumps({"username": self.user,
                                 "password": self.passw})
        user_request = self.req.post("%s/login" % self.base_url,
                                     data=json_users,
                                     headers=self.headers,
                                     cookies=self.cookies)
        self.cookies = user_request.cookies
        reply = json.loads(user_request.json())
        if reply['login'] == "OK":
            return True
        else:
            return False

    def get_zones(self):
        """ Get zone list """
        zone_request = self.req.get("%s/api/zones" % self.base_url,
                                    headers=self.headers,
                                    cookies=self.cookies)
        reply = json.loads(json.dumps(zone_request.json()))
        return reply['zones']

    def get_zone_data(self, zone):
        """ Get zone records """
        if zone is not None:
            zone_data_request = self.req.get("%s/api/zones/%s" % (self.base_url, zone),
                                             headers=self.headers,
                                             cookies=self.cookies)
            reply = json.loads(json.dumps(zone_data_request.json()))
            return reply['data']

    def get_queues(self):
        """ Get queue list """
        queue_request = self.req.get("%s/api/queues" % self.base_url,
                                     headers=self.headers,
                                     cookies=self.cookies)
        reply = json.loads(json.dumps(queue_request.json()))
        return reply['queues']

    def get_queue_data(self, zone):
        """ Get modification queue for zone """
        if zone is not None:
            queue_data_request = self.req.get("%s/api/queues/%s" % (self.base_url, zone),
                                              headers=self.headers,
                                              cookies=self.cookies)
            reply = json.loads(json.dumps(queue_data_request.json()))
            return reply
