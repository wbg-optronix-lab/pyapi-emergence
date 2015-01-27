# -*- coding: utf-8 -*-
"""
pyapi-emergence. A Python wrapper for the Emergence Lab API.
"""

import requests
import json


class Emergence(object):
    """
    Main class
    """

    def __init__(self, host, token="", verify_ssl=True):
        """
        Sets up default connection parameters for the API
        """
        if token != "":
            self.token = token
            self.headers = {'content-type': 'application/json',
                            'Authorization': 'Token {}'.format(self.token)}
        if not host:
            raise ValueError('Host arguement must not be empty')
        if host[-1] == '/':
            self.host = host[:-1]
        else:
            self.host = host
        if self.host[:7] == 'http://' or self.host[:8] == 'https://':
            pass
        else:
            self.host = 'https://' + self.host

        self.verify_ssl = verify_ssl
        self.api_url = self.host + '/api/v0'

    #def login(self, user=None, password=None):
    #    """
    #    Login to the instance of emergence and get token if not provided.
    #
    #    :param user: Username of Emergence user, ie. from LDAP
    #    :param password: Password for the user, ie. LDAP password
    #    :return: True if login is successful
    #    """
    #    CURRENTLY NOT SUPPORTED BY SW: TOKEN LOGIN ONLY #

    ############
    # CORE API #
    ############

    def get_users(self):
        """
        Returns a list of users in the instance
        """
        url = self.api_url + '/users'
        response = requests.get(url, headers=self.headers)
        if response.status_code == 200:
            return json.loads(response.content)
        else:
            return False

    def get_substrate_list(self):
        """
        Returns a lit of substrates and associated details
        """
        url = self.api_url + '/sample/substrate'
        response = requests.get(url, headers=self.headers)
        if response.status_code ==200:
            return json.loads(response.content)
        else:
            return False

    def get_sample_list(self):
        """
        Returns a list of samples and associated details
        """
        url = self.api_url + '/sample'
        response = requests.get(url, headers=self.headers)
        if response.status_code ==200:
            return json.loads(response.content)
        else:
            return False

    def get_sample(self, uuid):
        """
        Show details for a specific sample specified by uuid.
        Does not retrieve full process tree.

        :param uuid: UUID of sample
        """
        url = self.api_url + '/sample/{}'.format(uuid)
        response = requests.get(url, headers=self.headers)
        if response.status_code ==200:
            return json.loads(response.content)
        else:
            return False

    def get_process_list(self):
        """
        Returns a list of processes and generic details
        """
        url = self.api_url + '/process'
        response = requests.get(url, headers=self.headers)
        if response.status_code ==200:
            return json.loads(response.content)
        else:
            return False

    def get_process(self, uuid):
        """
        Show details of a specific process specified by uuid.

        :param uuid: UUID of process
        """
        url = self.api_url + '/process/{}'.format(uuid)
        response = requests.get(url, headers=self.headers)
        if response.status_code ==200:
            return json.loads(response.content)
        else:
            return False

    def get_process_node(self, uuid):
        """
        Show details of a specific process node specified by uuid.

        :param uuid: UUID of process node.
        """
        url = self.api_url + '/process/node/{}'.format(uuid)
        response = requests.get(url, headers=self.headers)
        if response.status_code ==200:
            return json.loads(response.content)
        else:
            return False

