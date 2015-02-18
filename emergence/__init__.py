# -*- coding: utf-8 -*-
"""
pyapi-emergence. A Python wrapper for the Emergence Lab API.
"""

import os
import requests
import json

from requests.packages.urllib3.exceptions import InsecureRequestWarning


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
        if not verify_ssl:
            requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

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
        response = requests.get(url, headers=self.headers,
                                verify=self.verify_ssl)
        if response.status_code == 200:
            return json.loads(response.content)
        else:
            return False

    def download_media_file(self, path, output_dir):
        """
        Downloads media file from specified path

        :param path: path to file from Emergence
        :param output_dir: path to save the file
        """
        url = self.api_url + '/utility/media' + path
        response = requests.get(url, headers=self.headers,
                                verify=self.verify_ssl)
        output_file_name = path.split('/')[-1]
        if not output_file_name:
            raise NameError('Path returns empty string')
        if response.status_code == 200:
            with open(os.path.join(output_dir, output_file_name), 'wb+') as f:
                for block in response.iter_content(1024):
                    if not block:
                        break
                    f.write(block)
                    f.close
            return True
        else:
            return False

    def get_media_file(self, path):
        """
        Returns media file from specified path for manipulation

        :param path: path to file from Emergence
        """
        url = self.api_url + '/utility/media' + path
        response = requests.get(url, headers=self.headers,
                                verify=self.verify_ssl)
        if response.status_code == 200:
            #with open(os.path.join(output_dir, output_file_name), 'wb+') as f:
            #    for block in response.iter_content(1024):
            #        if not block:
            #            break
            #        f.write(block)
            #        f.close
            return ''.join([block for block in response.iter_content(1024)])
        else:
            return False

    def get_substrate_list(self):
        """
        Returns a lit of substrates and associated details
        """
        url = self.api_url + '/sample/substrate'
        response = requests.get(url, headers=self.headers,
                                verify=self.verify_ssl)
        if response.status_code == 200:
            return json.loads(response.content)
        else:
            return False

    def get_sample_list(self):
        """
        Returns a list of samples and associated details
        """
        url = self.api_url + '/sample'
        response = requests.get(url, headers=self.headers,
                                verify=self.verify_ssl)
        if response.status_code == 200:
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
        response = requests.get(url, headers=self.headers,
                                verify=self.verify_ssl)
        if response.status_code == 200:
            return json.loads(response.content)
        else:
            return False

    def get_process_list(self):
        """
        Returns a list of processes and generic details
        """
        url = self.api_url + '/process'
        response = requests.get(url, headers=self.headers,
                                verify=self.verify_ssl)
        if response.status_code == 200:
            return json.loads(response.content)
        else:
            return False

    def get_process(self, uuid):
        """
        Show details of a specific process specified by uuid.

        :param uuid: UUID of process
        """
        url = self.api_url + '/process/{}'.format(uuid)
        response = requests.get(url, headers=self.headers,
                                verify=self.verify_ssl)
        if response.status_code == 200:
            return json.loads(response.content)
        else:
            return False

    def get_process_node(self, uuid):
        """
        Show details of a specific process node specified by uuid.

        :param uuid: UUID of process node.
        """
        url = self.api_url + '/process/node/{}'.format(uuid)
        response = requests.get(url, headers=self.headers,
                                verify=self.verify_ssl)
        if response.status_code == 200:
            return json.loads(response.content)
        else:
            return False

    ############
    # D180 API #
    ############

    def get_growth_list(self):
        """
        Returns a list of all growths
        """
        url = self.api_url + '/d180/growths'
        response = requests.get(url, headers=self.headers,
                                verify=self.verify_ssl)
        if response.status_code == 200:
            return json.loads(response.content)
        else:
            return False

    def create_growth(self, data):
        """
        Create a growth via API

        :param data: JSON dump of data fields for growth model
        """
        url = self.api_url + '/d180/growths'
        response = requests.post(url, data, headers=self.headers,
                                 verify=self.verify_ssl)
        if response.status_code == 201:
            return True
        else:
            return False

    def get_growth(self, pk):
        """
        Show details of a specific growth specified by growth PK

        :param pk: ID of growth in database
        """
        url = self.api_url + '/d180/growths/{}'.format(pk)
        response = requests.get(url, headers=self.headers,
                                verify=self.verify_ssl)
        if response.status_code == 200:
            return json.loads(response.content)
        else:
            return False

    def update_growth(self, pk, data):
        """
        Update parameters of a specific growth specified by growth PK
        Only updated parameters should be included in data object
        NB this method uses an HTTP PATCH request, which should be formatted
        as a list with a single object, where the object is a dictionary of values
        to update.

        :param pk: ID of growth in database
        :param data: Single-item List with dict of updated data fields from growth model
        """
        url = self.api_url + '/d180/growths/{}'.format(pk)
        response = requests.patch(url, data, headers=self.headers,
                                  verify=self.verify_ssl)
        if response.status_code == 200:
            return True
        else:
            return False

    def latest_growth(self):
        """
        Returns details of the latest growth.
        """
        url = self.api_url + '/d180/growths/latest'
        response = requests.get(url, headers=self.headers,
                                verify=self.verify_ssl)
        if response.status_code == 200:
            return json.loads(response.content)
        else:
            return False

    def get_readings_list(self):
        """
        Returns a list of all readings for D180 growths
        """
        url = self.api_url + '/d180/readings'
        response = requests.get(url, headers=self.headers,
                                verify=self.verify_ssl)
        if response.status_code == 200:
            return json.loads(response.content)
        else:
            return False

    def create_readings(self, data):
        """
        Create a reading via API

        :param data: JSON dump of data fields for readings model
        """
        url = self.api_url + '/d180/readings'
        response = requests.post(url, data, headers=self.headers,
                                 verify=self.verify_ssl)
        if response.status_code == 201:
            return True
        else:
            return False

    def get_readings(self, pk):
        """
        Show details of a specific reading set specified by readings PK

        :param pk: ID of readings set in database
        """
        url = self.api_url + '/d180/readings/{}'.format(pk)
        response = requests.get(url, headers=self.headers,
                                verify=self.verify_ssl)
        if response.status_code == 200:
            return json.loads(response.content)
        else:
            return False

    def update_readings(self, pk, data):
        """
        Update parameters of a specific reading set specified by reading set PK
        Only updated parameters should be included in data object
        NB this method uses an HTTP PATCH request, which should be formatted
        as a list with a single object, where the object is a dictionary of values
        to update.

        :param pk: ID of readings set in database
        :param data: Single-item List with dict of updated data fields from readings model
        """
        url = self.api_url + '/d180/readings/{}'.format(pk)
        response = requests.patch(url, data, headers=self.headers,
                                  verify=self.verify_ssl)
        if response.status_code == 200:
            return True
        else:
            return False

    ###########
    # AFM API #
    ###########

    def get_afm_list(self):
        """
        Returns a list of all AFM scans
        """
        url = self.api_url + '/afm'
        response = requests.get(url, headers=self.headers,
                                verify=self.verify_ssl)
        if response.status_code == 200:
            return json.loads(response.content)
        else:
            return False

    def create_afm(self, data):
        """
        Create an AFM scan via API

        :param data: JSON dump of data fields for AFM model
        """
        url = self.api_url + '/afm'
        response = requests.post(url, data, headers=self.headers,
                                 verify=self.verify_ssl)
        if response.status_code == 201:
            return True
        else:
            return False

    def get_afm(self, pk):
        """
        Show details of a specific AFM specified by AFM PK

        :param pk: ID of AFM in database
        """
        url = self.api_url + '/afm/{}'.format(pk)
        response = requests.get(url, headers=self.headers,
                                verify=self.verify_ssl)
        if response.status_code == 200:
            return json.loads(response.content)
        else:
            return False

    def update_afm(self, pk, data):
        """
        Update parameters of a specific AFM specified by AFM PK
        Only updated parameters should be included in data object
        NB this method uses an HTTP PATCH request, which should be formatted
        as a list with a single object, where the object is a dictionary of values
        to update.

        :param pk: ID of AFM in database
        :param data: Single-item List with dict of updated data fields from AFM model
        """
        url = self.api_url + '/afm/{}'.format(pk)
        response = requests.patch(url, data, headers=self.headers,
                                  verify=self.verify_ssl)
        if response.status_code == 200:
            return True
        else:
            return False

    ###########
    # SEM API #
    ###########

    def get_sem_list(self):
        """
        Returns a list of all SEM scans
        """
        url = self.api_url + '/sem'
        response = requests.get(url, headers=self.headers,
                                verify=self.verify_ssl)
        if response.status_code == 200:
            return json.loads(response.content)
        else:
            return False

    def create_sem(self, data):
        """
        Create an SEM scan via API

        :param data: JSON dump of data fields for SEM model
        """
        url = self.api_url + '/sem'
        response = requests.post(url, data, headers=self.headers,
                                 verify=self.verify_ssl)
        if response.status_code == 201:
            return True
        else:
            return False

    def get_sem(self, pk):
        """
        Show details of a specific SEM specified by SEM PK

        :param pk: ID of SEM in database
        """
        url = self.api_url + '/sem/{}'.format(pk)
        response = requests.get(url, headers=self.headers,
                                verify=self.verify_ssl)
        if response.status_code == 200:
            return json.loads(response.content)
        else:
            return False

    def update_sem(self, pk, data):
        """
        Update parameters of a specific SEM specified by SEM PK
        Only updated parameters should be included in data object
        NB this method uses an HTTP PATCH request, which should be formatted
        as a list with a single object, where the object is a dictionary of values
        to update.

        :param pk: ID of SEM in database
        :param data: Single-item List with dict of updated data fields from SEM model
        """
        url = self.api_url + '/sem/{}'.format(pk)
        response = requests.patch(url, data, headers=self.headers,
                                  verify=self.verify_ssl)
        if response.status_code == 200:
            return True
        else:
            return False
