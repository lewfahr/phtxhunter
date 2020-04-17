#!/usr/bin/python
# -*- coding: utf-8 -*-
# -----------------------------------------
# Phantom sample App Connector python file
# -----------------------------------------

# Python 3 Compatibility imports
from __future__ import print_function, unicode_literals

# Phantom App imports
import phantom.app as phantom
from phantom.base_connector import BaseConnector
from phantom.action_result import ActionResult

# Usage of the consts file is recommended
# from txhunter_consts import *
import requests
import json
import time
import re
import uuid
import winrm
from bs4 import BeautifulSoup


class RetVal(tuple):

    def __new__(cls, val1, val2=None):
        return tuple.__new__(RetVal, (val1, val2))


class TxhunterConnector(BaseConnector):

    def __init__(self):

        # Call the BaseConnectors init first
        super(TxhunterConnector, self).__init__()

        self._state = None

        # Variable to hold a base_url in case the app makes REST calls # Do note that the app json defines the asset config, so please # modify this as you deem fit.
        self._base_url = None

    def _process_empty_response(self, response, action_result):
        if response.status_code == 200:
            return RetVal(phantom.APP_SUCCESS, {})

        return RetVal(
            action_result.set_status(
                phantom.APP_ERROR, "Empty response and no information in the header"
            ), None
        )

    def _process_html_response(self, response, action_result):
        # An html response, treat it like an error
        status_code = response.status_code

        try:
            soup = BeautifulSoup(response.text, "html.parser")
            error_text = soup.text
            split_lines = error_text.split('\n')
            split_lines = [x.strip() for x in split_lines if x.strip()]
            error_text = '\n'.join(split_lines)
        except:
            error_text = "Cannot parse error details"

        message = "Status Code: {0}. Data from server:\n{1}\n".format(status_code, error_text)

        message = message.replace(u'{', '{{').replace(u'}', '}}')
        return RetVal(action_result.set_status(phantom.APP_ERROR, message), None)

    def _process_json_response(self, r, action_result):
        # Try a json parse
        try:
            resp_json = r.json()
        except Exception as e:
            return RetVal(
                action_result.set_status(
                    phantom.APP_ERROR, "Unable to parse JSON response. Error: {0}".format(str(e))
                ), None
            )

        # Please specify the status codes here
        if 200 <= r.status_code < 399:
            return RetVal(phantom.APP_SUCCESS, resp_json)

        # You should process the error returned in the json
        message = "Error from server. Status Code: {0} Data from server: {1}".format(
            r.status_code,
            r.text.replace(u'{', '{{').replace(u'}', '}}')
        )

        return RetVal(action_result.set_status(phantom.APP_ERROR, message), None)

    def _process_response(self, r, action_result):
        # store the r_text in debug data, it will get dumped in the logs if the action fails
        if hasattr(action_result, 'add_debug_data'):
            action_result.add_debug_data({'r_status_code': r.status_code})
            action_result.add_debug_data({'r_text': r.text})
            action_result.add_debug_data({'r_headers': r.headers})

        # Process each 'Content-Type' of response separately

        # Process a json response
        if 'json' in r.headers.get('Content-Type', ''):
            return self._process_json_response(r, action_result)

        # Process an HTML response, Do this no matter what the api talks.
        # There is a high chance of a PROXY in between phantom and the rest of
        # world, in case of errors, PROXY's return HTML, this function parses
        # the error and adds it to the action_result.
        if 'html' in r.headers.get('Content-Type', ''):
            return self._process_html_response(r, action_result)

        # it's not content-type that is to be parsed, handle an empty response
        if not r.text:
            return self._process_empty_response(r, action_result)

        # everything else is actually an error at this point
        message = "Can't process response from server. Status Code: {0} Data from server: {1}".format(
            r.status_code,
            r.text.replace('{', '{{').replace('}', '}}')
        )

        return RetVal(action_result.set_status(phantom.APP_ERROR, message), None)

    def _make_rest_call(self, endpoint, action_result, headers=None, params=None, data=None, method="get", **kwargs):
        # **kwargs can be any additional parameters that requests.request accepts

        config = self.get_config()

        resp_json = None

        try:
            request_func = getattr(requests, method)
        except AttributeError:
            return RetVal(
                action_result.set_status(phantom.APP_ERROR, "Invalid method: {0}".format(method)),
                resp_json
            )

        # Create a URL to connect to
        url = self._base_url + endpoint

        try:
            r = request_func(
                url,
                # auth=(self.username, self.password),
                json=data,
                headers=headers,
                params=params,
                verify=config.get('verify_server_cert', False),
                **kwargs
            )
        except Exception as e:
            return RetVal(
                action_result.set_status(
                    phantom.APP_ERROR, "Error Connecting to server. Details: {0}".format(str(e))
                ), resp_json
            )

        return self._process_response(r, action_result)

    def _handle_test_connectivity(self, param):
        action_result = self.add_action_result(ActionResult(dict(param)))

        self.save_progress("Connecting to endpoint")

        ret_val, response = self._make_rest_call(
            '/version', action_result
        )

        if phantom.is_fail(ret_val):
            self.save_progress("Test Connectivity Failed.")
            return action_result.get_status()

        # Return success
        self.save_progress("Test Connectivity Passed")
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_get_version(self, param):
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        action_result = self.add_action_result(ActionResult(dict(param)))

        ret_val, response = self._make_rest_call(
            '/version', action_result
        )

        if phantom.is_fail(ret_val):
            return action_result.get_status()
            pass

        action_result.add_data(response)

        return action_result.set_status(phantom.APP_SUCCESS)

    def _check_endpoint_state(self, action_result, param=None):

        endpoint = param['ip_hostname']
        self.debug_print("_check_endpoint_state ip_hostname: ", endpoint)

        params = {
                'apikey': self._apikey,
                'ip': endpoint
        }

        ret_val, response = self._make_rest_call(
            '/check_state_by_ip', action_result, params=params, method="get"
        )

        if phantom.is_fail(ret_val):
            return RetVal(action_result.get_status(), None)

        if 'success' not in response:
            return RetVal(action_result.set_status(phantom.APP_ERROR, 'Error while checking endpoint state: ("missing success in response")'), None)

        if response['success'] is False:
            if 'msg' in response:
                return RetVal(action_result.set_status(phantom.APP_ERROR, 'Error while checking endpoint state: ("{}")'.format(response['msg'])), None)
            else:
                return RetVal(action_result.set_status(phantom.APP_ERROR, 'Error while checking endpoint state: ("Unknown reason")'), None)

        return RetVal(phantom.APP_SUCCESS, response)

    def _hunt_on_permanent_agent(self, action_result, param=None):

        endpoint = param['ip_hostname']
        self.debug_print("_hunt_on_permanent_agent ip_hostname: ", endpoint)

        data = {
                'apikey': self._apikey,
                'user': self._user,
                'ip': endpoint
        }

        ret_val, response = self._make_rest_call(
            '/request_hunting_by_ip', action_result, data=data, method="post"
        )

        if phantom.is_fail(ret_val):
            return action_result.get_status()

        if 'success' not in response:
            return RetVal(action_result.set_status(phantom.APP_ERROR, 'Error while hunting on permanent agent: ("missing success in response")'), None)

        if response['success'] is False:
            if 'msg' in response:
                return RetVal(action_result.set_status(phantom.APP_ERROR, 'Error while hunting on permanent agent: ("{}")'.format(response['msg'])), None)
            else:
                return RetVal(action_result.set_status(phantom.APP_ERROR, 'Error while hunting on permanent agent: ("Unknown reason")'), None)

        if 'info' not in response:
            return RetVal(action_result.set_status(phantom.APP_ERROR, 'Error while retriving the info on permanent agent'), None)

        if 'CaseID' not in response['info']:
            return RetVal(action_result.set_status(phantom.APP_ERROR, 'Error while retriving the case id on permanent agent: ("{}")'.format(endpoint)), None)

        caseid = response['info']['CaseID']

        return RetVal(phantom.APP_SUCCESS, caseid)

    def _hunt_on_onetime_agent(self, action_result, caseid, param=None):

        self.debug_print("_hunt_on_onetime_agent caseid: ", caseid)

        if not self._init_session_to_endpoint(action_result, param):
            return action_result.get_status()
        else:
            url = ('{0}/txhunter.zip?user={1}&company={2}&none=1&silence=false&monitoring=true&apikey={3}').format(self._base_url, self._user, self._org, self._apikey)
            fdir = '%TEMP%'
            fname = 'txhunter.zip'
            fpath = ('{0}\\{1}').format(fdir, fname)

            command = ('curl -k "{0}" --output "{1}"').format(url, fpath)
            arguments = None
#            self.debug_print("cmd: ", command)
            ret_val = self._run_cmd_on_endpoint(action_result, command, arguments)
            if phantom.is_fail(ret_val):
                return ret_val

            command = ('PowerShell Expand-Archive -Path "{0}" -DestinationPath {1}\\ -Force').format(fpath, fdir)
            arguments = None
#            self.debug_print("cmd: ", command)
            ret_val = self._run_cmd_on_endpoint(action_result, command, arguments)
            if phantom.is_fail(ret_val):
                return ret_val

            command = ('{0}\\{1} /caseid:{2}').format(fdir, 'TxHunter.exe', caseid)
            arguments = None
#            self.debug_print("cmd: ", command)
            ret_val = self._run_cmd_on_endpoint(action_result, command, arguments)
            if phantom.is_fail(ret_val):
                return ret_val

        return phantom.APP_SUCCESS

    def _sc_start_tgxservice(self, action_result, param=None):

        endpoint = param['ip_hostname']
        self.debug_print("_sc_start_tgxservice ip_hostname: ", endpoint)

        if not self._init_session_to_endpoint(action_result, param):
            return action_result.get_status()
        else:
            count = 0
            while count < 3:
                count = count + 1

                self.debug_print("starting tgxservice on endpoint, wait 20s...")

                command = ('sc start {0}').format('TGXService')
                arguments = None
#                self.debug_print("cmd: ", command)
                ret_val = self._run_cmd_on_endpoint(action_result, command, arguments)
                if phantom.is_fail(ret_val):
                    return ret_val

                time.sleep( 20 )

                ret_val, response = self._check_endpoint_state(action_result, param)

                if phantom.is_fail(ret_val):
                    return action_result.get_status()

                if 'IsPermanent' in response['info'] and response['info']['IsPermanent'] is True and 'IsOnline' in response['info'] and response['info']['IsOnline'] is True:
                    return phantom.APP_SUCCESS

        return action_result.set_status(phantom.APP_ERROR, 'Error while starting tgxservice on endpoint: ("{}")'.format(endpoint))

    def _get_report_from_txserver(self, action_result, caseid, param=None):

        self.debug_print("_get_report_from_txserver caseid: ", caseid)

        ext = 'jsonex'
        params = {
                'apikey': self._apikey,
                'caseid': caseid,
                'ext': ext
        }

        count = 0
        while count < 240:
            count = count + 1

            ret_val, response = self._make_rest_call(
                '/get_summary_report', action_result, params=params, method="get"
            )

            if phantom.is_fail(ret_val):
                return action_result.get_status()

            if 'success' in response and response['success'] is False:
                self.debug_print("report is not ready, wait 30s...", caseid)
                time.sleep( 30 )
            else:
                break

        if 'Severity' not in response:
            return RetVal(action_result.set_status(phantom.APP_ERROR, 'Error while retriving the severity on case: ("{}")'.format(caseid)), None)

        return RetVal(phantom.APP_SUCCESS, response)

    def _fill_out_phantom_output(self, action_result, report, param=None):

        self.debug_print("_fill_out_phantom_output...")

        summary = action_result.update_summary({})

        if 'title' in report:
            summary['title'] = report['title']
        if 'Final Result' in report:
            summary['Final Result'] = report['Final Result']
        if 'System Critical Level(SCL)' in report:
            summary['System Critical Level(SCL)'] = report['System Critical Level(SCL)']
        if 'Conclusion' in report:
            summary['Conclusion'] = report['Conclusion']
        if 'Rate' in report:
            summary['Rate'] = report['Rate']
        if 'Severity' in report:
            summary['Severity'] = report['Severity']
#        if 'Endpoint' in report:
#            summary['Endpoint'] = report['Endpoint']

        action_result.add_data(report)

        return action_result.set_status(phantom.APP_SUCCESS)

    def _init_session_to_endpoint(self, action_result, param=None):

        endpoint = param['ip_hostname']
        self.debug_print("_init_session_to_endpoint ip_hostname: ", endpoint)

        default_port = param.get('default_port', 5985)
        default_protocol = param.get('default_protocol', 'http')

        if re.search('^[a-z]+://', endpoint, re.UNICODE | re.IGNORECASE) is None:
            endpoint = ('{0}://{1}').format(default_protocol, endpoint)
        if re.search(':\\d+$', endpoint, re.UNICODE | re.IGNORECASE) is None:
            endpoint = ('{0}:{1}').format(endpoint, default_port)

        username = param.get('username')
        password = param.get('password')
        transport = param.get('transport')
        domain = param.get('domain')

#        verify_bool = param.get('verify_server_cert', False)
#        if verify_bool:
#            verify = 'validate'
#        else:
#            verify = 'ignore'

        if transport == 'basic' or transport == 'plaintext':
            if domain:
                self.save_progress("Warning: Domain is set but transport type is set to 'basic'")
        elif transport == 'ntlm':
            if domain:
                username = ('{}\\{}').format(domain, username)
        elif transport == 'kerberos':
            return action_result.set_status(phantom.APP_ERROR, 'This transport type is not yet implemented')
        else:
            if transport == 'credssp':
                return action_result.set_status(phantom.APP_ERROR, 'This transport type is not yet implemented')
            return action_result.set_status(phantom.APP_ERROR, ('Invalid transport type: {}').format(transport))

#        self._session = winrm.Session(endpoint, auth=(username, password), verify=verify, transport=transport)
        self._session = winrm.Session(endpoint, auth=(username, password), transport=transport)
        self._protocol = self._session.protocol

        return phantom.APP_SUCCESS

    def _run_cmd_on_endpoint(self, action_result, cmd, args=None):

        self.debug_print("_run_cmd_on_endpoint...")

        resp = None
        try:
            resp = self._session.run_cmd(cmd, args)

        except Exception as e:
            return action_result.set_status(phantom.APP_ERROR, ('Error running command: {}').format(str(e)))

        if resp is None:
            self.debug_print('Error: _run_cmd is missing parameters')
            return action_result.set_status(phantom.APP_ERROR, 'Unknown error while running command')
        else:
            self.debug_print("cmd status_code: ", resp.status_code)
            self.debug_print("cmd std_out: ", resp.std_out.decode())
            self.debug_print("cmd std_err: ", resp.std_err.decode())

#            data = {}
#            data['status_code'] = resp.status_code
#            data['std_out'] = resp.std_out
#            data['std_err'] = resp.std_err

            return phantom.APP_SUCCESS

    def _handle_forensic_investigation(self, param):

        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        action_result = self.add_action_result(ActionResult(dict(param)))

        caseid = ''
        report = None

        ret_val, response = self._check_endpoint_state(action_result, param)

        if phantom.is_fail(ret_val):
            return action_result.get_status()

        if 'info' not in response:
            return action_result.set_status(phantom.APP_ERROR, 'Error while retriving the info from endpoint state')

        if 'IsPermanent' not in response['info'] or response['info']['IsPermanent'] is False:
            self.debug_print("do one time agent, starting_______________")  # do one time agent

            caseid = str(uuid.uuid1()).upper()
            ret_val = self._hunt_on_onetime_agent(action_result, caseid, param)
            if phantom.is_fail(ret_val):
                return action_result.get_status()

            self.debug_print("action started, caseid: ", caseid)

        else:
            if 'IsOnline' not in response['info'] or response['info']['IsOnline'] is False:
                self.debug_print("do start service, starting_______________")  # do start service

                ret_val = self._sc_start_tgxservice(action_result, param)
                if phantom.is_fail(ret_val):
                    return action_result.get_status()

                self.debug_print("service started")

            self.debug_print("do permanent agent, starting_______________")  # do permanent agent

            ret_val, caseid = self._hunt_on_permanent_agent(action_result, param)
            if phantom.is_fail(ret_val):
                return action_result.get_status()

            if caseid is None or caseid == '':
                return action_result.set_status(phantom.APP_ERROR, 'Error while retriving case id in case of permanent agent')

            self.debug_print("action started, caseid: ", caseid)

        self.debug_print("get hunt report, starting_______________")  # do get report

        ret_val, report = self._get_report_from_txserver(action_result, caseid, param)
        if phantom.is_fail(ret_val):
            return action_result.get_status()

        if report is None or any(report) is False:
            return action_result.set_status(phantom.APP_ERROR, 'Error while retriving hunt report in case of permanent agent')

        self.debug_print("report ready")

        return self._fill_out_phantom_output(action_result, report, param)

    def handle_action(self, param):
        ret_val = phantom.APP_SUCCESS

        # Get the action that we are supposed to execute for this App Run
        action_id = self.get_action_identifier()

        self.debug_print("action_id", self.get_action_identifier())

        if action_id == 'test_connectivity':
            ret_val = self._handle_test_connectivity(param)

        elif action_id == 'get_version':
            ret_val = self._handle_get_version(param)

        elif action_id == 'forensic_investigation':
            ret_val = self._handle_forensic_investigation(param)

        return ret_val

    def initialize(self):
        # Load the state in initialize, use it to store data
        # that needs to be accessed across actions
        self._state = self.load_state()

        # get the asset config
        config = self.get_config()
        """
        # Access values in asset config by the name

        # Required values can be accessed directly
        required_config_name = config['required_config_name']

        # Optional values should use the .get() function
        optional_config_name = config.get('optional_config_name')
        """

        self._base_url = config['base_url']
        self._apikey = config['apikey']
        self._user = config['user']
        self._org = config['org']

        return phantom.APP_SUCCESS

    def finalize(self):
        # Save the state, this data is saved across actions and app upgrades
        self.save_state(self._state)
        return phantom.APP_SUCCESS


def main():
    import pudb
    import argparse

    pudb.set_trace()

    argparser = argparse.ArgumentParser()

    argparser.add_argument('input_test_json', help='Input Test JSON file')
    argparser.add_argument('-u', '--username', help='username', required=False)
    argparser.add_argument('-p', '--password', help='password', required=False)

    args = argparser.parse_args()
    session_id = None

    username = args.username
    password = args.password

    if username is not None and password is None:

        # User specified a username but not a password, so ask
        import getpass
        password = getpass.getpass("Password: ")

    if username and password:
        try:
            login_url = TxhunterConnector._get_phantom_base_url() + '/login'

            print("Accessing the Login page")
            r = requests.get(login_url, verify=False)
            csrftoken = r.cookies['csrftoken']

            data = dict()
            data['username'] = username
            data['password'] = password
            data['csrfmiddlewaretoken'] = csrftoken

            headers = dict()
            headers['Cookie'] = 'csrftoken=' + csrftoken
            headers['Referer'] = login_url

            print("Logging into Platform to get the session id")
            r2 = requests.post(login_url, verify=False, data=data, headers=headers)
            session_id = r2.cookies['sessionid']
        except Exception as e:
            print("Unable to get session id from the platform. Error: " + str(e))
            exit(1)

    with open(args.input_test_json) as f:
        in_json = f.read()
        in_json = json.loads(in_json)
        print(json.dumps(in_json, indent=4))

        connector = TxhunterConnector()
        connector.print_progress_message = True

        if session_id is not None:
            in_json['user_session_token'] = session_id
            connector._set_csrf_info(csrftoken, headers['Referer'])

        ret_val = connector._handle_action(json.dumps(in_json), None)
        print(json.dumps(json.loads(ret_val), indent=4))

    exit(0)


if __name__ == '__main__':
    main()
