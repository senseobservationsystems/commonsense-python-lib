""" 
Copyright (C) [2012] Sense Observation Systems B.V.
Licensed under the Apache License, Version 2.0 (the 'License');
you may not use this file except in compliance with the License.
You may obtain a copy of the License at
 
http://www.apache.org/licenses/LICENSE-2.0
 
Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
"""

import md5, urllib, httplib, json, socket, oauth.oauth as oauth, urlparse, string

class SenseAPI:
    """
        Class for interacting with CommonSense Api. 
        
        Can be set to interact with either the live or test server.
        Can authenticate using session_id and oauth.
    """
    def __init__(self):
        """
            Constructor function.
        """
        self.__api_key__ = ""
        self.__session_id__ = ""
        self.__status__ = 0
        self.__headers__ = {}
        self.__response__ = ""
        self.__error__ = ""
        self.__verbose__ = False
        self.__server__ = 'live'
        self.__server_url__ = 'api.sense-os.nl'
        self.__authentication__ = 'not_authenticated'
        self.__oauth_consumer__ = {}
        self.__oauth_token__ = {}
        self.__use_https__ = True

#===============================================
# C O N F I G U R A T I O N  F U N C T I O N S =
#===============================================
    def setVerbosity(self, verbose):
        """
            Set verbosity of the SenseApi object.
            
            @param verbose (boolean) - True of False
            
            @return (boolean) - Boolean indicating whether setVerbosity succeeded
        """
        if not (verbose == True or verbose == False):
            return False
        else:
            self.__verbose__ = verbose
            return True

    def setServer(self, server):
        """
            Set server to interact with.
            
            @param server (string) - 'live' for live server, 'dev' for test server, 'rc' for release candidate
            
            @return (boolean) - Boolean indicating whether setServer succeeded
        """
        if server == 'live':
            self.__server__ = server
            self.__server_url__ = 'api.sense-os.nl'
            self.setUseHTTPS()
            return True
        elif server == 'dev':
            self.__server__ = server
            self.__server_url__ = 'api.dev.sense-os.nl'
            # the dev server doesn't support https
            self.setUseHTTPS(False)
            return True
        elif server == 'rc':
            self.__server__ = server
            self.__server_url__ = 'api.rc.dev.sense-os.nl'
            self.setUseHTTPS(False)
        else:
            return False

    def setUseHTTPS(self, enable = True):
        """
            Set whether to use https or http.
            @param enable (boolean) - True to enable https (default), False to use http
        """
        self.__use_https__ = enable

    def __setAuthenticationMethod__(self, method):
        if not (method in ['session_id', 'oauth', 'authenticating_session_id', 'authenticating_oauth', 'not_authenticated', 'api_key']):
            return False
        else:
            self.__authentication__ = method
            return True


#=======================================
# R E T R I E V A L  F U N C T I O N S =
#=======================================
    def getResponseStatus(self):
        """
            Retrieve the response status code of the last api call
            
            @return (integer) - Http status code
        """
        return self.__status__

    def getResponseHeaders(self):
        """
            Retrieve the response headers of the last api call
            
            @return (dictionary) - Dictonary containing headers
        """
        return self.__headers__

    def getResponse(self):
        """
            Retrieve the response of the last api call
            
            @return (string) - The literal response body, which is likely to be in json format
        """
        return self.__response__

    def getError(self):
        """
            Retrieve the error value
            
            @return (string) - The most recent error message
        """
        return self.__error__

    def getLocationId(self):
        """
            Retrieve the integer that should be present in the Location header after creating an object in CommonSense
            
            @return (string) - String containing the id of the created object, or empty if nothing was created
        """
        location = self.__headers__.get('location')
        return location.split('/')[-1] if location is not None else None;

    def getAllSensors(self):
        """
            Retrieve all the user's own sensors by iterating over the SensorsGet function
            
            @return (list) - Array of sensors
        """
        j = 0
        sensors = []
        parameters = {'page':0, 'per_page':1000, 'owned':1}
        while True:
            parameters['page'] = j
            if self.SensorsGet(parameters):
                s = json.loads(self.getResponse())['sensors']
                sensors.extend(s)
            else:
                # if any of the calls fails, we cannot be cannot be sure about the sensors in CommonSense
                return None

            if len(s) < 1000:
                break

            j += 1

        return sensors


    def findSensor(self, sensors, sensor_name, device_type = None):
        """
            Find a sensor in the provided list of sensors
            
            @param sensors (list) - List of sensors to search in
            @param sensor_name (string) - Name of sensor to find
            @param device_type (string) - Device type of sensor to find, can be None
            
            @return (string) - sensor_id of sensor or None if not found
        """

        if device_type == None:
            for sensor in sensors:
                if sensor['name'] == sensor_name:
                    return sensor['id']
        else:
            for sensor in sensors:
                if sensor['name'] == sensor_name and sensor['device_type'] == device_type:
                    return sensor['id']

        return None

#=======================================
    # B A S E  A P I  C A L L  M E T H O D =
#=======================================
    def __SenseApiCall__ (self, url, method, parameters = None, headers = {}):
        heads = {}
        heads.update(headers)
        body = ''
        http_url = url
        if self.__authentication__ == 'not_authenticated' and (url == '/users.json' or url == '/users.json?disable_mail=1') and method == 'POST':
            heads.update({"Content-type": "application/json", "Accept":"*"})
            body = json.dumps(parameters)
        elif self.__authentication__ == 'not_authenticated':
            self.__status__ = 401
            return False

        elif self.__authentication__ == 'authenticating_oauth':
            heads.update({"Content-type": "application/x-www-form-urlencoded", "Accept":"*"})
            if not parameters is None:
                http_url = '{0}?{1}'.format(url, urllib.urlencode(parameters, True))

        elif self.__authentication__ == 'authenticating_session_id':
            heads.update({"Content-type": "application/json", "Accept":"*"})
            if not parameters is None:
                body = json.dumps(parameters)

        elif self.__authentication__ == 'oauth':
            oauth_url = 'http://{0}{1}'.format(self.__server_url__, url)
            if not parameters is None and (method == 'GET' or method == 'DELETE'):
                oauth_request = oauth.OAuthRequest.from_consumer_and_token(self.__oauth_consumer__, token = self.__oauth_token__, http_method = method, http_url = oauth_url, parameters = parameters)
            else:
                oauth_request = oauth.OAuthRequest.from_consumer_and_token(self.__oauth_consumer__, token = self.__oauth_token__, http_method = method, http_url = oauth_url)
            oauth_request.sign_request(oauth.OAuthSignatureMethod_HMAC_SHA1(), self.__oauth_consumer__, self.__oauth_token__)
            http_url = oauth_request.to_url()
            # heads.update(oauth_request.to_header())
            if not parameters is None:
                if method == 'GET' or method == 'DELETE':
                    pass
                    # heads.update({"Accept":"*"})
                    # http_url = '{0}?{1}'.format(url, urllib.urlencode(parameters,True))
                else:
                    heads.update({"Content-type": "application/json", "Accept":"*"})
                    body = json.dumps(parameters)

        elif self.__authentication__ == 'session_id':
            heads.update({'X-SESSION_ID':"{0}".format(self.__session_id__)})
            if not parameters is None:
                if method == 'GET' or method == 'DELETE':
                    heads.update({"Content-type": "application/x-www-form-urlencoded", "Accept":"*"})
                    http_url = '{0}?{1}'.format(url, urllib.urlencode(parameters, True))
                else:
                    heads.update({"Content-type": "application/json", "Accept":"*"})
                    body = json.dumps(parameters)

        elif self.__authentication__ == 'api_key':
            if parameters is None:
                parameters = {}
            parameters['API_KEY'] = self.__api_key__
            if method == 'GET' or method == 'DELETE':
                heads.update({"Content-type": "application/x-www-form-urlencoded", "Accept":"*"})
                http_url = '{0}?{1}'.format(url, urllib.urlencode(parameters, True))
            else:
                heads.update({"Content-type": "application/json", "Accept":"*"})
                body = json.dumps(parameters)

        else:
            self.__status__ = 418
            return False


        if self.__use_https__ and not self.__authentication__ == 'authenticating_oauth' and not self.__authentication__ == 'oauth':
            connection = httplib.HTTPSConnection(self.__server_url__, timeout = 60)
        else:
            connection = httplib.HTTPConnection(self.__server_url__, timeout = 60)

        try:
            connection.request(method, http_url, body, heads);
            result = connection.getresponse();
        except:  # TODO: check if this doesnt already generate a status
            self.__status__ = 408
            return False

        self.__headers__ = {}

        self.__response__ = result.read()
        self.__status__ = result.status
        resp_headers = result.getheaders()

        connection.close()

        for h in resp_headers:
            self.__headers__.update({h[0]:h[1]})
        self.__headers__ = dict(zip(map(string.lower, self.__headers__.keys()), self.__headers__.values()))


        if self.__verbose__:
            print "===================CALL==================="
            print "Call: {0} {1}".format(method, http_url)
            print "Server: {0}".format(self.__server__)
            print "Headers: {0}".format(heads)
            print "Body: {0}".format(body)
            print "==================RESPONSE================"
            print "Status: {0}".format(self.__status__)
            print "Headers: {0}".format(self.__headers__)
            print "Response: {0}".format(self.__response__)
            print "==========================================\n"

        if self.__status__ == 200 or self.__status__ == 201 or self.__status__ == 302:
            return True
        else:
            return False

#=============================================
# A P I _ K E Y  A U T H E N T I C A T I O N =
#=============================================
    def SetApiKey(self, api_key):
        """
            Set the api key.
            
            @param api_key (string) - A valid api key to authenticate with CommonSense
        """
        self.__setAuthenticationMethod__('api_key')
        self.__api_key__ = api_key
#==================================================
# S E S S I O N  I D  A U T H E N T I C A T I O N =
#==================================================
    def SetSessionId(self, session_id):
        """
            Pass an existing session_id to SenseApi object. Use with care!
            
            @param session_id (string) - A valid session_id obtained by logging into CommonSense
        """
        self.__setAuthenticationMethod__('session_id')
        self.__session_id__ = session_id

    def AuthenticateSessionId(self, username, password):
        """
            Authenticate using a username and password. 
            The SenseApi object will store the obtained session_id internally until a call to LogoutSessionId is performed.
            
            @param username (string) - CommonSense username
            @param password (string) - MD5Hash of CommonSense password
            
            @return (bool) - Boolean indicating whether AuthenticateSessionId was successful
        """
        self.__setAuthenticationMethod__('authenticating_session_id')

        parameters = {'username':username, 'password':password}

        if self.__SenseApiCall__("/login.json", "POST", parameters = parameters):
            try:
                response = json.loads(self.__response__)
            except:
                self.__setAuthenticationMethod__('not_authenticated')
                self.__error__ = "notjson"
                return False
            try:
                self.__session_id__ = response['session_id']
                self.__setAuthenticationMethod__('session_id')
                return True
            except:
                self.__setAuthenticationMethod__('not_authenticated')
                self.__error__ = "no session_id"
                return False
        else:
            self.__setAuthenticationMethod__('not_authenticated')
            self.__error__ = "api call unsuccessful"
            return False

    def LogoutSessionId(self):
        """
            Logout the current session_id from CommonSense
            
            @return (bool) - Boolean indicating whether LogoutSessionId was successful
        """
        if self.__SenseApiCall__('/logout.json', 'POST'):
            self.__setAuthenticationMethod__('not_authenticated')
            return True
        else:
            self.__error__ = "api call unsuccessful"
            return False

    # deprecated
    def Login (self, username, password):
        """
            Deprecated, use AuthenticateSessionId instead
        """
        return self.AuthenticateSessionId(username, password)

    # deprecated
    def Logout (self):
        """
            Deprecated, use LogoutSessionId instead
        """
        return self.LogoutSessionId()


#=========================================
# O A U T H  A U T H E N T I C A T I O N =
#=========================================
    def AuthenticateOauth (self, oauth_token_key, oauth_token_secret, oauth_consumer_key, oauth_consumer_secret):
        """
            Authenticate using Oauth
            
            @param oauth_token_key (string) - A valid oauth token key obtained from CommonSense
            @param oauth_token_secret (string) - A valid oauth token secret obtained from CommonSense
            @param oauth_consumer_key (string) - A valid oauth consumer key obtained from CommonSense
            @param oauth_consumer_secret (string) - A valid oauth consumer secret obtained from CommonSense
            
            @return (boolean) - Boolean indicating whether the provided credentials were successfully authenticated
        """
        self.__oauth_consumer__ = oauth.OAuthConsumer(str(oauth_consumer_key), str(oauth_consumer_secret))
        self.__oauth_token__ = oauth.OAuthToken(str(oauth_token_key), str(oauth_token_secret))
        self.__authentication__ = 'oauth'
        if self.__SenseApiCall__('/users/current.json', 'GET'):
            return True
        else:
            self.__error__ = "api call unsuccessful"
            return False

#=======================================
# O A U T H  A U T H O R I Z A T I O N =
#=======================================

    def OauthSetConsumer(self, oauth_consumer_key, oauth_consumer_secret):
        """
            @param oauth_consumer_key (string) - A valid oauth consumer key obtained from CommonSense
            @param oauth_consumer_secret (string) - A valid oauth consumer secret obtained from CommonSense
        """
        self.__oauth_consumer__ = oauth.OAuthConsumer(str(oauth_consumer_key), str(oauth_consumer_secret))

    def OauthSetToken(self, token_key, token_secret, token_verifier = None):
        """
            @param token_key (string) - A valid oauth token key obtained from CommonSense
            @param token_secret (string) - A valid oauth token secret obtained from CommonSense
            @param token_verifier (string) - A valid oauth token verifier obtained from CommonSense
        """

        self.__oauth_token__ = oauth.OAuthToken(str(token_key), str(token_secret))
        if not token_verifier == None:
            self.__oauth_token__.set_verifier(str(token_verifier))

    def OauthGetRequestToken(self, oauth_callback = 'http://www.sense-os.nl'):
        """
            Obtain temporary credentials at CommonSense. If this function returns True, the clients __oauth_token__ member
            contains the temporary oauth request token.
            
            @param oauth_consumer_key (string) - A valid oauth consumer key obtained from CommonSense
            @param oauth_consumer_secret (string) - A valid oauth consumer secret obtained from CommonSense
            @param oauth_callback (string) (optional) - Oauth callback url
            
            @return (boolean) - Boolean indicating whether OauthGetRequestToken was successful
        """
        self.__setAuthenticationMethod__('authenticating_oauth')

    # obtain a request token
        oauth_request = oauth.OAuthRequest.from_consumer_and_token(self.__oauth_consumer__, \
                                                                    http_method = 'GET', \
                                                                     callback = oauth_callback, \
                                                                     http_url = 'http://api.sense-os.nl/oauth/request_token')
        oauth_request.sign_request(oauth.OAuthSignatureMethod_HMAC_SHA1(), self.__oauth_consumer__, None)

        parameters = []
        for key in oauth_request.parameters.iterkeys():
            parameters.append((key, oauth_request.parameters[key]))
        parameters.sort()

        if self.__SenseApiCall__('/oauth/request_token', 'GET', parameters = parameters):
            response = urlparse.parse_qs(self.__response__)
            self.__oauth_token__ = oauth.OAuthToken(response['oauth_token'][0], response['oauth_token_secret'][0])
            return True
        else:
            self.__setAuthenticationMethod__('not_authenticated')
            self.__error__ = "error getting request token"
            return False

    def OauthGetAccessToken(self):
        """
            Use token_verifier to obtain an access token for the user. If this function returns True, the clients __oauth_token__ member
            contains the access token. 
            
            @return (boolean) - Boolean indicating whether OauthGetRequestToken was successful
        """

        self.__setAuthenticationMethod__('authenticating_oauth')

        # obtain access token
        oauth_request = oauth.OAuthRequest.from_consumer_and_token(self.__oauth_consumer__, \
                                                                     token = self.__oauth_token__, \
                                                                     callback = '', \
                                                                     verifier = self.__oauth_token__.verifier, \
                                                                     http_url = 'http://api.sense-os.nl/oauth/access_token')
        oauth_request.sign_request(oauth.OAuthSignatureMethod_HMAC_SHA1(), self.__oauth_consumer__, self.__oauth_token__)

        parameters = []
        for key in oauth_request.parameters.iterkeys():
            parameters.append((key, oauth_request.parameters[key]))
        parameters.sort()

        if self.__SenseApiCall__('/oauth/access_token', 'GET', parameters = parameters):
            response = urlparse.parse_qs(self.__response__)
            self.__oauth_token__ = oauth.OAuthToken(response['oauth_token'][0], response['oauth_token_secret'][0])
            self.__setAuthenticationMethod__('oauth')
            return True
        else:
            self.__setAuthenticationMethod__('session_id')
            self.__error__ = "error getting access token"
            return False

    def OauthAuthorizeApplication(self, oauth_duration = 'hour'):
        """
            Authorize an application using oauth. If this function returns True, the obtained oauth token can be retrieved using getResponse and will be in url-parameters format.
            TODO: allow the option to ask the user himself for permission, instead of doing this automatically. Especially important for web applications.
            
            @param oauth_duration (string) (optional) -'hour', 'day', 'week', 'year', 'forever'
            
            @return (boolean) - Boolean indicating whether OauthAuthorizeApplication was successful
        """
        if self.__session_id__ == '':
            self.__error__ = "not logged in"
            return False

    # automatically get authorization for the application
        parameters = {'oauth_token':self.__oauth_token__.key, 'tok_expir':self.__OauthGetTokExpir__(oauth_duration), 'action':'ALLOW', 'session_id':self.__session_id__}

        if self.__SenseApiCall__('/oauth/provider_authorize', 'POST', parameters = parameters):
            if self.__status__ == 302:
                response = urlparse.parse_qs(urlparse.urlparse(self.__headers__['location'])[4])
                verifier = response['oauth_verifier'][0]
                self.__oauth_token__.set_verifier(verifier)
                return True
            else:
                self.__setAuthenticationMethod__('session_id')
                self.__error__ = "error authorizing application"
                return False
        else:
            self.__setAuthenticationMethod__('session_id')
            self.__error__ = "error authorizing application"
            return False

    def __OauthGetTokExpir__ (self, duration):
        if duration == 'hour':
            return 1
        if duration == 'day':
            return 2
        if duration == 'week':
            return 3
        if duration == 'month':
            return 4
        if duration == 'forever':
            return 0

#================
# S E N S O R S =
#================
    def SensorsGet_Parameters(self):
        return {'page':0, 'per_page':100, 'shared':0, 'owned':0, 'physical':0, 'details':'full'}

    def SensorsGet(self, parameters = None, sensor_id = -1):
        """
            Retrieve sensors from CommonSense, according to parameters, or by sensor id. 
            If successful, result can be obtained by a call to getResponse(), and should be a json string.
            
            @param parameters (dictionary) (optional) - Dictionary containing the parameters for the api-call.
                    @note - http://www.sense-os.nl/45?nodeId=45&selectedId=11887
            @param sensor_id (int) (optional) - Sensor id of sensor to retrieve details from.
            
            @return (boolean) - Boolean indicating whether SensorsGet was successful.
        """

        url = ''
        if parameters is None and sensor_id <> -1:
            url = '/sensors/{0}.json'.format(sensor_id)
        else:
            url = '/sensors.json'

        if self.__SenseApiCall__(url, 'GET', parameters = parameters):
            return True
        else:
            self.__error__ = "api call unsuccessful"
            return False

    def SensorsDelete(self, sensor_id):
        """
            Delete a sensor from CommonSense.
            
            @param sensor_id (int) - Sensor id of sensor to delete from CommonSense.
            
            @return (bool) - Boolean indicating whether SensorsDelete was successful.
        """
        if self.__SenseApiCall__('/sensors/{0}.json'.format(sensor_id), 'DELETE'):
            return True
        else:
            self.__error__ = "api call unsuccessful"
            return False

    def SensorsPost_Parameters(self):
        return {'sensor': {'name':'', 'display_name':'', 'device_type':'', 'pager_type':'', 'data_type':'', 'data_structure':''}}

    def SensorsPost(self, parameters):
        """
            Create a sensor in CommonSense.
            If SensorsPost is successful, the sensor details, including its sensor_id, can be obtained by a call to getResponse(), and should be a json string.
            
            @param parameters (dictonary) - Dictionary containing the details of the sensor to be created. 
                    @note - http://www.sense-os.nl/46?nodeId=46&selectedId=11887            
                                    
            @return (bool) - Boolean indicating whether SensorsPost was successful.
        """
        if self.__SenseApiCall__('/sensors.json', 'POST', parameters = parameters):
            return True
        else:
            self.__error__ = "api call unsuccessful"
            return False

    def SensorsPut(self, sensor_id, parameters):
        """
            Update a sensor in CommonSense.
            
            @param parameters (dictionary) - Dictionary containing the sensor parameters to be updated.
                    
            @return (bool) - Boolean indicating whether SensorsPut was successful.
        """
        if self.__SenseApiCall__('/sensors/{0}.json'.format(sensor_id), 'PUT', parameters = parameters):
            return True
        else:
            self.__error__ = "api call unscuccessful"
            return False

#==================
# M E T A T A G S =
#==================
    def SensorsMetatagsGet(self, parameters, namespace = None):
        """
            Retrieve sensors with their metatags.
            
            @param namespace (string) - Namespace for which to retrieve the metatags.
            @param parameters (dictionary - Dictionary containing further parameters.
            
            @return (bool) - Boolean indicating whether SensorsMetatagsget was successful
        """
        ns = "default" if namespace is None else namespace
        parameters['namespace'] = ns
        if self.__SenseApiCall__('/sensors/metatags.json', 'GET', parameters = parameters):
            return True
        else:
            self.__error__ = "api call unsuccessful"
            return False

    def GroupSensorsMetatagsGet(self, group_id, parameters, namespace = None):
        """
            Retrieve sensors in a group with their metatags.
            
            @param group_id (int) - Group id for which to retrieve metatags.
            @param namespace (string) - Namespace for which to retrieve the metatags.
            @param parameters (dictionary) - Dictionary containing further parameters.
            
            @return (bool) - Boolean indicating whether GroupSensorsMetatagsGet was successful
        """
        ns = "default" if namespace is None else namespace
        parameters['namespace'] = ns
        if self.__SenseApiCall__('/groups/{0}/sensors/metatags.json'.format(group_id), 'GET', parameters = parameters):
            return True
        else:
            self.__error__ = "api call unsuccessful"
            return False

    def SensorMetatagsGet(self, sensor_id, namespace = None):
        """
            Retrieve the metatags of a sensor.
            
            @param sensor_id (int) - Id of the sensor to retrieve metatags from
            @param namespace (stirng) - Namespace for which to retrieve metatags.
            
            @return (bool) - Boolean indicating whether SensorMetatagsGet was successful
        """
        ns = "default" if namespace is None else namespace
        if self.__SenseApiCall__('/sensors/{0}/metatags.json'.format(sensor_id), 'GET', parameters = {'namespace': ns}):
            return True
        else:
            self.__error__ = "api call unsuccessful"
            return False

    def SensorMetatagsPost(self, sensor_id, metatags, namespace = None):
        """
            Attach metatags to a sensor for a specific namespace
            
            @param sensor_id (int) - Id of the sensor to attach metatags to
            @param namespace (string) - Namespace for which to attach metatags
            @param metatags (dictionary) - Metatags to attach to the sensor
            
            @return (bool) - Boolean indicating whether SensorMetatagsPost was successful
        """
        ns = "default" if namespace is None else namespace
        if self.__SenseApiCall__("/sensors/{0}/metatags.json?namespace={1}".format(sensor_id, ns), "POST", parameters = metatags):
            return True
        else:
            self.__error__ = "api call unsuccessful"
            return False

    def SensorMetatagsPut(self, sensor_id, metatags, namespace = None):
        """
            Overwrite the metatags attached to a sensor for a specific namespace
            
            @param sensor_id (int) - Id of the sensor to overwrite metatags for
            @param namespace (string) - Namespace for which to overwrite metatags
            @param metatags (dictionary) - Metatags to overwrite the existing metatags with
            
            @return (bool) - Boolean indicating whether SensorMetatagsPut was successful
        """
        ns = "default" if namespace is None else namespace
        if self.__SenseApiCall__("/sensors/{0}/metatags.json?namespace={1}".format(sensor_id, ns), "POST", parameters = metatags):
            return True
        else:
            self.__error__ = "api call unsuccessful"
            return False

    def SensorMetatagsDelete(self, sensor_id, namespace = None):
        """
            Delete the metatags attached to a sensor for a specific namespace
            
            @param sensor_id (int) - Id of the sensor to delete metatags for
            @param namespace (string) - Namespace for which to delete metatags
            
            @return (bool) - Boolean indicating whether SensorMetatagsDelete was successful
        """
        ns = "default" if namespace is None else namespace
        if self.__SenseApiCall__("/sensors/{0}/metatags.json".format(sensor_id), "POST", parameters = {'namespace':ns}):
            return True
        else:
            self.__error__ = "api call unsuccessful"
            return False

    def SensorsFind(self, parameters, filters, namespace = None):
        """
            Find sensors based on a number of filters on metatags in a specific namespace
            
            @param namespace (string) - Namespace to use in filtering on metatags
            @param parameters (dictionary) - Dictionary containing additional parameters
            @param filters (dictionary) - Dictionary containing the filters on metatags
            
            @return (bool) - Boolean indicating whetehr SensorsFind was successful
        """
        ns = "default" if namespace is None else namespace
        parameters['namespace'] = ns
        if self.__SenseApiCall__("/sensors/find.json?{0}".format(urllib.urlencode(parameters, True)), "POST", parameters = filters):
            return True
        else:
            self.__error__ = "api call unsuccessful"
            return False

    def GroupSensorsFind(self, group_id, parameters, filters, namespace = None):
        """
            Find sensors in a group based on a number of filters on metatags
            
            @param group_id (int) - Id of the group in which to find sensors
            @param namespace (string) - Namespace to use in filtering on metatags
            @param parameters (dictionary) - Dictionary containing additional parameters
            @param filters (dictionary) - Dictioanry containing the filters on metatags
            
            @return (bool) - Boolean indicating whether GroupSensorsFind was successful
        """
        ns = "default" if namespace is None else namespace
        parameters['namespace'] = ns
        if self.__SenseApiCall__("/groups/{0}/sensors/find.json?{1}".format(group_id, urllib.urlencode(parameters, True)), "POST", parameters = filters):
            return True
        else:
            self.__error__ = "api call unsuccessful"
            return False

    def MetatagDistinctValuesGet(self, metatag_name, namespace = None):
        """
            Find the distinct value of a metatag name in a certain namespace
            
            @param metatag_name (string) - Name of the metatag for which to find the distinct values
            @param namespace (stirng) - Namespace in which to find the distinct values
            
            @return (bool) - Boolean indicating whether MetatagDistinctValuesGet was successful
        """
        ns = "default" if namespace is None else namespace
        if self.__SenseApiCall__("/metatag_name/{0}/distinct_values.json", "GET", parameters = {'namespace': ns}):
            return True
        else:
            self.__error__ = "api call unsuccessful"
            return False

#=======================
# S E N S O R  D A T A =
#=======================
    def SensorDataGet_Parameters(self):
        return {'page':0, 'per_page':100, 'start_date':0, 'end_date':4294967296, 'date':0, 'next':0, 'last':0, 'sort':'ASC', 'total':1}

    def SensorDataGet(self, sensor_id, parameters):
        """
            Retrieve sensor data for a specific sensor from CommonSense.
            If SensorDataGet is successful, the result can be obtained by a call to getResponse(), and should be a json string.
            
            @param sensor_id (int) - Sensor id of the sensor to retrieve data from.
            @param parameters (dictionary) - Dictionary containing the parameters for the api call.
                    @note - http://www.sense-os.nl/52?nodeId=52&selectedId=11887
                    
            @return (bool) - Boolean indicating whether SensorDataGet was successful.
        """
        if self.__SenseApiCall__('/sensors/{0}/data.json'.format(sensor_id), 'GET', parameters = parameters):
            return True
        else:
            self.__error__ = "api call unsuccessful"
            return False

    def SensorsDataGet(self, sensorIds, parameters):
        """
            Retrieve sensor data for the specified sensors from CommonSense.
            If SensorsDataGet is successful, the result can be obtained by a call to getResponse(), and should be a json string.

            @param sensorIds (list) a list of sensor ids to retrieve the data for
            @param parameters (dictionary) - Dictionary containing the parameters for the api call.

            @return (bool) - Boolean indicating whether SensorsDataGet was successful.
        """
        if parameters is None:
                parameters = {}
        parameters["sensor_id[]"] = sensorIds
        if self.__SenseApiCall__('/sensors/data.json', 'GET', parameters = parameters):
                return True
        else:
            self.__error__ = "api call unsuccessful"
            return False

    def SensorDataPost(self, sensor_id, parameters):
        """
            Post sensor data to a specific sensor in CommonSense.
            
            @param sensor_id (int) - Sensor id of the sensor to post data to.
            @param parameters (dictionary) - Data to post to the sensor.
                    @note - http://www.sense-os.nl/53?nodeId=53&selectedId=11887
        """
        if self.__SenseApiCall__('/sensors/{0}/data.json'.format(sensor_id), 'POST', parameters = parameters):
            return True
        else:
            self.__error__ = "api call unsuccessful"
            return False

    def SensorDataDelete(self, sensor_id, data_id):
        """
            Delete a sensor datum from a specific sensor in CommonSense.
            
            @param sensor_id (int) - Sensor id of the sensor to delete data from
            @param data_id (int) - Id of the data point to delete
            
            @return (bool) - Boolean indicating whether SensorDataDelete was successful. 
        """
        if self.__SenseApiCall__('/sensors/{0}/data/{1}.json'.format(sensor_id, data_id), 'DELETE'):
            return True
        else:
            self.__error_ = "api call unsuccessful"
            return False

    def SensorsDataPost(self, parameters):
        """
            Post sensor data to multiple sensors in CommonSense simultaneously.
            
            @param parameters (dictionary) - Data to post to the sensors.
                    @note - http://www.sense-os.nl/59?nodeId=59&selectedId=11887
                    
            @return (bool) - Boolean indicating whether SensorsDataPost was successful.
        """
        if self.__SenseApiCall__('/sensors/data.json', 'POST', parameters = parameters):
            return True
        else:
            self.__error__ = "api call unsuccessful"
            return False

#==================
# S E R V I C E S =
#==================
    def ServicesGet (self, sensor_id):
        """
            Retrieve services connected to a sensor in CommonSense.
            If ServicesGet is successful, the result can be obtained by a call to getResponse() and should be a json string.
            
            @sensor_id (int) - Sensor id of sensor to retrieve services from.
            
            @return (bool) - Boolean indicating whether ServicesGet was successful.
        """
        if self.__SenseApiCall__('/sensors/{0}/services.json'.format(sensor_id), 'GET'):
            return True
        else:
            self.__error__ = "api call unsuccessful"
            return False

    def ServicesPost_Parameters (self):
        return {'service':{'name':'math_service', 'data_fields':['sensor']}, 'sensor':{'name':'', 'device_type':''}}

    def ServicesPost (self, sensor_id, parameters):
        """
            Create a new service in CommonSense, attached to a specific sensor. 
            If ServicesPost was successful, the service details, including its service_id, can be obtained from getResponse(), and should be a json string.
            
            @param sensor_id (int) - The sensor id of the sensor to connect the service to.
            @param parameters (dictionary) - The specifics of the service to create.
                    @note: http://www.sense-os.nl/81?nodeId=81&selectedId=11887
            
            @return (bool) - Boolean indicating whether ServicesPost was successful.
        """
        if self.__SenseApiCall__('/sensors/{0}/services.json'.format(sensor_id), 'POST', parameters = parameters):
            return True
        else:
            self.__error__ = "api call unsuccessful"
            return False

    def ServicesDelete (self, sensor_id, service_id):
        """
            Delete a service from CommonSense.
            
            @param sensor_id (int) - Sensor id of the sensor the service is connected to.
            @param service_id (int) - Sensor id of the service to delete.
            
            @return (bool) - Boolean indicating whether ServicesDelete was successful.
        """
        if self.__SenseApiCall__('/sensors/{0}/services/{1}.json'.format(sensor_id, service_id), 'DELETE'):
            return True
        else:
            self.__error__ = "api call unsuccessful"
            return False

    def ServicesGetExpression(self, sensor_id, service_id):
        """
            Get expression for the math service.
            
            @param sensor_id (int) - Id of the sensor to which the service is connected
            @param service_id (int) - Id of the service for which to get the expression
            
            @return (bool) - Boolean indicating whether ServicesGetExpression was successful 
        """
        if self.__SenseApiCall__('/sensors/{0}/services/{1}/GetExpression.json'.format(sensor_id, service_id), "GET"):
            return True
        else:
            self.__error__ = "api call unsuccessful"
            return False

    def ServicesSet_Parameters (self):
            return {'parameters':[]}

    def ServicesSetExpression (self, sensor_id, service_id, parameters):
        """
            Set expression for the math service.
            
            @param sensor_id (int) - Sensor id of the sensor the service is connected to.
            @param service_id (int) - Service id of the service for which to set the expression.
            @param parameters (dictonary) - Parameters to set the expression of the math service.
                    @note - http://www.sense-os.nl/85?nodeId=85&selectedId=11887
                    
            @return (bool) - Boolean indicating whether ServicesSetExpression was successful.
        """
        if self.__SenseApiCall__('/sensors/{0}/services/{1}/SetExpression.json'.format(sensor_id, service_id), 'POST', parameters = parameters):
            return True
        else:
            self.__error__ = "api call unsuccessful"
            return False

    def ServicesSetMetod (self, sensor_id, service_id, method, parameters):
        """
            Set expression for the math service.
            
            @param sensor_id (int) - Sensor id of the sensor the service is connected to.
            @param service_id (int) - Service id of the service for which to set the expression.
            @param method (string) - The set method name.
            @param parameters (dictonary) - Parameters to set the expression of the math service.
                                    
            @return (bool) - Boolean indicating whether ServicesSetMethod was successful.
        """
        if self.__SenseApiCall__('/sensors/{0}/services/{1}/{2}.json'.format(sensor_id, service_id, method), 'POST', parameters = parameters):
            return True
        else:
            self.__error__ = "api call unsuccessful"
            return False

    def ServicesGetMetod (self, sensor_id, service_id, method):
        """
            Set expression for the math service.
            
            @param sensor_id (int) - Sensor id of the sensor the service is connected to.
            @param service_id (int) - Service id of the service for which to set the expression.
            @param method (string) - The get method name.
                    
            @return (bool) - Boolean indicating whether ServicesSetExpression was successful.
        """
        if self.__SenseApiCall__('/sensors/{0}/services/{1}/{2}.json'.format(sensor_id, service_id, method), 'GET'):
            return True
        else:
            self.__error__ = "api call unsuccessful"
            return False



    def ServicesSetUseDataTimestamp(self, sensor_id, service_id, parameters):
        """
            Indicate whether a math service should use the original timestamps of the incoming data, or let CommonSense timestamp the aggregated data.
            
            @param sensors_id (int) - Sensor id of the sensor the service is connected to.
            @param service_id (int) - Service id of the service for which to set the expression.
            @param parameters (dictonary) - Parameters to set the expression of the math service.
                    @note - http://www.sense-os.nl/85?nodeId=85&selectedId=11887
                    
            @return (bool) - Boolean indicating whether ServicesSetuseDataTimestamp was successful.
        """
        if self.__SenseApiCall__('/sensors/{0}/services/{1}/SetUseDataTimestamp.json'.format(sensor_id, service_id), 'POST', parameters = parameters):
            return True
        else:
            self.__error__ = "api call unsuccessful"
            return False


#============
# U S E R S =
#============
    def CreateUser_Parameters(self):
        return {'user':{'email':'user@example.com', 'username':'herpaderp', 'password':'098f6bcd4621d373cade4e832627b4f6', 'name':'foo', 'surname':'bar', 'mobile':'0612345678'}}


    def CreateUser (self, parameters):
        """
            Create a user
            This method creates a user and returns the user object and session
            
            @param parameters (dictionary) - Parameters according to which to create the user.        
        """
        print "Creating user"
        print parameters
        if self.__SenseApiCall__('/users.json', 'POST', parameters = parameters):
            return True
        else:
            self.__error__ = "api call unsuccessful"
            return False

    def CreateUserNoEmail (self, parameters):
        if self.__SenseApiCall__('/users.json?disable_mail=1', 'POST', parameters = parameters):
            return True
        else:
            self.__error__ = "api call unsuccessful"
            return False

    def UsersGetCurrent (self):
        """
            Obtain details of current user. 
            If successful, result can be obtained by a call to getResponse(), and should be a json string.
            
            @return (bool) - Boolean indicating whether UsersGetCurrent was successful.
        """
        if self.__SenseApiCall__('/users/current.json', 'GET'):
            return True
        else:
            self.__error__ = "api call unsuccessful"
            return False

    def UsersUpdate (self, user_id, parameters):
        """
            Update the current user.
            
            @param user_id (int) - id of the user to be updated
            @param parameters (dictionary) - user object to update the user with
            
            @return (bool) - Boolean indicating whether UserUpdate was successful.
        """
        if self.__SenseApiCall__('/users/{0}.json'.format(user_id), 'PUT', parameters):
            return True
        else:
            self.__error__ = "api call unsuccessful"
            return False

    def UsersChangePassword (self, current_password, new_password):
        """
            Change the password for the current user
            
            @param current_password (string) - md5 hash of the current password of the user
            @param new_password (string) - md5 hash of the new password of the user (make sure to doublecheck!)
            
            @return (bool) - Boolean indicating whether ChangePassword was successful.
        """
        if self.__SenseApiCall__('/change_password', "POST", {"current_password":current_password, "new_password":new_password}):
            return True
        else:
            self.__error__ = "api call unsuccessful"
            return False

    def UsersDelete (self, user_id):
        """
            Delete user. 
            
            @return (bool) - Boolean indicating whether UsersDelete was successful.
        """
        if self.__SenseApiCall__('/users/{user_id}.json'.format(user_id = user_id), 'DELETE'):
            return True
        else:
            self.__error__ = "api call unsuccessful"
            return False

#==============
# E V E N T S =
#==============
    def EventsNotificationsGet(self, event_notification_id = -1):
        """
            Retrieve either all notifications or the notifications attached to a specific event.
            If successful, result can be obtained by a call to getResponse(), and should be a json string.
            
            @param event_notification_id (int) (optional) - Id of the event-notification to retrieve details from.
            
            @return (bool) - Boolean indicating whether EventsNotificationsGet was successful.
        """
        if event_notification_id == -1:
            url = '/events/notifications.json'
        else:
            url = '/events/notifications/{0}.json'.format(event_notification_id)

        if self.__SenseApiCall__(url, 'GET'):
            return True
        else:
            self.__error__ = "api call unsuccessful"
            return False

    def EventsNotificationsDelete(self, event_notification_id):
        """
            Delete an event-notification from CommonSense.
            
            @param event_notification_id (int) - Id of the event-notification to delete.
            
            @return (bool) - Boolean indicating whether EventsNotificationsDelete was successful.
        """
        if self.__SenseApiCall__('/events/notifications/{0}.json'.format(event_notification_id), 'DELETE'):
            return True
        else:
            self.__error__ = "api call unsuccessful"
            return False

    def EventsNotificationsPost_Parameters(self):
        return {'event_notification':{'name':'my_event', 'event':'add_sensor', 'notification_id':0, 'priority':0}}

    def EventsNotificationsPost(self, parameters):
        """
            Create an event-notification in CommonSense.
            If EvensNotificationsPost was successful the result, including the event_notification_id can be obtained from getResponse(), and should be a json string.
            
            @param parameters (dictionary) - Parameters according to which to create the event notification.
                    @note - 
                    
            @return (bool) - Boolean indicating whether EventsNotificationsPost was successful. 
        """
        if self.__SenseApiCall__('/events/notifications.json', 'POST', parameters = parameters):
            return True
        else:
            self.__error__ = "api call unsuccessful"
            return False

#==================
# T R I G G E R S =
#==================
    def TriggersGet(self, trigger_id = -1):
        """
            Retrieve either all triggers or the details of a specific trigger.
            If successful, result can be obtained by a call to getResponse(), and should be a json string.

            @param trigger_id (int) (optional) - Trigger id of the trigger to retrieve details from.
            
            @param (bool) - Boolean indicating whether TriggersGet was successful.
        """
        if trigger_id == -1:
            url = '/triggers.json'
        else:
            url = '/triggers/{0}.json'.format(trigger_id)
        if self.__SenseApiCall__(url, 'GET'):
            return True
        else:
            self.__error__ = "api call unsuccessful"
            return False

    def TriggersDelete(self, trigger_id):
        """
            Delete a trigger from CommonSense.
            
            @param trigger_id (int) - Trigger id of the trigger to delete.
            
            @return (bool) - Boolean indicating whether TriggersDelete was successful.
        """
        if self.__SenseApiCall__('/triggers/{0}'.format(trigger_id), 'DELETE'):
            return True
        else:
            self.__error__ = "api call unsuccessful"
            return False

    def TriggersPost_Parameters(self):
        return {'trigger':{'name':'', 'expression':'', 'inactivity':0}}

    def TriggersPost(self, parameters):
        """
            Create a trigger on CommonSense.
            If TriggersPost was successful the result, including the trigger_id, can be obtained from getResponse().
            
            @param parameters (dictionary) - Parameters of the trigger to create.
                    @note 
                    
            @return (bool) - Boolean indicating whether TriggersPost was successful.
        """
        if self.__SenseApiCall__('/triggers.json', 'POST', parameters = parameters):
            return True
        else:
            self.__error__ = "api call unsuccessful"
            return False

#=================================
# S E N S O R S  T R I G G E R S =
#=================================
    def SensorsTriggersGet(self, sensor_id, trigger_id = -1):
        """
            Obtain either all triggers connected to a sensor, or the details of a specific trigger connected to a sensor.
            If successful, result can be obtained from getResponse(), and should be a json string.
            
            @param sensor_id (int) - Sensor id of the sensor to retrieve triggers from.
            @param trigger_id (int) (optional) - Trigger id of the trigger to retrieve details from.
            
            @return (bool) - Boolean indicating whether SensorsTriggersGet was successful.
        """
        if trigger_id == -1:
            url = '/sensors/{0}/triggers.json'.format(sensor_id)
        else:
            url = '/sensors/{0}/triggers/{1}.json'.format(sensor_id, trigger_id)

        if self.__SenseApiCall__(url, 'GET'):
            return True
        else:
            self.__error__ = "api call unsuccessful"
            return False

    def SensorsTriggersDelete(self, sensor_id, trigger_id):
        """
            Disconnect a trigger from a sensor in CommonSense
            
            @param sensor_id (int) - Sensor id of the sensor to disconnect a trigger from.
            @param trigger_id (int) - Trigger id of the trigger to disconnect.
            
            @return (bool) - Boolean indicating whether SensorsTriggersDelete was successful.
        """
        if self.__SenseApiCall__('/sensors/{0}/triggers/{1}.json'.format(sensor_id, trigger_id), 'DELETE'):
            return True
        else:
            self.__error__ = "api call unsuccessful"
            return False

    def SensorsTriggersPost_Parameters(self):
        return {'trigger':{'id':0}}

    def SensorsTriggersPost(self, sensor_id, parameters):
        """
            Connect a trigger to a sensor in CommonSense.
            
            @param sensor_id (int) - Sensor id of the sensor to connect a trigger to.
            @param parameters (dictionary) - Dictionary containing the details of the trigger.
                    @note - 
                    
            @return (bool) - Boolean indicating whether SensorsTriggersPost was successeful.
        """
        if self.__SenseApiCall__('/sensors/{0}/triggers'.format(sensor_id), 'POST', parameters):
            return True
        else:
            self.__error__ = "api call unsuccessful"
            return False

    def SensorsTriggersPut(self, sensor_id, trigger_id, parameters):
        """
            Update a trigger of a sensor in CommonSense.
            
            @param sensor_id (int) - Sensor id of the sensor to connect a trigger to.
            @param trigger_id (int) - Trigger id of the trigger connected to the sensor.
            @param parameters (dictionary) - Dictionary containing the details of the trigger.
                    @note - 
                    
            @return (bool) - Boolean indicating whether SensorsTriggersPost was successeful.
        """
        if self.__SenseApiCall__('/sensors/{0}/trigger/{1}.json'.format(sensor_id, trigger_id), 'PUT', parameters):
            return True
        else:
            self.__error__ = "api call unsuccessful"
            return False

    def SensorsTriggersToggleActive_Parameters(self):
        return {'active':1}

    def SensorsTriggersToggleActive(self, sensor_id, trigger_id, parameters):
        """
            Enable a sensor trigger
            
            @param sensor_id (int) - Sensor id of the sensor connected to the trigger.
            @param trigger_id (int) - Trigger id of the trigger connected to the sensor.
            @param parameters (dictionary) - Dictionary containing the details for toggeling the activation.
                    @note - 
                    
            @return (bool) - Boolean indicating whether SensorsTriggersEnable was successeful.
        """
        if self.__SenseApiCall__('/sensors/{0}/triggers/{1}/active'.format(sensor_id, trigger_id), 'POST', parameters):
            return True
        else:
            self.__error__ = "api call unsuccessful"
            return False

# TODO: SensorsTriggerPut

#============================================================
# S E N S O R S  T R I G G E R S  N O T I F I C A T I O N S =
#============================================================
    def SensorsTriggersNotificationsGet(self, sensor_id, trigger_id):
        """
            Obtain all notifications connected to a sensor-trigger combination.
            If successful, the result can be obtained from getResponse(), and should be a json string.
            
            @param sensor_id (int) - Sensor id if the sensor-trigger combination.
            @param trigger_id (int) - Trigger id of the sensor-trigger combination.
            
            @return (bool) - Boolean indicating whether SensorstriggersNoticiationsGet was successful.
        """
        if self.__SenseApiCall__('/sensors/{0}/triggers/{1}/notifications.json'.format(sensor_id, trigger_id), 'GET'):
            return True
        else:
            self.__error__ = "api call unsuccessful"
            return False

    def SensorsTriggersNotificationsDelete(self, sensor_id, trigger_id, notification_id):
        """
            Disconnect a notification from a sensor-trigger combination.
            
            @param sensor_id (int) - Sensor id if the sensor-trigger combination.
            @param trigger_id (int) - Trigger id of the sensor-trigger combination.
            @param notification_id (int) - Notification id of the notification to disconnect.
            
            @param (bool) - Boolean indicating whether SensorstriggersNotificationsDelete was successful.            
        """
        if self.__SenseApiCall__('/sensors/{0}/triggers/{1}/notifications/{2}.json'.format(sensor_id, trigger_id, notification_id), 'DELETE'):
            return True
        else:
            self.__error__ = "api call unsuccessful"
            return False

    def SensorsTriggersNotificationsPost_Parameters(self):
        return {'notification':{'id':0}}

    def SensorsTriggersNotificationsPost(self, sensor_id, trigger_id, parameters):
        """
            Connect a notification to a sensor-trigger combination.
            
            @param sensor_id (int) - Sensor id if the sensor-trigger combination.
            @param trigger_id (int) - Trigger id of the sensor-trigger combination.
            @param parameters (dictionary) - Dictionary containing the notification to connect.
                    @note - 
                    
            @return (bool) - Boolean indicating whether SensorsTriggersNotificationsPost was successful.            
        """
        if self.__SenseApiCall__('/sensors/{0}/triggers/{1}/notifications.json'.format(sensor_id, trigger_id), 'POST', parameters = parameters):
            return True
        else:
            self.__error__ = "api call unsuccessful"
            return False

#============================
# N O T I F I C A T I O N S =
#============================
    def NotificationsGet(self, notification_id = -1):
        """
            Obtain either all notifications from CommonSense, or the details of a specific notification.
            If successful, the result can be obtained from getResponse(), and should be a json string.
            
            @param notification_id (int) (optional) - Notification id of the notification to obtain details from.
            
            @return (bool) - Boolean indicating whether NotificationsGet was successful.
        """
        if notification_id == -1:
            url = '/notifications.json'
        else:
            url = '/notifications/{0}.json'.format(notification_id)

        if self.__SenseApiCall__(url, 'GET'):
            return True
        else:
            self.__error__ = "api call unsuccessful"
            return False

    def NotificationsDelete(self, notification_id):
        """
            Delete a notification from CommonSense.
            
            @param notification_id (int) - Notification id of the notification to delete.
            
            @return (bool) - Boolean indicating whether NotificationsDelete was successful.
        """
        if self.__SenseApiCall__('/notifications/{0}.json'.format(notification_id), 'DELETE'):
            return True
        else:
            self.__error__ = "api call unsuccessful"
            return False

    def NotificationsPost_Parameters(self):
        return {'notification':{'type':'url, email', 'text':'herpaderp', 'destination':'http://api.sense-os.nl/scripts'}}

    def NotificationsPost(self, parameters):
        """
            Create a notification on CommonSense.
            If successful the result, including the notification_id, can be obtained from getResponse(), and should be a json string.
            
            @param parameters (dictionary) - Dictionary containing the notification to create.
                    @note - 
                    
            @return (bool) - Boolean indicating whether NotificationsPost was successful.
        """
        if self.__SenseApiCall__('/notifications.json', 'POST', parameters = parameters):
            return True
        else:
            self.__error__ = "api call unsuccessful"
            return False

#================
# D E V I C E S =
#================

    def DevicesGet(self):
        """
            Retrieve all devices for the user.

            @return (bool) - Boolean indicating whether DevicesGet was successful.
        """
        if self.__SenseApiCall__('/devices', 'GET'):
            return True
        else:
            self.__error__ = "api call unsuccessful"
            return False

    def DeviceGet(self, device_id):
        """
            Obtain details of a single device

            @param device_id (int) - Device for which to obtain details
        """
        if self.__SenseApiCall__('/devices/{0}'.format(device_id), 'GET'):
            return True
        else:
            self.__error__ = "api call unsuccessful"
            return False


    def DeviceSensorsGet_Parameters(self):
        return {"page": 0, "per_page": 100, "details": "full"}

    def DeviceSensorsGet(self, device_id, parameters):
        """
            Obtain a list of all sensors attached to a device.

            @param device_id (int) - Device for which to retrieve sensors
            @param parameters (dict) - Search parameters

            @return (bool) - Boolean indicating whether DeviceSensorsGet was succesful.
        """
        if self.__SenseApiCall__('/devices/{0}/sensors.json'.format(device_id), 'GET', parameters = parameters):
            return True
        else:
            self.__error__ = "api call unsuccessful"
            return False

    def SensorAddToDevice_Parameters(self):
        return {'device':{'id':0, 'type':'', 'uuid':0}}

    def SensorAddToDevice(self, sensor_id, parameters):
        """
            Add a sensor to a device in CommonSense. 
            If successful, the result, including the device_id, can be obtained from getResponse(), and should be a json string.
            
            @param sensor_id (int) - Sensor id of the sensor to add to a device.
            @param parameters (dictionary) - Dictionary containing the device to attach the sensor to.
            
            @return (bool) - Boolean indicating whether SensorAddToDevice was successful.
        """
        if self.__SenseApiCall__('/sensors/{0}/device.json'.format(sensor_id), 'POST', parameters = parameters):
            return True
        else:
            self.__error__ = "api call unsuccessful"
            return False

#==============
# G R O U P S =
#==============
    def GroupsGet_Parameters(self):
        return {'page':0, 'per_page':100, 'total':0, 'public':0 }

    def GroupsGet(self, parameters = None, group_id = -1):
        """
            Retrieve groups from CommonSense, according to parameters, or by group id. 
            If successful, result can be obtained by a call to getResponse(), and should be a json string.
            
            @param parameters (dictionary) (optional) - Dictionary containing the parameters for the api-call.
            @param group_id (int) (optional) - Id of the group to retrieve details from.
            
            @return (boolean) - Boolean indicating whether GroupsGet was successful.
        """
        if parameters is None and group_id == -1:
            self.__error__ = "no arguments"
            return False

        url = ''
        if group_id is -1:
            url = '/groups.json'
        else:
            url = '/groups/{0}.json'.format(group_id)

        if self.__SenseApiCall__(url, 'GET', parameters = parameters):
            return True
        else:
            self.__error__ = "api call unsuccessful"
            return False

    def GroupsDelete(self, group_id):
        """
            Delete a group from CommonSense.
            
            @param group_id (int) - group id of group to delete from CommonSense.
            
            @return (bool) - Boolean indicating whether GroupsDelete was successful.
        """
        if self.__SenseApiCall__('/groups/{0}.json'.format(group_id), 'DELETE'):
            return True
        else:
            self.__error__ = "api call unsuccessful"
            return False

    def GroupsPost_Parameters(self):
        return {'group': {'name':''}}

    def GroupsPost(self, parameters):
        """
            Create a group in CommonSense.
            If GroupsPost is successful, the group details, including its group_id, can be obtained by a call to getResponse(), and should be a json string.
            
            @param parameters (dictonary) - Dictionary containing the details of the group to be created. 
                                    
            @return (bool) - Boolean indicating whether GroupsPost was successful.
        """
        if self.__SenseApiCall__('/groups.json', 'POST', parameters = parameters):
            return True
        else:
            self.__error__ = "api call unsuccessful"
            return False

    def GroupsPut_Parameters(self):
        return self.GroupsPost_Parameters()

    def GroupsPut(self, parameters, group_id):
        """
            Update a group in CommonSense.
            If GroupsPut is successful, the group details, including its group_id, can be obtained by a call to getResponse(), and should be a json string.
            
            @param parameters (dictonary) - Dictionary containing the details of the group to be created. 
                                    
            @return (bool) - Boolean indicating whether GroupsPost was successful.
        """
        if self.__SenseApiCall__('/groups/{group_id}'.format(group_id = group_id), 'PUT', parameters = parameters):
            return True
        else:
            self.__error__ = "api call unsuccessful"
            return False

#============================
# G R O U P S  &  U S E R S =
#============================

    def GroupsUsersGet_Parameters(self):
        return {'details': 'full'}

    def GroupsUsersGet(self, parameters, group_id):
        """
            List users to a group in CommonSense.
            
            @param parameters (dictonary) - Dictionary containing the parameters of the request.
                                    
            @return (bool) - Boolean indicating whether GroupsPost was successful.
        """
        if self.__SenseApiCall__('/groups/{group_id}/users.json'.format(group_id = group_id), 'GET', parameters = parameters):
            return True
        else:
            self.__error__ = "api call unsuccessful"
            return False

    def GroupsUsersPost_Parameters(self):
        return {"users":[{"user":{"id":"", "username":""}}]}

    def GroupsUsersPost(self, parameters, group_id):
        """
            Add users to a group in CommonSense.
            
            @param parameters (dictonary) - Dictionary containing the users to add.
                                    
            @return (bool) - Boolean indicating whether GroupsPost was successful.
        """
        if self.__SenseApiCall__('/groups/{group_id}/users.json'.format(group_id = group_id), 'POST', parameters = parameters):
            return True
        else:
            self.__error__ = "api call unsuccessful"
            return False

    def GroupsUsersDelete(self, group_id, user_id):
        """
            Delete a user from a group in CommonSense.
            
            @return (bool) - Boolean indicating whether GroupsPost was successful.
        """
        if self.__SenseApiCall__('/groups/{group_id}/users/{user_id}.json'.format(group_id = group_id, user_id = user_id), 'DELETE'):
            return True
        else:
            self.__error__ = "api call unsuccessful"
            return False

#==============
# S T A T E S =
#==============
    def StatesDefaultCheck(self):
        """
            Create default states.
            @return (bool) - Boolean indicating wether this request was successful.
        """
        if self.__SenseApiCall__('/states/default/check.json', 'GET'):
            return True
        else:
            self.__error__ = "api call unsuccessful"
            return False


#================================
# G R O U P S  &  S E N S O R S =
#================================
    def GroupsSensorsPost(self, group_id, sensors):
        """
            Share a number of sensors within a group.
            
            @param group_id (int) - Id of the group to share sensors with
            @param sensors (dictionary) - Dictionary containing the sensors to share within the groups
            
            @return (bool) - Boolean indicating whether the GroupsSensorsPost call was successful
        """
        if self.__SenseApiCall__("/groups/{0}/sensors.json".format(group_id), "POST", parameters = sensors):
            return True
        else:
            self.__error__ = "api call unsuccessful"
            return False

    def GroupsSensorsGet(self, group_id, parameters):
        """
            Retrieve sensors shared within the group.
            
            @param group_id (int) - Id of the group to retrieve sensors from
            @param parameters (dictionary) - Additional parameters for the call
            
            @return (bool) - Boolean indicating whether GroupsSensorsGet was successful
        """
        if self.__SenseApiCall("/groups/{0}/sensors.json".format(group_id), "GET", parameters = parameters):
            return True
        else:
            self.__error__ = "api call unsuccessful"
            return False

    def GroupsSensorsDelete(self, group_id, sensor_id):
        """
            Stop sharing a sensor within a group
            
            @param group_id (int) - Id of the group to stop sharing the sensor with
            @param sensor_id (int) - Id of the sensor to stop sharing
            
            @return (bool) - Boolean indicating whether GroupsSensorsDelete was successful
        """
        if self.__SenseApiCall__("/groups/{0}/sensors/{1}.json".format(group_id, sensor_id), "DELETE"):
            return True
        else:
            self.__error__ = "api call unsuccessful"
            return False

#================
# D O M A I N S =
#================
    def DomainsGet_Parameters(self):
        return {'details': 'full', 'page':0, 'per_page':100, 'total':0, 'member_type':'member'}

    def DomainsGet(self, parameters = None, domain_id = -1):
        """
            This method returns the domains of the current user. 
            The list also contains the domains to which the users has not yet been accepted.
            
            @param parameters (dictonary) - Dictionary containing the parameters of the request.
                                    
            @return (bool) - Boolean indicating whether DomainsGet was successful.
        """
        url = ''
        if parameters is None and domain_id <> -1:
            url = '/domains/{0}.json'.format(domain_id)
        else:
            url = '/domains.json'

        if self.__SenseApiCall__(url, 'GET', parameters = parameters):
            return True
        else:
            self.__error__ = "api call unsuccessful"
            return False

    def DomainUsersGet_Parameters(self):
        return {'page':0, 'per_page':100, 'sort':'ASC', 'sort_field':''}

    def DomainUsersGet(self, domain_id, parameters):
        """
            Retrieve users of the specified domain.
            
            @param domain_id (int) - Id of the domain to retrieve users from
            @param parameters (int) - parameters of the api call.
            
            @return (bool) - Boolean idicating whether DomainUsersGet was successful.
        """
        if self.__SenseApiCall__('/domains/{0}/users.json'.format(domain_id), 'GET', parameters = parameters):
            return True
        else:
            self.__error__ = "api call unsuccessful"
            return False

    def DomainAddUserPost_Parameters(self):
        return {'users': [{'id':'1'}]}

    def DomainAddUserPost(self, parameters, domain_id):
        """
        This method adds users to the domain as a domain member. 
        Domain managers can add users to their domain. 
        Users who add themselfs to a domain will have the accepted status false until a manager accepts the user by adding a users via this method. 
        Users with a token can add themselfs to the group as member and will receive the accepted status. 
        Tokens can only be used one time for one user.
        
        @param parameters (dictonary) - Dictionary containing the users to add to the domain. 
                                
        @return (bool) - Boolean indicating whether DomainAddUser was successful.
        """
        if self.__SenseApiCall__('/domains/{0}/users.json'.format(domain_id), 'POST', parameters = parameters):
            return True
        else:
            self.__error__ = "api call unsuccessful"
            return False

    def DomainTokensGet(self, domain_id):
        """
            T his method returns the list of tokens which are available for this domain. 
            Only domain managers can list domain tokens.
            
            @param domain_id - ID of the domain for which to retrieve tokens
            
            @return (bool) - Boolean indicating whether DomainTokensGet was successful
        """
        if self.__SenseApiCall__('/domains/{0}/tokens.json'.format(domain_id), 'GET'):
            return True
        else:
            self.__error__ = "api call unsuccessful"
            return False

    def DomainTokensCreate(self, domain_id, amount):
        """
            This method creates tokens that can be used by users who want to join the domain. 
            Tokens are automatically deleted after usage. 
            Only domain managers can create tokens.
        """
        if self.__SenseApiCall__('/domains/{0}/tokens.json'.format(domain_id), 'POST', parameters = {"amount":amount}):
            return True
        else:
            self.__error__ = "api call unsuccessful"
            return False

#=============================
# D A T A  P R O C E S S O R =
#=============================
    def DataProcessorsGet_Parameters(self):
        return {"total":0, "page":0, "per_page":1000}

    def DataProcessorsGet(self, parameters):
        """
            List the users data processors.

            @param parameters (dictonary) - Dictionary containing the parameters of the request.
                                    
            @return (bool) - Boolean indicating whether this call was successful.
        """
        if self.__SenseApiCall__('/dataprocessors.json', 'GET', parameters = parameters):
            return True
        else:
            self.__error__ = "api call unsuccessful"
            return False

    def DataProcessorsPost_Parameters(self):
        return {'dataprocessor':{'command':'', 'execution_interval':'', 'last_start_time':''}, 'sensor': {'name':'', 'display_name':'', 'device_type':'', 'data_type':'', 'data_structure':''}}

    def DataProcessorsPost(self, parameters):
        """
            Create a Data processor  in CommonSense.
            If DataProcessorsPost is successful, the data processor and sensor details, including its sensor_id, can be obtained by a call to getResponse(), and should be a json string.
            
            @param parameters (dictonary) - Dictionary containing the details of the data processor to be created. 
                    @note - http://www.sense-os.nl/46?nodeId=46&selectedId=11887            
                                    
            @return (bool) - Boolean indicating whether DataProcessorPost was successful.
        """
        if self.__SenseApiCall__('/dataprocessors.json', 'POST', parameters = parameters):
            return True
        else:
            self.__error__ = "api call unsuccessful"
            return False

    def DataProcessorsDelete(self, dataProcessorId):
        """
            Delete a data processor in CommonSense.
            
            @param dataProcessorId - The id of the data processor that will be deleted.
                                    
            @return (bool) - Boolean indicating whether GroupsPost was successful.
        """
        if self.__SenseApiCall__('/dataprocessors/{id}.json'.format(id = dataProcessorId), 'DELETE'):
            return True
        else:
            self.__error__ = "api call unsuccessful"
            return False

    def DataProcessorsPut(self, dataProcessorId, parameters):
        if self.__SenseApiCall__('/dataprocessors/{id}.json'.format(id = dataProcessorId), 'PUT', parameters):
            return True
        else:
            self.__error__ = "api call unsuccessful"
            return False

#==================================
# N O N  C L A S S  M E T H O D S =
#==================================
def MD5Hash(password):
    """
        Returns md5 hash of a string.
        
        @param password (string) - String to be hashed.
        
        @return (string) - Md5 hash of password.
    """
    md5_password = md5.new(password)
    password_md5 = md5_password.hexdigest()
    return password_md5



