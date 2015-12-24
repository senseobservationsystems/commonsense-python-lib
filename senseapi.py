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
        Class for interacting with the Sensor Api. 
        
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
        self.__server_url__ = 'sensor-api.sense-os.nl'
        self.__authentication__ = 'not_authenticated'
        self.__server_auth_url__ = 'auth-api.sense-os.nl'
        self.__oauth_consumer__ = {}
        self.__oauth_token__ = {}
        self.__use_https__ = True
        self.__app_key__ = ""

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
            self.__server_url__ = 'sensor-api.sense-os.nl'
            self.__server_auth_url__ = 'auth-api.sense-os.nl'
            self.setUseHTTPS()
            return True
        elif server == 'dev':
            self.__server__ = server
            self.__server_url__ = 'sensor-api.staging.sense-os.nl'
            self.__server_auth_url__ = 'auth-api.staging.sense-os.nl'
            # the dev server doesn't support https
            self.setUseHTTPS(False)
            return True
        elif server == 'rc':
            self.__server__ = server
            self.__server_url__ = 'sensor-api.staging.sense-os.nl'
            self.__server_auth_url__ = 'auth-api.staging.sense-os.nl'
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
        if not (method in ['session_id', 'authenticating_session_id', 'not_authenticated']):
            return False
        else:
            self.__authentication__ = method
            return True
            
    def setAppKey(self, appKey):
        self.__app_key__ = appKey


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

#=======================================
    # B A S E  A P I  C A L L  M E T H O D =
#=======================================
    def __SenseApiCall__ (self, url, method, parameters = None, headers = {}, authenticate = False):
        heads = {'APPLICATION-KEY': self.__app_key__}
        heads.update(headers)
        body = ''
        http_url = url
        server_url = ''
        if authenticate:
            server_url = self.__server_auth_url__
        else:
            server_url = self.__server_url__
            
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
            oauth_url = 'http://{0}{1}'.format(server_url, url)
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
            heads.update({'SESSION-ID':"{0}".format(self.__session_id__)})
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
            connection = httplib.HTTPSConnection(server_url, timeout = 60)
        else:
            connection = httplib.HTTPConnection(server_url, timeout = 60)

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
        if self.__SenseApiCall__("/v1/login", "POST", parameters = parameters, authenticate = True):
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
        if self.__SenseApiCall__('/v1/logout', 'POST', authenticate = True):
            self.__setAuthenticationMethod__('not_authenticated')
            return True
        else:
            self.__error__ = "api call unsuccessful"
            return False

    def Login (self, username, password):
        """
            Deprecated, use AuthenticateSessionId instead
        """
        return self.AuthenticateSessionId(username, password)

    def Logout (self):
        """
            Deprecated, use LogoutSessionId instead
        """
        return self.LogoutSessionId()



#================
# S E N S O R S =
#================
    def SensorsGet(self):
        """
            Retrieve sensors from CommonSense, according to parameters, or by sensor id. 
            If successful, result can be obtained by a call to getResponse(), and should be a json string.
            
            @param parameters (dictionary) (optional) - Dictionary containing the parameters for the api-call.
                    @note - http://www.sense-os.nl/45?nodeId=45&selectedId=11887
            @param sensor_id (int) (optional) - Sensor id of sensor to retrieve details from.
            
            @return (boolean) - Boolean indicating whether SensorsGet was successful.
        """
        url = '/sensors'

        if self.__SenseApiCall__(url, 'GET', parameters = None):
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

#=======================
# S E N S O R  D A T A =
#=======================
    def SensorDataGet_Parameters(self):
        return {'limit':100, 'start_time':0, 'end_time':4294967296000, 'sort':'ASC'}

    def SensorDataGet(self, sourceName, sensorName, parameters = None):
        """
            Retrieve sensor data for a specific sensor from CommonSense.
            If SensorDataGet is successful, the result can be obtained by a call to getResponse(), and should be a json string.
            
            @param sourceName (string) - The source name of the sensor
            @param sensorName (string) - The sensor name
            @param parameters (dictionary) - Dictionary containing the parameters for the api call.
                    @note - http://www.sense-os.nl/52?nodeId=52&selectedId=11887
                    
            @return (bool) - Boolean indicating whether SensorDataGet was successful.
        """
        if parameters is None:
                parameters = {}
        if self.__SenseApiCall__('/sensor_data/{0}/{1}'.format(sourceName, sensorName), 'GET', parameters = parameters):
            return True
        else:
            self.__error__ = "api call unsuccessful"
            return False

    def SensorDataPost(self, sourceName, sensorName, parameters = None):
        """
            Post sensor data to a specific sensor in CommonSense.
            
            @param sourceName (string) - The source name of the sensor
            @param sensorName (string) - The sensor name
            @param parameters (dictionary) - Data to post to the sensor.
                    @note - http://www.sense-os.nl/53?nodeId=53&selectedId=11887
        """
        if self.__SenseApiCall__('/sensors/{0}/data.json'.format(sensor_id), 'POST', parameters = parameters):
            return True
        else:
            self.__error__ = "api call unsuccessful"
            return False

    def SensorDataDelete(self,sourceName, sensorName, parameters = None):
        """
            Delete a sensor datum from a specific sensor in CommonSense.
            
            @param sourceName (string) - The source name of the sensor
            @param sensorName (string) - The sensor name
            @param parameters (dictionary) - The selection criteria
            
            @return (bool) - Boolean indicating whether SensorDataDelete was successful. 
        """
        if self.__SenseApiCall__('/sensor_data/{0}/{1}'.format(sourceName, sensorName), 'DELETE', parameters = parameters):
            return True
        else:
            self.__error_ = "api call unsuccessful"
            return False

    # def SensorsDataPost(self, parameters):
    #     """
    #         Post sensor data to multiple sensors in CommonSense simultaneously.
            
    #         @param parameters (dictionary) - Data to post to the sensors.
    #                 @note - http://www.sense-os.nl/59?nodeId=59&selectedId=11887
                    
    #         @return (bool) - Boolean indicating whether SensorsDataPost was successful.
    #     """
    #     if self.__SenseApiCall__('/sensors/data.json', 'POST', parameters = parameters):
    #         return True
    #     else:
    #         self.__error__ = "api call unsuccessful"
    #         return False

#============
# U S E R S =
#============
    # def CreateUser_Parameters(self):
    #     return {'user':{'email':'user@example.com', 'username':'herpaderp', 'password':'098f6bcd4621d373cade4e832627b4f6', 'name':'foo', 'surname':'bar', 'mobile':'0612345678'}}


    # def CreateUser (self, parameters):
    #     """
    #         Create a user
    #         This method creates a user and returns the user object and session
            
    #         @param parameters (dictionary) - Parameters according to which to create the user.        
    #     """
    #     print "Creating user"
    #     print parameters
    #     if self.__SenseApiCall__('/users.json', 'POST', parameters = parameters):
    #         return True
    #     else:
    #         self.__error__ = "api call unsuccessful"
    #         return False

    # def CreateUserNoEmail (self, parameters):
    #     if self.__SenseApiCall__('/users.json?disable_mail=1', 'POST', parameters = parameters):
    #         return True
    #     else:
    #         self.__error__ = "api call unsuccessful"
    #         return False

    # def UsersGetCurrent (self):
    #     """
    #         Obtain details of current user. 
    #         If successful, result can be obtained by a call to getResponse(), and should be a json string.
            
    #         @return (bool) - Boolean indicating whether UsersGetCurrent was successful.
    #     """
    #     if self.__SenseApiCall__('/users/current.json', 'GET'):
    #         return True
    #     else:
    #         self.__error__ = "api call unsuccessful"
    #         return False

    # def UsersUpdate (self, user_id, parameters):
    #     """
    #         Update the current user.
            
    #         @param user_id (int) - id of the user to be updated
    #         @param parameters (dictionary) - user object to update the user with
            
    #         @return (bool) - Boolean indicating whether UserUpdate was successful.
    #     """
    #     if self.__SenseApiCall__('/users/{0}.json'.format(user_id), 'PUT', parameters):
    #         return True
    #     else:
    #         self.__error__ = "api call unsuccessful"
    #         return False

    # def UsersChangePassword (self, current_password, new_password):
    #     """
    #         Change the password for the current user
            
    #         @param current_password (string) - md5 hash of the current password of the user
    #         @param new_password (string) - md5 hash of the new password of the user (make sure to doublecheck!)
            
    #         @return (bool) - Boolean indicating whether ChangePassword was successful.
    #     """
    #     if self.__SenseApiCall__('/change_password', "POST", {"current_password":current_password, "new_password":new_password}):
    #         return True
    #     else:
    #         self.__error__ = "api call unsuccessful"
    #         return False

    # def UsersDelete (self, user_id):
    #     """
    #         Delete user. 
            
    #         @return (bool) - Boolean indicating whether UsersDelete was successful.
    #     """
    #     if self.__SenseApiCall__('/users/{user_id}.json'.format(user_id = user_id), 'DELETE'):
    #         return True
    #     else:
    #         self.__error__ = "api call unsuccessful"
    #         return False

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



