import md5, urllib, httplib, json, socket, oauth.oauth as oauth, urlparse

class SenseAPI:
	def __init__(self):
		self.session_id = ""
		self.status = 0
		self.headers = []
		self.response = ""
		self.verbose = False
		self.server  = 'live'
		self.server_url ='api.sense-os.nl'
		self.authentication = 'not_authenticated'
		self.oauth_consumer = {}
		self.oauth_token = {}
		
	def setVerbosity(self, verbose):
		if not (verbose == True or verbose == False):
			return False
		else:
			self.verbose = verbose
			return True

	def setServer(self, server):
		if server == 'live':
			self.server = server
			self.server_url = 'api.sense-os.nl'
			return True
		elif server == 'dev':
			self.server = server
			self.server_url = 'api.dev.sense-os.nl'
			return True
		else:
			return False
		
	def setAuthenticationMethod(self, method):
		if not (method == 'session_id' or method == 'oauth' or method == 'authenticating_session_id' or method == 'authenticating_oauth' or method == 'not_authenticated'):
			return False
		else:
			self.authentication = method
			return True
		
########################################
# B A S E  A P I  C A L L  M E T H O D #
########################################
	def SenseApiCall(self, url, method, parameters=None, headers={}):
		heads = headers
		body = ''
		http_url = url
		
		if self.authentication == 'not_authenticated':
			self.status = 401
			return False
		
		elif self.authentication == 'authenticating_oauth':
			heads.update({'X-SESSION_ID':"{0}".format(self.session_id)})
			heads.update({"Content-type": "application/x-www-form-urlencoded", "Accept":"*"})
			if not parameters is None:
				http_url = '{0}?{1}'.format(url, urllib.urlencode(parameters))

		elif self.authentication == 'authenticating_session_id':
			heads.update({"Content-type": "application/json", "Accept":"*"})
			if not parameters is None:
				body = json.dumps(parameters) 

		elif self.authentication == 'oauth':
			oauth_url = 'http://{0}{1}'.format(self.server_url, url)
			oauth_request = oauth.OAuthRequest.from_consumer_and_token(self.oauth_consumer, token=self.oauth_token, http_method=method, http_url=oauth_url)
			oauth_request.sign_request(oauth.OAuthSignatureMethod_HMAC_SHA1(), self.oauth_consumer, self.oauth_token)
			heads.update(oauth_request.to_header())
			if not parameters is None:
				if method == 'GET' or method == 'DELETE':
					heads.update({"Content-type": "application/x-www-form-urlencoded", "Accept":"*"})
					http_url = '{0}?{1}'.format(url, urllib.urlencode(parameters))
				else:
					heads.update({"Content-type": "application/json", "Accept":"*"})
					body = json.dumps(parameters)
			
		elif self.authentication == 'session_id':
			heads.update({'X-SESSION_ID':"{0}".format(self.session_id)})
			if not parameters is None:
				if method == 'GET' or method == 'DELETE':
					heads.update({"Content-type": "application/x-www-form-urlencoded", "Accept":"*"})
					http_url = '{0}?{1}'.format(url, urllib.urlencode(parameters))
				else:
					heads.update({"Content-type": "application/json", "Accept":"*"})
					body = json.dumps(parameters)
		else:
			self.status = 418
			return False

		connection 	= httplib.HTTPSConnection(self.server_url, timeout=60)
			
		try:
			connection.request(method, http_url, body, heads);
			result = connection.getresponse(); 
			connection.close()		
		except: # TODO: check if this doesnt already generate a status
			self.status = 408
			return False

		self.response 	= result.read()
		self.status		= result.status
		self.headers	= result.getheaders()
		
		if self.verbose:
			print "===================CALL==================="
			print "Call: {0} {1}".format(method, http_url)
			print "Server: {0}".format(self.server)
			print "Headers: {0}".format(heads)
			print "Body: {0}".format(body)
			print "==================RESPONSE================"
			print "Status: {0}".format(self.status)
			print "Headers: {0}".format(self.headers)
			print "Response: {0}".format(self.response)
			print "==========================================\n"
		
		if self.status == 200 or self.status == 201 or self.status == 302:
			return True
		else:
			return False
		
###################################################
# S E S S I O N  I D  A U T H E N T I C A T I O N #
###################################################
	def SetSessionId(self, session_id):
		self.session_id = session_id

	def AuthenticateSessionId(self, username, password):
		self.setAuthenticationMethod('authenticating_session_id')
			
		parameters = {'username':username,'password':password}

		if self.SenseApiCall("/login.json", "POST", parameters=parameters):
			try:
				response = json.loads(self.response)
			except: 
				self.setAuthenticationMethod('not_authenticated')
				return False, {'error':'notjson'}
			try: 
				self.session_id = response['session_id']
				self.authentication = 'session_id'		
				return True, response
			except: 
				self.setAuthenticationMethod('not_authenticated')
				return False, {'error':'no session id'}
		else:
			self.setAuthenticationMethod('not_authenticated')
			return False, {'error':self.status}
		
	def LogoutSessionId(self):
		if self.SenseApiCall('/logout.json', 'POST'):
			self.setAuthenticationMethod('not_authenticated')
			return True, {}
		else:
			return False, {'error':self.status}
		
	# deprecated
	def Login (self, username, password):
		return self.AuthenticateSessionId(username, password)
		
	#deprecated
	def Logout (self):
		return self.LogoutSessionId()
	
##########################################		
# O A U T H  A U T H E N T I C A T I O N #
##########################################
	def AuthenticateOauth (self, oauth_token_key, oauth_token_secret, oauth_consumer_key, oauth_consumer_secret):
		self.oauth_consumer = oauth.OAuthConsumer(oauth_consumer_key, oauth_consumer_secret)
		self.oauth_token 	= oauth.OAuthToken(oauth_token_key, oauth_token_secret)
		self.authentication = 'oauth'
		if self.SenseApiCall('/users/current.json', 'GET'):
			try:
				response = json.loads(self.response)
				return True, response
			except:
				return True, {}
		else:
			return False, {}
		
########################################
# O A U T H  A U T H O R I Z A T I O N #
########################################
	def OauthAuthorizeApplication(self, oauth_consumer_key, oauth_consumer_secret, oauth_duration='hour', oauth_callback='http://www.sense-os.nl'):
		if self.session_id == '':
			return False, {'error':'not logged in'}
		
		self.setAuthenticationMethod('authenticating_oauth')
		
	# first obtain a request token
		self.oauth_consumer = oauth.OAuthConsumer(oauth_consumer_key, oauth_consumer_secret)
		oauth_request = oauth.OAuthRequest.from_consumer_and_token(self.oauth_consumer, callback=oauth_callback, http_url='http://api.sense-os.nl/oauth/request_token')
		oauth_request.sign_request(oauth.OAuthSignatureMethod_HMAC_SHA1(), self.oauth_consumer, None)
		
		parameters = []
		for key in oauth_request.parameters.iterkeys():
			parameters.append((key, oauth_request.parameters[key]))
		parameters.sort()

		if self.SenseApiCall('/oauth/request_token', 'GET', parameters=parameters):
			response = urlparse.parse_qs(self.response)
			self.oauth_token = oauth.OAuthToken(response['oauth_token'][0], response['oauth_token_secret'][0])
		else:
			self.setAuthenticationMethod('session_id')
			return False, {'error':'error getting request token'}
		
	#second, automatically get authorization for the application
		parameters 	= {'oauth_token':self.oauth_token.key, 'tok_expir':self.OauthGetTokExpir(oauth_duration), 'action':'ALLOW', 'session_id':self.session_id}
		
		if self.SenseApiCall('/oauth/provider_authorize', 'POST', parameters=parameters):
			if self.status == 302:
				for header in self.headers:
					if header[0] == 'location':
						response = urlparse.parse_qs(header[1])
						self.oauth_token.verifier = response['oauth_verifier'][0]
			else:
				self.setAuthenticationMethod('session_id')
				return False, {'error':'error authorizing application'}
		else:
			self.setAuthenticationMethod('session_id')
			return False, {'error':'error authorizing application'}
		
	#third, obtain access token
		oauth_request = oauth.OAuthRequest.from_consumer_and_token(self.oauth_consumer, callback='', token=self.oauth_token, http_url='http://api.sense-os.nl/oauth/access_token')
		oauth_request.sign_request(oauth.OAuthSignatureMethod_HMAC_SHA1(), self.oauth_consumer, self.oauth_token)
		
		parameters = []
		for key in oauth_request.parameters.iterkeys():
			parameters.append((key, oauth_request.parameters[key]))
		parameters.sort()
		
		if self.SenseApiCall('/oauth/access_token', 'GET', parameters=parameters):
			response = urlparse.parse_qs(self.response)
			self.oauth_token = oauth.OAuthToken(response['oauth_token'][0], response['oauth_token_secret'][0])
			self.setAuthenticationMethod('oauth')
			return True, {'oauth_token':response['oauth_token'][0], 'oauth_token_secret':response['oauth_token_secret'][0]}
		else:
			self.setAuthenticationMethod('session_id')
			return False, {'error':'error getting access token'}		

	def OauthGetTokExpir (self, duration):
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

#################
# S E N S O R S #
#################
	def SensorsGet_Parameters(self):
		return {'page':0, 'per_page':100, 'shared':0, 'owned':0, 'physical':0, 'details':'full'}
		
	def SensorsGet(self, parameters=None, sensor_id=-1):
		if parameters is None and sensor_id == -1:
			return False, {'error':'no arguments'}
		
		url = ''
		if parameters is None:
			url = '/sensors/{0}.json'.format(sensor_id)
		else:
			url = '/sensors.json'
			
		if self.SenseApiCall(url, 'GET', parameters=parameters):
			try:
				response = json.loads(self.response)
				return True, response
			except:
				return True, {}
		else:
			return False, {'error':self.status}
				
	def SensorsDelete(self, sensor_id):
		if self.SenseApiCall('/sensors/{0}.json'.format(sensor_id), 'DELETE'):
			try:
				response = json.loads(self.response)
				return True, response
			except:
				return True, {}
		else:
			return False, {'error':self.status}
				
	def SensorsPost_Parameters(self):
		return {'sensor': {'name':'', 'display_name':'', 'device_type':'', 'pager_type':'', 'data_type':'', 'data_structure':''}}
		
	def SensorsPost(self, parameters):
		if self.SenseApiCall('/sensors.json', 'POST', parameters=parameters):
			try:
				response = json.loads(self.response)
				return True, response
			except:
				return True, {}
		else:
			return False, {'error':self.status}
		
########################
# S E N S O R  D A T A #
########################
	def SensorDataGet_Parameters(self):
		return {'page':0, 'per_page':100, 'start_date':0, 'end_date':4294967296, 'date':0, 'next':0, 'last':0, 'sort':'ASC', 'total':1}
		
	def SensorDataGet(self, sensor_id, parameters):
		if self.SenseApiCall('/sensors/{0}/data.json'.format(sensor_id), 'GET', parameters=parameters):
			try:
				response = json.loads(self.response)
				return True, response
			except:
				return True, {}
		else:	
			return False, {'error':self.status} 
	
	def SensorDataPost(self, sensor_id, parameters):
		if self.SenseApiCall('/sensors/{0}/data.json'.format(sensor_id), 'POST', parameters=parameters):
			try:
				response = json.loads(self.response)
				return True, response
			except:
				return True, {}
		else:
			return False, {'error':self.status}

	def SensorsDataPost(self, parameters):
		if self.SenseApiCall('/sensors/data.json', 'POST', parameters=parameters):
			try:
				response = json.loads(self.response)
				return True, response
			except:
				return True, {}
		else:
			return False, {'error':'{0}: {1}'.format(self.status, self.response)}

###################
# S E R V I C E S #
###################
	def ServicesGet (self, sensor_id):
		if self.SenseApiCall('/sensors/{0}/services.json'.format(sensor_id), 'GET'):
			try:
				response = json.loads(self.response)
				return True, response
			except:
				return True, {}
		else:
			return False, {'error':self.status}

	def ServicesPost_Parameters (self):
		return {'service':{'name':'math_service', 'data_fields':['sensor']}, 'sensor':{'name':'', 'device_type':''}}

	def ServicesPost (self, sensor_id, parameters):
		if self.SenseApiCall('/sensors/{0}/services.json'.format(sensor_id), 'POST', parameters=parameters):
			try:
				response = json.loads(self.response)
				for header in self.headers:
					if header[0] == 'location':
						service_id = header[1].strip('abcdefghijklmnopqrstuvwxyz.:/-')
						response.update({'service[id]':service_id})
				return True, response
			except:
				return True, {}
		else:
			return False, {'error':self.status}
		
	def ServicesDelete (self, sensor_id, service_id):
		if self.SenseApiCall('/sensors/{0}/services/{1}.json'.format(sensor_id, service_id), 'DELETE'):
			try:
				response = json.loads(self.response)
				return True, response
			except:
				return True, {}
		else:
			return False, {'error':self.status}
		
	def ServicesSet_Parameters (self):
			return {'parameters':[]}
		
	def ServicesSetExpression (self, sensor_id, service_id, parameters):
		if self.SenseApiCall('/sensors/{0}/services/{1}/SetExpression.json'.format(sensor_id, service_id), 'POST', parameters=parameters):
			try:
				response = json.loads(self.response)
				return True, response
			except:
				return True, {}
		else:
			return False, {'error':self.status}

	def ServicesSetUseDataTimestamp(self, sensor_id, service_id, parameters):
		if self.SenseApiCall('/sensors/{0}/services/{1}/SetUseDataTimestamp.json'.format(sensor_id, service_id), 'POST', parameters=parameters):
			try:
				response = json.loads(self.response)
				return True, response
			except:
				return True, {}
		else:
			return False, {'error':self.status}
			

#############
# U S E R S #
#############
	def UsersGetCurrent (self):
		if self.SenseApiCall('/users/current.json', 'GET'):
			try:
				response = json.loads(self.response)
				return True, response
			except:
				return True, {}
		else:
			return False, {'error':self.status}
		
###############
# E V E N T S #
###############
	def EventsNotificationsGet(self, event_notification_id = -1):
		if event_notification_id == -1:
			url = '/events/notifications.json'
		else:
			url = '/events/notifications/{0}.json'.format(event_notification_id)
			
		if self.SenseApiCall(url, 'GET'):
			try:
				response = json.loads(self.response)
				return True, response
			except:
				return True, {}
		else:
			return False, {'error':self.status}

	def EventsNotificationsDelete(self, event_notification_id):
		if self.SenseApiCall('/events/notifications/{0}.json'.format(event_notification_id), 'DELETE'):
			try:
				response = json.loads(self.response)
				return True, response
			except:
				return True, {}
		else:
			return False, {'error':self.status}

	def EventsNotificationsPost_Parameters(self):
		return {'event_notification':{'name':'my_event', 'event':'add_sensor', 'notification_id':0, 'priority':0}}
	
	def EventsNotificationsPost(self, parameters):
		if self.SenseApiCall('/events/notifications.json', 'POST', parameters=parameters):
			try:
				response = json.loads(self.response)
				return True, response
			except:
				return True, {}
		else:
			return False, {'error':self.status}

###################
# T R I G G E R S #
###################
	def TriggersGet(self, trigger_id=-1):
		if trigger_id == -1:
			url = '/triggers.json'
		else:
			url = '/triggers/{0}.json'.format(trigger_id)
		if self.SenseApiCall(url, 'GET'):
			try:
				response = json.loads(self.response)
				return True, response
			except:
				return True, {}
		else:
			return False, {'error':self.status}

	def TriggersDelete(self, trigger_id):
		if self.SenseApiCall('/triggers/{0}'.format(trigger_id), 'DELETE'):
			try:
				response = json.loads(self.response)
				return True, response
			except:
				return True, {}
		else:
			return False, {'error':self.status}

	def TriggersPost_Parameters(self):
		return {'trigger':{'name':'', 'expression':'', 'inactivity':0}}

	def TriggersPost(self, parameters):
		if self.SenseApiCall('/triggers.json', 'POST', parameters=parameters):
			try:
				response = json.loads(self.response)
				return True, response
			except:
				return True, {}
		else:
			return False, {'error':self.status}

##################################
# S E N S O R S  T R I G G E R S #
##################################
	def SensorsTriggersGet(self, sensor_id, trigger_id=-1):
		if trigger_id == -1:
			url = '/sensors/{0}/triggers.json'.format(sensor_id)
		else:
			url = '/sensors/{0}/triggers/{1}.json'.format(sensor_id, trigger_id)
			
		if self.SenseApiCall(url, 'GET'):
			try:
				response = json.loads(self.response)
				return True, response
			except:
				return True, {}
		else:
			return False, {'error':self.status}
	
	def SensorsTriggersDelete(self, sensor_id, trigger_id):
		if self.SenseApiCall('/sensors/{0}/triggers/{1}.json'.format(sensor_id, trigger_id), 'DELETE'):
			try:
				response = json.loads(self.response)
				return True, response
			except:
				return True, {}
		else:
			return False, {'error':self.status}
		
	def SensorsTriggersPost_Parameters(self):
		return {'trigger':{'id':0}}
		
	def SensorsTriggersPost(self, sensor_id, parameters):
		if self.SenseApiCall('/sensors/{0}/triggers'.format(sensor_id), 'POST', parameters):
			try:
				response = json.loads(self.response)
				return True, response
			except:
				return True, {}
		else:
			return False, {'error':self.status}

#TODO: SensorsTriggerPut

#############################################################
# S E N S O R S  T R I G G E R S  N O T I F I C A T I O N S #
#############################################################
	def SensorsTriggersNotificationsGet(self, sensor_id, trigger_id):
		if self.SenseApiCall('/sensors/{0}/triggers/{1}/notifications.json'.format(sensor_id, trigger_id), 'GET'):
			try:
				response = json.loads(self.response)
				return True, response
			except:
				return True, {}
		else:
			return False, {'error':self.status}

	def SensorsTriggersNotificationsDelete(self, sensor_id, trigger_id, notification_id):
		if self.SenseApiCall('/sensors/{0}/triggers/{1}/notifications/{2}.json'.format(sensor_id, trigger_id, notification_id), 'DELETE'):
			try:
				response = json.loads(self.response)
				return True, response
			except:
				return True, {}
		else:
			return False, {'error':self.status}
	
	def SensorsTriggersNotificationsPost_Parameters(self):
		return {'notification':{'id':0}}
		
	def SensorsTriggersNotificationsPost(self, sensor_id, trigger_id, parameters):
		if self.SenseApiCall('/sensors/{0}/triggers/{1}/notifications.json'.format(sensor_id, trigger_id), 'POST', parameters=parameters):
			try:
				response = json.loads(self.response)
				return True, response
			except:
				return True, {}
		else:
			return False, {'error':self.status}
		
#############################
# N O T I F I C A T I O N S #
#############################
	def NotificationsGet(self, notification_id=-1):
		if notification_id == -1:
			url = '/notifications.json'
		else:
			url = '/notifications/{0}.json'.format(notification_id)
			
		if self.SenseApiCall(url, 'GET'):
			try:
				response = json.loads(self.response)
				return True, response
			except:
				return True, {}
		else:
			return False, {'error':self.status}

	def NotificationsDelete(self, notification_id):
		if self.SenseApiCall('/notifications/{0}.json'.format(notification_id), 'DELETE'):
			try:
				response = json.loads(self.response)
				return True, response
			except:
				return True, {}
		else:
			return False, {'error':self.status}

	def NotificationsPost_Parameters(self):
		return {'notification':{'type':'url, email', 'text':'herpaderp', 'destination':'http://api.sense-os.nl/scripts'}}
	
	def NotificationsPost(self, parameters):
		if self.SenseApiCall('/notifications.json', 'POST', parameters=parameters):
			try:
				response = json.loads(self.response)
				return True, response
			except:
				return True, {}
		else:
			return False, {'error':self.status}

#################
# D E V I C E S #
#################
	def SensorAddToDevice_Parameters(self):
		return {'device':{'id':0, 'type':'', 'uuid':0}}

	def SensorAddToDevice(self, sensor_id, parameters):
		if self.SenseApiCall('/sensors/{0}/device.json'.format(sensor_id), 'POST', parameters=parameters):
			try:
				response = json.loads(self.response)
				return True, response
			except:
				return True, {}
		else:
			return False, {'error':self.status} 
		
###################################
# N O N  C L A S S  M E T H O D S #
###################################
def MD5Hash(password):
	md5_password = md5.new(password)
	password_md5 = md5_password.hexdigest()
	return password_md5
	
