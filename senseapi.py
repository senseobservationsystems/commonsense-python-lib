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
		self.authentication = ''
		self.oauth_consumer = {}
		self.oauth_token = {}
		
	def setVerbosity(self, verbose):
		if not (verbose == True or verbose == False):
			return False
		else:
			self.verbose = verbose
			return True
		
	def somenewfunction(self):
		print 'hoewoi!'

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
		if not (method == 'session_id' or method == 'oauth'):
			return False
		else:
			self.authentication = method
			return True
		
########################################
# B A S E  A P I  C A L L  M E T H O D #
########################################
	def SenseApiCall(self, url, method, parameters=None, headers={}, body=''):
		heads = {}
		
		if self.authentication == 'session_id':
			if self.session_id == '':
				self.status = 401
				return False
			heads.update({'X-SESSION_ID':"{0}".format(self.session_id)})
		elif self.authentication == 'oauth':
			oauth_url = 'http://{0}{1}'.format(self.server_url, url)
			oauth_request = oauth.OAuthRequest.from_consumer_and_token(self.oauth_consumer, token=self.oauth_token, http_method=method, http_url=oauth_url)
			oauth_request.sign_request(oauth.OAuthSignatureMethod_HMAC_SHA1(), self.oauth_consumer, self.oauth_token)
			heads.update(oauth_request.to_header())
		elif self.authentication == '':
			pass
		else:
			self.status = 418
			return False
		
		if body == '':
			heads.update({"Content-type": "application/x-www-form-urlencoded", "Accept":"*"})
			if not parameters is None:
				body = urllib.urlencode(parameters) 
		else:
			heads.update({"Content-type": "application/json", "Accept":"*"})
		heads.update(headers)
		
		connection 	= httplib.HTTPConnection(self.server_url, timeout=10)
			
		try:
			connection.request(method, url, body, heads);
		except socket.timeout: # TODO: check if this doesnt already generate a status
			self.status = 408
			return False
		
		result = connection.getresponse(); 
		self.response 	= result.read()
		self.status		= result.status
		self.headers	= result.getheaders()
		
		connection.close()
		
		if self.verbose:
			print "===================CALL==================="
			print "Call: {0} {1}".format(method, url)
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
		parameters = {'username':username,'password':password}

		if self.SenseApiCall("/login", "POST", parameters=parameters):
			try:
				response = json.loads(self.response)
			except: 
				return False, {'error':'notjson'}
			try: 
				self.session_id = response['session_id']
				self.authentication = 'session_id'		
				return True, response
			except: 
				return False, {'error':'no session id'}
		else:
			return False, {'error':self.status}
		
	def LogoutSessionId(self):
		if self.SenseApiCall('/logout', 'POST'):
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
		if self.SenseApiCall('/users/current', 'GET'):
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
				return False, {'error':'error authorizing application'}
		else:
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
			return True, {'oauth_token':response['oauth_token'][0], 'oauth_token_secret':response['oauth_token_secret'][0]}
		else:
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
		
	def SensorsGet(self, parameters=None, sensor_id=0):
		if parameters is None and sensor_id is 0:
			return False, {'error':'no arguments'}
		
		url = ''
		if parameters is None:
			url = '/sensors/{0}'.format(sensor_id)
		else:
			url = '/sensors'
			
		if self.SenseApiCall(url, 'GET', parameters=parameters):
			try:
				response = json.loads(self.response)
				return True, response
			except:
				return True, {}
		else:
			return False, {'error':self.status}
				
	def SensorGetJson(self, parameters=None, sensor_id=0):
		if parameters is None and sensor_id is 0:
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
	
			
				
	def SensorsPost_Parameters(self):
		return {'sensor[name]':'', 'sensor[display_name]':'', 'sensor[device_type]':'', 'sensor[pager_type]':'', 'sensor[data_type]':'', 'sensor[data_structure]':''}
		
	def SensorsPost(self, parameters):
		if self.SenseApiCall('/sensors', 'POST', parameters=parameters):
			try:
				response = json.loads(self.response)
				return True, response
			except:
				return True, {}
		else:
			return False, {'error':self.status}

	def SensorsPostJson_Parameters(self):
		return {'sensor':{'name':'', 'display_name':'', 'device_type':'', 'pager_type':'', 'data_type':'', 'data_structure':''}}
			
	def SensorsPostJson (self, parameters):
		if self.SenseApiCall('/sensors.json', 'POST', body=json.dumps(parameters)):
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
		if self.SenseApiCall('/sensors/{0}/data'.format(sensor_id), 'GET', parameters=parameters):
			try:
				response = json.loads(self.response)
				return True, response
			except:
				return True, {}
		else:	
			return False, {'error':self.status} 
	
	def SensorDataPost(self, sensor_id, parameters):
		if self.SenseApiCall('/sensors/{0}/data.json'.format(sensor_id), 'POST', body=json.dumps(parameters)):
			try:
				response = json.loads(self.response)
				return True, response
			except:
				return True, {}
		else:
			return False, {'error':self.status}

###################
# S E R V I C E S #
###################
	def ServicesPostJson_Parameters (self):
		return {'service':{'name':'math_service', 'data_fields':['sensor']}, 'sensor':{'name':'', 'device_type':''}}

	def ServicesPostJson (self, sensor_id, parameters):
		if self.SenseApiCall('/sensors/{0}/services.json'.format(sensor_id), 'POST', body=json.dumps(parameters)):
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
		if self.SenseApiCall('/sensors/{0}/services/{1}'.format(sensor_id, service_id), 'DELETE'):
			try:
				response = json.loads(self.response)
				return True, response
			except:
				return True, {}
		else:
			return False, {'error':self.status}
		
	def ServicesSetExpressionJson_Parameters (self):
			return {'parameters':[]}
		
	def ServicesSetExpressionJson (self, sensor_id, service_id, parameters):
		if self.SenseApiCall('/sensors/{0}/services/{1}/SetExpression.json'.format(sensor_id, service_id), 'POST', body=json.dumps(parameters)):
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
		if self.SenseApiCall('/users/current', 'GET'):
			try:
				response = json.loads(self.response)
				return True, response
			except:
				return True, {}
		else:
			return False, {'error':self.status}
		
##### TO BE TESTED: #####
###############
# E V E N T S #
###############
	def EventsNotificationsGet(self, event_notification_id = -1):
		if event_notification_id == -1:
			url = '/events/notifications'
		else:
			url = '/events/notifications/{0}'.format(event_notification_id)
			
		if self.SenseApiCall(url, 'GET'):
			try:
				response = json.loads(self.response)
				return True, response
			except:
				return True, {}
		else:
			return False, {'error':self.status}

	def EventsNotificationsDel(self, event_notification_id):
		if self.SenseApiCall('/events/notifications/{0}'.format(event_notification_id), 'DELETE'):
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
		if self.SenseApiCall('/events/notifications.json', 'POST', body=json.dumps(parameters)):
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
			url = '/notifications'
		else:
			url = '/notifications/{0}'.format(notification_id)
			
		if self.SenseApiCall(url, 'GET'):
			try:
				response = json.loads(self.response)
				return True, response
			except:
				return True, {}
		else:
			return False, {'error':self.status}

	def NotificationsDel(self, notification_id):
		if self.SenseApiCall('/notifications/{0}'.format(notification_id), 'DELETE'):
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
		if self.SenseApiCall('/notifications.json', 'POST', body=json.dumps(parameters)):
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
		return {'device[id]':0, 'device[type]':'', 'device[uuid]':0}

	def SensorAddToDevice(self, sensor_id, parameters):
		if self.SenseApiCall('/sensors/{0}/device'.format(sensor_id), 'POST', parameters=parameters):
			try:
				response = json.loads(self.response)
				return True, response
			except:
				return True, {}
		else:
			return False, {'error':self.status} 
		
		
	def SensorsDataPost(self, parameters):
		if self.SenseApiCall('/sensors/data.json', 'POST', body=json.dumps(parameters)):
			try:
				response = json.loads(self.response)
				return True, response
			except:
				return True, {}
		else:
			return False, {'error':'{0}: {1}'.format(self.status, self.response)}
	
###################################
# N O N  C L A S S  M E T H O D S #
###################################
def MD5Hash(password):
	md5_password = md5.new(password)
	password_md5 = md5_password.hexdigest()
	return password_md5
	
	
def CheckForError(response):
	try:
		error = response['error']
		return True
	except KeyError:
		return False
	
