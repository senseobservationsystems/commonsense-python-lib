import md5, urllib, httplib, json, socket


#GITGITIGITIGITIGITIGIT
#MORETESTING

class SenseAPI:
	def __init__(self):
		self.session_id = ""
		self.status = 0
		self.headers = []
		self.response = ""

	def SenseApiCall(self, url, method, parameters={}, headers={}):
		if method == "POST":
			heads 		= {"Content-type": "application/x-www-form-urlencoded", "Accept":"*"}
		else:
			heads 		= {"Content-type": "application/x-www-form-urlencoded", "Accept":"*"}
		heads.update(headers)
		connection 	= httplib.HTTPConnection('api.sense-os.nl', timeout=10);
		
		try:
			connection.request(method, url, parameters, heads);
		except socket.timeout:
			return {}
		
		result = connection.getresponse(); 
		self.response 	= result.read()
		self.status		= result.status
		self.headers	= result.getheaders()
		
		connection.close()
		
		if self.status == 200 or self.status == 201:
			return True
		else:
			return False

	def Login(self, username, password):
		parameters = {'username':username,'password':password}
		params 		= urllib.urlencode(parameters)

		if self.SenseApiCall("/login", "POST", params):
			try:
				response = json.loads(self.response)
			except: 
				return {'error':'notjson'}
			try: 
				self.session_id = response['session_id']		
				return response
			except: 
				return {'error':'no session id'}
		else:
			return {'error':self.status}
		
	def Logout(self):
		if self.session_id == "":
			return {'error':'not logged in'}
			
		headers    = {'X-SESSION_ID':"{}".format(self.session_id)}
		parameters = {}
		params 		= urllib.urlencode(parameters)

		if self.SenseApiCall('/logout', 'POST', params, headers):
			try:
				response = json.loads(self.response)
				self.session_id = ""
				return response
			except:
				return {'error':'notjson'}
		else:
			return {'error':self.status}
		
	def SensorsGet_Parameters(self):
		return {'page':0, 'per_page':100, 'shared':0, 'owned':0, 'physical':0, 'details':'full'}
		
	def SensorsGet(self, parameters):
		if self.session_id == "":
			return {'error':'not logged in'}
			
		headers    		= {'X-SESSION_ID':"{}".format(self.session_id)}
		params 			= urllib.urlencode(parameters)
		url 			= '/sensors?{}'.format(params)
		
		if self.SenseApiCall(url, 'GET', '', headers):
			try:
				response = json.loads(self.response)
				return response
			except:
				return {'error':'notjson'}
		else:
			return {'error':self.status}
				
	def SensorsPost_Parameters(self):
		return {'sensor[name]':'', 'sensor[display_name]':'', 'sensor[device_type]':'', 'sensor[pager_type]':'', 'sensor[data_type]':'', 'sensor[data_structure]':''}
		
	def SensorsPost(self, parameters):
		if self.session_id == "":
			return {'error':'not logged in'}
			
		headers    		= {'X-SESSION_ID':"{}".format(self.session_id)}
		params 			= urllib.urlencode(parameters)
		
		if self.SenseApiCall('/sensors', 'POST', params, headers):
			try:
				response = json.loads(self.response)
				return response
			except:
				return {'error':'notjson'}
		else:
			return {'error':self.status}	

	def SensorDataGet_Parameters(self):
		return {'page':0, 'per_page':100, 'start_date':0, 'end_date':4294967296, 'date':0, 'next':0, 'last':0, 'sort':'ASC', 'total':1}
		
	def SensorDataGet(self, sensor_id, parameters):
		if self.session_id == "":
			return {'error':'not logged in'}

		headers    		= {'X-SESSION_ID':"{}".format(self.session_id)}
		params 			= urllib.urlencode(parameters)
		url				= '/sensors/{}/data?{}'.format(sensor_id, params)

		if self.SenseApiCall(url, 'GET', '', headers):
			try:
				response = json.loads(self.response)
				return response
			except:
				return {'error':'notjson'}
		else:	
			return {'error':self.status} 
	
	def SensorDataPost(self, sensor_id, parameters):
		if self.session_id == "":
			return {'error':'not logged in'}
			
		headers    		= {'X-SESSION_ID':"{}".format(self.session_id)}
		params 			= json.dumps(parameters)
		
		if self.SenseApiCall('/sensors/{}/data.json'.format(sensor_id), 'POST', params, headers):
			try:
				response = json.loads(self.response)
				return response
			except:
				return {'error':'notjson'}
		else:
			return {'error':self.status}
		
##### TO BE TESTED: #####

	def SensorAddToDevice_Parameters(self):
		return {'device[id]':0, 'device[type]':'', 'device[uuid]':0}

	def SensorAddToDevice(self, sensor_id, parameters):
		if self.session_id == "":
			return {'error':'not logged in'}

		headers    		= {'X-SESSION_ID':"{}".format(self.session_id)}
		params 			= urllib.urlencode(parameters)
		url 			= '/sensors/{}/device'.format(sensor_id)
		
		if self.SenseApiCall(url, 'POST', params, headers):
			try:
				response = json.loads(self.response)
				return response
			except:
				return {'error':'notjson'}
		else:
			return {'error':self.status} 
		
	def SensorsDataPost(self, parameters):
		if self.session_id == "":
			return {'error':'not logged in'}

		headers			= {'X-SESSION_ID':"{}".format(self.session_id)}
		params			= json.dumps(parameters)
		
		if self.SenseApiCall('/sensors/data.json', 'POST', params, headers):
			try:
				response = json.loads(self.response)
				return response
			except:
				return {'error':'notjson'}
		else:
			return {'error':self.status}
	
	def ServicesPost_Parameters (self):
		return {'service[name]':'math_service', 'service[data_fields]':[], 'sensor[name]':'', 'sensor[device_type]':''}

	def ServicesPost (self, sensor_id, parameters):
		if self.session_id == "":
			return {'error':'not logged in'}

		headers    		= {'X-SESSION_ID':"{}".format(self.session_id)}
		params 			= urllib.urlencode(parameters)
		url 			= '/sensors/{}/services'.format(sensor_id)
		
		if self.SenseApiCall(url, 'POST', params, headers):
			try:
				response = json.loads(self.response)
				for header in self.headers:
					if header[0] == 'location':
						service_id = header.strip('abcdefghijklmnopqrstuvwxyz.:/-')
						response.update({'service[id]':service_id})
				return response
			except:
				return {'error':'notjson'}
		else:
			return {'error':self.status}
	
##########################

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
	
