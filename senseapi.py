import md5, urllib, httplib, json

class SenseAPI:
	def __init__(self):
		self.session_id = ""

	def SenseApiCall(self, url, method, parameters={}, headers={}):
		if method == "POST":
			heads 		= {"Content-type": "application/x-www-form-urlencoded", "Accept":"*"}
		else:
			heads 		= {"Content-type": "application/x-www-form-urlencoded", "Accept":"*"}
		heads.update(headers)
		connection 	= httplib.HTTPConnection('api.sense-os.nl', timeout=10);
		
		connection.request(method, url, parameters, heads);
		
		response 	= connection.getresponse();
		result 		= response.read()
		
		connection.close()
		
		return result

	def Login(self, username, password):
		parameters = {'username':username,'password':password}
		params 		= urllib.urlencode(parameters)

		response_json = self.SenseApiCall("/login", "POST", params)

		try:
			response = json.loads(response_json)
		except: 
			return {'error':'notjson'}
		
		try: 
			self.session_id = response['session_id']		
			return response
		except: 
			return response
		
	def Logout(self):
		if self.session_id == "":
			return {'error':'not logged in'}
			
		headers    = {'X-SESSION_ID':"{}".format(self.session_id)}
		parameters = {}
		params 		= urllib.urlencode(parameters)

		response_json = self.SenseApiCall('/login', 'POST', params, headers)
		
		try:
			response = json.loads(response_json)
			self.session_id = ""
		except:
			return {'error':'notjson'}
		
		return response
		
	def SensorsGet_Parameters(self):
		return {'page':0, 'per_page':100, 'shared':0, 'owned':0, 'physical':0, 'details':'full'}
		
	def SensorsGet(self, parameters):
		if self.session_id == "":
			return {'error':'not logged in'}
			
		headers    		= {'X-SESSION_ID':"{}".format(self.session_id)}
		params 			= urllib.urlencode(parameters)
		url 			= '/sensors?{}'.format(params)
		response_json 	= self.SenseApiCall(url, 'GET', '', headers)
			
		try:
			response = json.loads(response_json)
		except:
			return {'error':'notjson'}
			
		return response
			
	def SensorsPost_Parameters(self):
		return {'sensor[name]':'', 'sensor[display_name]':'', 'sensor[device_type]':'', 'sensor[pager_type]':'', 'sensor[data_type]':'', 'sensor[data_structure]':''}
		
	def SensorsPost(self, parameters):
		if self.session_id == "":
			return {'error':'not logged in'}
			
		headers    		= {'X-SESSION_ID':"{}".format(self.session_id)}
		params 			= urllib.urlencode(parameters)
		response_json 	= self.SenseApiCall('/sensors', 'POST', params, headers)
		
		try:
			response = json.loads(response_json)
		except:
			return {'error':'notjson'}
			
		return response

	def SensorDataGet_Parameters(self):
		return {'page':0, 'per_page':100, 'start_date':0, 'end_date':4294967296, 'date':0, 'next':0, 'last':0, 'sort':'ASC', 'total':1}
		
	def SensorDataGet(self, sensor_id, parameters):
		if self.session_id == "":
			return {'error':'not logged in'}

		headers    		= {'X-SESSION_ID':"{}".format(self.session_id)}
		params 			= urllib.urlencode(parameters)
		url				= '/sensors/{}/data?{}'.format(sensor_id, params)
		response_json 	= self.SenseApiCall(url, 'GET', '', headers)

		try:
			response = json.loads(response_json)
		except:
			return {'error':'notjson'}
			
		return response
	
	def SensorDataPost(self, sensor_id, parameters):
		if self.session_id == "":
			return {'error':'not logged in'}
			
		headers    		= {'X-SESSION_ID':"{}".format(self.session_id)}
		params 			= json.dumps(parameters)
		response_json 	= self.SenseApiCall('/sensors/{}/data.json'.format(sensor_id), 'POST', params, headers)

		try:
			response = json.loads(response_json)
		except:
			return {'error':'notjson'}
			
		return response
		
##### TO BE TESTED: #####

	def SensorAddToDevice_Parameters(self):
		return {'device[id]':0, 'device[type]':'', 'device[uuid]':0}

	def SensorAddToDevice(self, sensor_id, parameters):
		if self.session_id == "":
			return {'error':'not logged in'}

		headers    		= {'X-SESSION_ID':"{}".format(self.session_id)}
		params 			= urllib.urlencode(parameters)
		url 			= '/sensors/{}/device'.format(sensor_id)
		response_json 	= self.SenseApiCall(url, 'POST', params, headers)
	
		try:
			response = json.loads(response_json)
		except:
			return {'error':'notjson'}
			
		return response
		
	def SensorsDataPost(self, parameters):
		if self.session_id == "":
			return {'error':'not logged in'}

		headers			= {'X-SESSION_ID':"{}".format(self.session_id)}
		params			= json.dumps(parameters)
		response_json 	= self.SenseApiCall('/sensors/data.json', 'POST', params, headers)

		try:
			response = json.loads(response_json)
		except:
			return {'error':'notjson'}

		return response
	
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
	
