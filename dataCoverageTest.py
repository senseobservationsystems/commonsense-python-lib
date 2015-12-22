import senseapi
import json
import string

api = senseapi.SenseAPI()
api.setVerbosity(True)
api.setServer('dev')

try:
    f = open('credentials.txt', 'r')
except:
    print 'missing credentials.txt with username,password and application_key json'
creds = json.load(f)
f.close()
print creds

try:
    username = creds['username']
    password = creds['password']
    appKey = creds['application_key']
except:
    print 'session_id authentication not available!'
    username = ''
    password = ''
    appKey = ''

api.setAppKey(appKey)
password_md5 = senseapi.MD5Hash(password)

# Login
if api.AuthenticateSessionId(username, password_md5):
	print api.getResponse()
else:
	print api.getError()

# Get sensors
sensors = {}
if api.SensorsGet():
	sensors = json.loads(api.getResponse())
else:
	 print api.getError()

print sensors

# Get Data
for sensor in sensors:
	if api.SensorDataGet(sensor['source_name'], sensor['sensor_name']):
		print api.getResponse()
	else:
		print api.getError()
