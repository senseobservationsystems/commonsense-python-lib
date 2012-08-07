import senseapi

AUTHENTICATE_SESSIONID      = False
AUTHENTICATE_OAUTH          = True

TEST_GETSENSORS             = False
TEST_GETSENSORDATA          = False
TEST_POSTSENSORS            = True
TEST_POSTSENSORDATA         = False
TEST_CREATESERVICE          = True
TEST_CREATENOTIFICATION     = False
TEST_OAUTHAUTHORIZATION     = False 
TEST_OAUTHAUTHENTICATION    = False

api = senseapi.SenseAPI()
api.setVerbosity(True)
api.setServer('live')

# login
if AUTHENTICATE_SESSIONID:
    password_md5 = senseapi.MD5Hash('greenhousetest')
    status, response = api.Login('GreenhouseTest', password_md5)
#    password_md5 = senseapi.MD5Hash('zovke1984')
#    status, response = api.Login('freek@almende.com', password_md5)
    print(response)

if AUTHENTICATE_OAUTH:
    if api.server == 'live':
        status, response = api.AuthenticateOauth('MmNkN2M4OTg4MDc5NGEzMWFhZmY', 'MjRkODZmYzY5ZTI3NjkzNjg2Mjk', 'ZDljODM4NTI4NTI4NzAzNDIzYjg', 'ZmI3NDJmNmM1ZjE3ZjZhMzgxMjI')
#        status, response = api.AuthenticateOauth('M2ZjOWQ3NjUyYmFmZGExMWMxYWQ', 'ZTQ4YjkxNTk3NTdiMWJlZjAxYTk', 'ZDljODM4NTI4NTI4NzAzNDIzYjg', 'ZmI3NDJmNmM1ZjE3ZjZhMzgxMjI')
    elif api.server == 'dev':
        status, response = api.AuthenticateOauth('', '', 'NDQ1NTJjYTE0NjFkNmExYzI0Njc', 'OTA3NDg3ODRmNGZhYzU4MmNkMWM')
    else:
        pass

# get sensor list
if TEST_GETSENSORS:
    parameters = api.SensorsGet_Parameters()
    parameters['owned'] = 1
    parameters['physical'] = 1
    parameters['page'] = 0
    status, response = api.SensorsGet(parameters)
    print(response)

# get sensor data 
if TEST_GETSENSORDATA:
    parameters = api.SensorDataGet_Parameters()
    del parameters['date']
    del parameters['next']
    parameters['start_date'] = 1331215067
    parameters['end_date'] = 1331215667
    status, response = api.SensorDataGet(113522, parameters)
    print response

# post a sensor
if TEST_POSTSENSORS:
    parameters = api.SensorsPostJson_Parameters()
    parameters['sensor']['name'] = 'test_sensor'
    parameters['sensor']['device_type'] = 'gyrocopter'
    parameters['sensor']['data_type'] = 'float'
    status, response = api.SensorsPostJson(parameters)
    print response
    sensor_id = response['sensor']['id']
    
if TEST_POSTSENSORDATA:
    data = {'data':[{'value':10, 'date':1343055000},{'value':11, 'date':1343055001}]}
    status, response = api.SensorDataPost(sensor_id, data)
    print response

# post sensor data

# create a service for battery sensor
#parameters = api.ServicesPost_Parameters()
#parameters['service[data_fields]'] = ['level']
#parameters['sensor[name]'] = 'ChargeNeeded'
#parameters['sensor[device_type]'] = 'ChargeNeeded'
if TEST_CREATESERVICE:
    parameters = {'service':{'name':'math_service', 'data_fields':['level']}, 'sensor':{'name':'ChargeNeeded', 'device_type':'ChargeNeeded'}}
    status, response = api.ServicesPostJson(sensor_id, parameters)
    print response
    service_id = response['service[id]']
# setup the expression
    parameters = api.ServicesSetExpressionJson_Parameters()
    parameters['parameters'] = ["_113522_battery_sensor.level"]
    status, response = api.ServicesSetExpressionJson(sensor_id, service_id, parameters)
    print response
# add it to a device
    parameters = api.SensorAddToDevice_Parameters()
    parameters['device[type]'] = 'redXI'
    parameters['device[uuid]'] = 'bla:diebla'
    del parameters['device[id]']
    res, resp = api.SensorAddToDevice(service_id, parameters)

# create a notification for new sensors
if TEST_CREATENOTIFICATION:
    parameters = api.NotificationsPost_Parameters()
    parameters['notification']['type'] = 'url'
    parameters['notification']['text'] = 'herpaderping'
    parameters['notification']['destination'] = 'http://data.sense-os.nl:9012/scripts/ClimateSystemMap'
    status, response = api.NotificationsPost(parameters)
    print response
    notification_id = response['notification']['id']    
# setup the event
    status, parameters = api.EventsNotificationsPost_Parameters()
    parameters['event_notification']['name'] = 'new sensor event'
    parameters['event_notification']['event'] = 'add_sensor'
    parameters['event_notification']['notification_id'] = notification_id
    status, response = api.EventsNotificationsPost(parameters)
    print response

# test oauth authentication
if TEST_OAUTHAUTHORIZATION:
    result  = ''
    token   = {}
    if api.server == 'live':
        result, token = api.OauthAuthorizeApplication('ZDljODM4NTI4NTI4NzAzNDIzYjg', 'ZmI3NDJmNmM1ZjE3ZjZhMzgxMjI', 'for_ever')
    elif api.server =='dev':
        result, token = api.OauthAuthorizeApplication('NDQ1NTJjYTE0NjFkNmExYzI0Njc', 'OTA3NDg3ODRmNGZhYzU4MmNkMWM', 'for_ever')
    print '-----------------------------'
    print result
    print token
    print '-----------------------------'
  
# get current user
if TEST_OAUTHAUTHENTICATION:
    result, response = api.UsersGetCurrent()
    print result, response
  
#    consumer = api.OauthGetConsumer('ZDljODM4NTI4NTI4NzAzNDIzYjg', 'ZmI3NDJmNmM1ZjE3ZjZhMzgxMjI')
#    response = api.OauthRequestToken(consumer)
#    print response
#    response = api.OauthAuthorize()
#    response = api.OauthAccessToken(consumer)
#    print response
#logout
if AUTHENTICATE_SESSIONID:
    status, response = api.Logout()
    print(response)