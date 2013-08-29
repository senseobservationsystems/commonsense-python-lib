"""
Copyright (C) [2012] Sense Observation Systems B.V.
Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
"""

import senseapi
import json
import string

#####################
# I M P O R T A N T #
#####################
# This test script will attempt to open a file to read
# credentials with which it will authenticate at
# CommonSense. Make sure this file is present!
try:
    f = open('credentials.txt', 'r')
except:
    print 'pieuw'
creds = json.load(f)
f.close()
print creds

try:
    username = creds['username']
    password = creds['password']
except:
    print 'session_id authentication not available!'
    username = ''
    password = ''

try:
    oauth_token_key         = str(creds['oauth_token_key'])
    oauth_token_secret      = str(creds['oauth_token_secret'])
    oauth_consumer_key      = str(creds['oauth_consumer_key'])
    oauth_consumer_secret   = str(creds['oauth_consumer_secret'])
except:
    print 'oauth authentication not available!'
    oauth_token_key         = ''
    oauth_token_secret      = ''
    oauth_consumer_key      = ''
    oauth_consumer_secret   = ''


# Set all things to be tested
AUTHENTICATE_SESSIONID          = True
AUTHENTICATE_OAUTH              = False

Test_SensorsGet                 = True
Test_SensorDataGet              = True
Test_SensorsDataGet             = True
Test_SensorPost                 = True
Test_SensorDataPost             = True
Test_ServicesPost               = True
Test_EventsNotificationsPost    = True
Test_TriggersPost               = True
Test_GroupsPost                 = True
Test_GroupsSensorsPost          = True
Test_SensorAddToDevice          = True

Test_SensorMetatagsPost         = True
Test_SensorMetatagsGet          = True
Test_SensorsFind                = True
Test_GroupSensorsMetatagsGet    = True
Test_GroupSensorsFind           = True

api = senseapi.SenseAPI()
api.setVerbosity(True)
api.setServer('live') #options are: live (default), rc (release candidate server), dev (development server)

def run_tests ():
    if AUTHENTICATE_SESSIONID:
        login()

    if Test_SensorsGet:
        sensors = get_all_sensors()


    if Test_SensorPost:
        sensor_id = create_sensor()

    if Test_ServicesPost:
        service_id = create_service(sensor_id)
        set_service_expression(service_id, sensor_id, "test_sensor")

    if Test_SensorDataPost:
        create_sensor_data(sensor_id)

    if Test_SensorDataGet:
        if len(sensors) > 0:
            get_sensor_data(sensors[0]['id'], 1359385890, 1359472290)
        else:
            print "No sensors to test SensorDataGet"

    if Test_SensorsDataGet:
        if len(sensors) > 1:
            ids = [sensors[0]['id'], sensors[1]['id']]
	    get_sensors_data(ids, 1359385890, 1359472290)
        else:
	    print "No sensors to test SensorsDataGet"
        

    if Test_SensorAddToDevice:
        device_id = add_sensor_to_device(sensor_id)

    if Test_GroupsPost:
        group_id = create_group()

    if Test_GroupsSensorsPost:
        share_sensor_with_group(group_id, sensor_id)

    if Test_SensorMetatagsPost:
        create_metatags(sensor_id)

    if Test_SensorMetatagsGet:
        get_sensors_metatags()

    if Test_SensorsFind:
        find_sensors()

    if Test_GroupSensorsMetatagsGet:
        get_group_sensors_metatags(group_id)

    if Test_GroupSensorsFind:
        find_group_sensors(group_id)

    if Test_GroupsSensorsPost:
        unshare_sensor_with_group(group_id, sensor_id)

    if Test_GroupsPost:
        delete_group(group_id)

    if Test_ServicesPost:
        delete_service(sensor_id, service_id)

    if Test_SensorPost:
        delete_sensor(sensor_id)

    if AUTHENTICATE_SESSIONID:
        logout()

def printFunctionStart (function_name):
    print " "
    print "#####################################"
    print "{0}".format(function_name)

def printFunctionEnd ():
    print "#####################################"
    print " "


# login
def login():
    printFunctionStart("Test Logging In")
    password_md5 = senseapi.MD5Hash(password)
    if api.AuthenticateSessionId(username, password_md5):
        print api.getResponse()
    else:
        print api.getError()
    printFunctionEnd()


# authenticate oauth
def oauth():
    printFunctionStart("Test Oauth Authentication")
    if api.AuthenticateOauth(oauth_token_key, oauth_token_secret, oauth_consumer_key, oauth_consumer_secret):
        print api.getResponse()
    else:
        print api.getError()
    printFunctionEnd()


# get sensor list
def get_all_sensors():
    printFunctionStart("Test Getting All Sensors")
    page = 0;
    sensors = []
    while True:
        if api.SensorsGet({'page':page, 'owned':1, 'details':'full'}):
            r = json.loads(api.getResponse())
            sensors.extend(r['sensors'])
            if len(r['sensors']) < 100:
                break
            page += 1
        else:
            print api.getError()
            break
    printFunctionEnd()
    return sensors


# get sensor data
def get_sensor_data (sensor_id, start_date, end_date):
    printFunctionStart("Test Get Sensor Data")
    if api.SensorDataGet(sensor_id, {'start_date':start_date, 'end_date':end_date}):
        print api.getResponse()
    else:
        print api.getError()
    printFunctionEnd()

# get sensor data 
def get_sensors_data (sensor_id, start_date, end_date): 
    printFunctionStart("Test Get Sensors Data")   
    if api.SensorsDataGet(sensor_id, {'start_date':start_date, 'end_date':end_date}):
        print api.getResponse()
    else:
        print api.getError()
    printFunctionEnd()
    

# create a sensor
def create_sensor ():
    printFunctionStart("Test Post Sensor")
    sensor_id = -1
    if api.SensorsPost({'sensor':{'name':'test_sensor', 'device_type':'gyrocopter', 'data_type':'float'}}):
        print api.getResponse()
        sensor_id = api.getLocationId()
    else:
        print api.getError()
    printFunctionEnd()
    return sensor_id


# delete a sensor
def delete_sensor(sensor_id):
    printFunctionStart("Test SensorDelete")
    if api.SensorsDelete(sensor_id):
        print api.getResponse()
    else:
        print api.getError()
    printFunctionEnd()

# create sensor data
def create_sensor_data (sensor_id):
    printFunctionStart("Test SensorDataPost")
    data = {'data':[{'value':10, 'date':1343055000},{'value':11, 'date':1343055001}]}
    if api.SensorDataPost(sensor_id, data):
        print api.getResponse()
    else:
        print api.getError()
    printFunctionEnd()


# create a service
def create_service (sensor_id):
    printFunctionStart("Test ServicesPost")
    service_id = -1
    parameters = {'service':{'name':'math_service', 'data_fields':['level']}, 'sensor':{'name':'ChargeNeeded', 'device_type':'ChargeNeeded'}}
    if api.ServicesPost(sensor_id, parameters):
        print api.getResponse()
        service_id = api.getLocationId()
    else:
        print api.getError()
    printFunctionEnd()
    return service_id


# setup a service expression
def set_service_expression (service_id, sensor_id, sensor_name):
    printFunctionStart("Test ServicesSetExpression")
    parameters = {'parameters':['_{0}_{1}'.format(sensor_id, sensor_name)]}
    if api.ServicesSetExpression(sensor_id, service_id, parameters):
        print api.getResponse()
    else:
        print api.getError()
    printFunctionEnd()


# delete a service
def delete_service(sensor_id, service_id):
    printFunctionStart("Test ServicesDelete")
    if api.ServicesDelete(sensor_id, service_id):
        print api.getResponse()
    else:
        print api.getError()
    printFunctionEnd()


# add a sensor to a device
def add_sensor_to_device (sensor_id):
    printFunctionStart("Test SensorAddToDevice")
    device_id = -1
    parameters = {'device':{'type':'redXI', 'uuid':'bla:diebla'}}
    if api.SensorAddToDevice(sensor_id, parameters):
        print api.getResponse()
        device_id = api.getLocationId()
    else:
        print api.getError()
    printFunctionEnd()
    return device_id


# create a trigger
def create_trigger ():
    printFunctionStart("Test TriggerPost")
    trigger_id = -1
    parameters = {'trigger':{'name':'the signal', 'inactivity':60}}
    if api.TriggersPost(parameters):
        print api.getResponse()
        trigger_id = api.getLocationId()
    else:
        print api.getError()
    printFunctionEnd()
    return trigger_id


# attach trigger to sensor
def attach_trigger_to_sensor(sensor_id, trigger_id):
    printFunctionStart("Test SensorsTriggersPost")
    parameters = {'trigger':{'id':trigger_id}}
    if api.SensorsTriggersPost(sensor_id, parameters):
        print api.getResponse()
    else:
        print api.getError()
    printFunctionEnd()


# create a notification
def create_notification ():
    printFunctionStart("Test NotificationsPost")
    notification_id = -1
    parameters = {'notification':{'type':'email', 'text':'inactivity!', 'destination':'jondar@blackmagic.com'}}
    if api.NotificationsPost(parameters):
        print api.getResponse()
        notification_id = api.getLocationId()
    else:
        print api.getError()
    printFunctionEnd()
    return notification_id


# attach trigger to notification
def attach_trigger_to_notification(sensor_id, trigger_id, notification_id):
    printFunctionStart("Test SensorsTriggersNotificationsPost")
    parameters = {'notification': {'id':notification_id}}
    if api.SensorsTriggersNotificationsPost(sensor_id, trigger_id, parameters):
        print api.getResponse()
    else:
        print api.getError()
    printFunctionEnd()


# get trigger details
def get_triggers():
    printFunctionStart("Test TriggersGet")
    if api.TriggersGet():
        print api.getResponse()
    else:
        print api.getError()
    printFunctionEnd()


# create an event
def create_event (notification_id):
    printFunctionStart("Test EventsNotificationsPost")
    parameters = {'event_notification': {'name':'new sensor event', 'event':'add_sensor', 'notification_id':notification_id}}
    if api.EventsNotificationsPost(parameters):
        print api.getResponse()
    else:
        print api.getError()
    printFunctionEnd()


# create a group
def create_group():
    printFunctionStart("Test Groups Post")
    group_id = -1
    if api.GroupsPost({'group':{'name':'WarmGroup','description':'Love and Warmth','public':True,'hidden':True}}):
        headers = api.getResponseHeaders()
        #headers are case insensitive, map to lower case for easy lookup
        #headers = dict(zip(map(string.lower, headers.keys()), headers.values()))
        #location = headers.get('location')
        #group_id = location.split('/')[-1]
        group_id = api.getLocationId()
    else:
        print api.getError()
    printFunctionEnd()
    return group_id


# delete a group
def delete_group(group_id):
    printFunctionStart("Test GroupsDelete")
    if api.GroupsDelete(group_id):
        print api.getResponse()
    else:
        print api.getError()
    printFunctionEnd()


# test adding user to group
def add_user_to_group (user_id, group_id):
    printFunctionStart("Test GroupsUsersPost")
    par = api.GroupsUsersPost_Parameters()
    par['users'][0]['user'] = {'id':user_id}
    if api.GroupsUsersPost(par, group_id):
        print api.getResponse()
    else:
        print api.getError()
    printFunctionEnd()


# test listing users of a group
def get_group_users (group_id):
    printFunctionStart("Test GroupsUsersGet")
    par = api.GroupsUsersGet_Parameters()
    if api.GroupsUsersGet(par, group_id):
        print api.getResponse()
    else:
        print api.getError()
    printFunctionEnd()


# test sharing a sensor with a group
def share_sensor_with_group (group_id, sensor_id):
    printFunctionStart("Test Sharing Sensor with Group")
    if api.GroupsSensorsPost(group_id, {'sensors':[{'id':sensor_id}]}):
        print api.getResponse()
    else:
        print api.getError()
    printFunctionEnd()


# unshare sensor with a group
def unshare_sensor_with_group (group_id, sensor_id):
    printFunctionStart("Test Unsharing Sensor with Group")
    if api.GroupsSensorsDelete(group_id, sensor_id):
        print api.getResponse()
    else:
        print api.getError()
    printFunctionEnd()


# test creating metatags
def create_metatags (sensor_id):
    printFunctionStart("Test Metatags Post")
    if api.SensorMetatagsPost(sensor_id, {"metatags":{"greenhouse":["1"], "unit":["awesome"]}}, "testspace"):
        print api.getResponse()
    else:
        print api.getError()
    printFunctionEnd()


# test retrieving metatags
def get_sensors_metatags ():
    printFunctionStart("Test retrieving sensors with metatags")
    page = 0;
    sensors = []
    while True:
        if api.SensorsMetatagsGet({'page':page, 'per_page':100, 'sensor_owner':'me', 'details':'full'}, "testspace"):
            r = json.loads(api.getResponse())
            sensors.append(r['sensors'])
            if len(r['sensors']) < 100:
                break
            page += 1
        else:
            print api.getError()
            break
    printFunctionEnd()
    return sensors


# test finding sensors by metatags
def find_sensors ():
    printFunctionStart("Test finding sensors by metatags")
    filters = {'filter':{'metatag_statement_groups':[[{'metatag_name':'greenhouse', 'operator':'equal', 'value':'1'}]], 'sensor_statement_groups':[]}}
    if api.SensorsFind({'details':'full'}, filters, "testspace"):
        print api.getResponse()
    else:
        print api.getError()
    printFunctionEnd()


# test getting sensors with metatags in a group
def get_group_sensors_metatags (group_id):
    printFunctionStart("Test GroupSensorsMetatagsGet")
    page = 0;
    sensors = []
    while True:
        if api.GroupSensorsMetatagsGet(group_id, {'page':page, 'per_page':100, 'sensor_owner':'me', 'details':'full'}, "testspace"):
            r = json.loads(api.getResponse())
            sensors.append(r['sensors'])
            if len(r['sensors']) < 100:
                break
            page += 1
        else:
            print api.getError()
            break
    printFunctionEnd()
    return sensors


# test finding a sensor in a group
def find_group_sensors (group_id):
    printFunctionStart("Test GroupSensorsFind")
    filters = {'filter':{'metatag_statement_groups':[[{'metatag_name':'greenhouse', 'operator':'equal', 'value':'1'}]], 'sensor_statement_groups':[]}}
    if api.GroupSensorsFind(group_id, {'details':'full'}, filters, "testspace"):
        print api.getResponse()
    else:
        print api.getError()
    printFunctionEnd()


#def add_metatags_to_sensor(sensor_id):
#    if api.SensorsMetatagsGet("greenhouse", {"details":"full"}):
#        response = json.loads(api.getResponse())
#        for sensor in response['sensors']:
#           print "==================================="
#           print "id: {0}, name: {1}".format(sensor['id'], sensor['name'])
#            if 'metatags' in sensor:
#                for metatag in sensor['metatags']:
#                    print metatag, sensor['metatags'][metatag]


# logout
def logout():
    printFunctionStart("Test LogoutSessionId")
    if api.LogoutSessionId():
        print api.getResponse()
    else:
        print api.getError()
    printFunctionEnd()

run_tests()
