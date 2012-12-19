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
AUTHENTICATE_SESSIONID      = True
AUTHENTICATE_OAUTH          = False

TEST_GETSENSORS             = False
TEST_GETSENSORDATA          = False
TEST_POSTSENSORS            = False
TEST_POSTSENSORDATA         = False
TEST_CREATESERVICE          = False
TEST_CREATEEVENT            = False
TEST_CREATETRIGGER          = False
TEST_OAUTHAUTHORIZATION     = False 
TEST_GROUPS                 = True

api = senseapi.SenseAPI()
api.setVerbosity(True)
api.setServer('live')

# login
if AUTHENTICATE_SESSIONID:
    password_md5 = senseapi.MD5Hash(password)
    status = api.AuthenticateSessionId(username, password_md5)
    print api.getResponse()

if AUTHENTICATE_OAUTH:
    status = api.AuthenticateOauth(oauth_token_key, oauth_token_secret, oauth_consumer_key, oauth_consumer_secret)

# get sensor list
if TEST_GETSENSORS:
    print " "
    print "#####################################"
    print "Test SensorsGet"
    
    page = 0;
    while True:
        if api.SensorsGet({'page':page, 'owned':1, 'details':'full'}):
            r = json.loads(api.getResponse())
            print "page: {0}: {1}".format(page, r['sensors'])
            if len(r['sensors']) < 100:
                break
            page += 1
        else:
            break
        
    print "#####################################"

# get sensor data 
if TEST_GETSENSORDATA:
    print " "
    print "#####################################"
    print "Test SensorDataGet:"
    
    if api.SensorDataGet(150776, {'start_date':1331215067, 'end_date':1331215667}):
        print api.getResponse()

    print "#####################################"

if TEST_POSTSENSORS:
    print " "
    print "#####################################"
    print "Test SensorsPost:"
    
    if api.SensorsPost({'sensor':{'name':'test_sensor', 'device_type':'gyrocopter', 'data_type':'float'}}):
        print api.getResponse()
        sensor_id = json.loads(api.getResponse())['sensor']['id']
    
    print "#####################################"
    
if TEST_POSTSENSORDATA:
    print " "
    print "#####################################"
    print "Test SensorDataPost:"

    data = {'data':[{'value':10, 'date':1343055000},{'value':11, 'date':1343055001}]}
    if api.SensorDataPost(sensor_id, data):
        print api.getResponse()

    print "#####################################"

# create a service for battery sensor
if TEST_CREATESERVICE:
    print " "
    print "#####################################"
    print "Test ServicesPost:"
    
    parameters = {'service':{'name':'math_service', 'data_fields':['level']}, 'sensor':{'name':'ChargeNeeded', 'device_type':'ChargeNeeded'}}
    if api.ServicesPost(sensor_id, parameters):
        print api.getResponse()
        service_id = json.loads(api.getResponse)['service[id]']
        
    print "#####################################"
    
# setup the expression
    print " "
    print "#####################################"
    print "Test ServicesSetExpression:"
    
    parameters = {'parameters':['_113522_battery_sensor.level']}
    if api.ServicesSetExpression(sensor_id, service_id, parameters):
        print api.getResponse()
    
    print "#####################################"
    
# add it to a device
    print " "
    print "#####################################"
    print "Test SensorAddToDevice:"
    
    parameters = {'device':{'type':'rexXI', 'uuid':'bla:diebla'}}
    if api.SensorAddToDevice(service_id, parameters):
        print api.getResponse()
        device_id = json.loads(api.getResponse())['device']['id']

    print "#####################################"

if TEST_CREATETRIGGER:
    print " "
    print "#####################################"
    print "Test TriggerPost:"
    
    parameters = {'trigger':{'name':'the signal', 'inactivity':60}}
    if api.TriggersPost(parameters):
        print api.getResponse()
        trigger_id = json.loads(api.getResponse())['trigger']['id']
    
    print "#####################################"
    
    print " "
    print "#####################################"
    print "Test SensorsTriggersPost:"

    parameters = {'trigger':{'id':trigger_id}}
    if api.SensorsTriggersPost(sensor_id, parameters):
        print api.getResponse()

    print "#####################################"

    print " "
    print "#####################################"
    print "Test NotificationsPost:"

    parameters = {'notification':{'type':'email', 'text':'inactivity!', 'destination':'jondar@blackmagic.com'}} 
    if api.NotificationsPost(parameters):
        print api.getResponse()
        notification_id = json.loads(api.getResponse)['notification']['id']

    print "#####################################"

    print " "
    print "#####################################"
    print "Test SensorsTriggersNotificationsPost:"

    parameters = {'notification': {'id':notification_id}}
    if api.SensorsTriggersNotificationsPost(sensor_id, trigger_id, parameters):
        print api.getResponse()

    print "#####################################"

    print " "
    print "#####################################"
    print "Test TriggersGet:"

    if api.TriggersGet():
        print api.getResponse()
    
    print "#####################################"

if TEST_CREATEEVENT:
    print " "
    print "#####################################"
    print "Test NotificationsPost:"
    
    parameters = {'notification':{'type':'url', 'text':'herpaderping', 'destination':'http://blackmagic.barsour.way'}}
    if api.NotificationsPost(parameters):
        print api.getResponse()
        notification_id = json.loads(api.getResponse())['notification']['id']
        
    print "#####################################"    
    
    print " "
    print "#####################################"
    print "Test EventsNotificationsPost:"

    parameters = {'event_notification': {'name':'new sensor event', 'event':'add_sensor'}}
    if api.EventsNotificationsPost(parameters):
        print api.getResponse()
    
    print "#####################################"
    
# test oauth authentication
if TEST_OAUTHAUTHORIZATION:
    print " "
    print "#####################################"
    print "Test AouthAuthorizeApplication:"
   
    result  = ''
    token   = {}
    if api.server == 'live':
        result = api.OauthAuthorizeApplication('ZDljODM4NTI4NTI4NzAzNDIzYjg', 'ZmI3NDJmNmM1ZjE3ZjZhMzgxMjI', 'for_ever')
    elif api.server =='dev':
        result = api.OauthAuthorizeApplication('NDQ1NTJjYTE0NjFkNmExYzI0Njc', 'OTA3NDg3ODRmNGZhYzU4MmNkMWM', 'for_ever')
    if result: 
        print api.getResponse()
  
    print "#####################################"

#Test groups
if TEST_GROUPS:
    def testGroups():
        print " "
        print "#####################################"
        group={}
        group['name']='SomeTestGroup_l3vs9rrv'
        group['description']='Group for testing'
        group['public']=True
        group['hidden']=True
        par={'group':group}
        
        groupId = None
        print "Test GroupsPost:"
        if api.GroupsPost(par):
            headers = api.getResponseHeaders()
            #headers are case insensitive, map to lower case for easy lookup
            headers = dict(zip(map(string.lower, headers.keys()), headers.values()))
            location = headers.get('location')
            groupId = location.split('/')[-1]
        if groupId is None:
                print "Couldn't create group, aborting the next tests with groups."
                return
        print "Test GroupsPut:"
        if api.GroupsPut(par, groupId):
            print api.getResponse()
        print "#####################################"
        print "Test GroupsGet:"
        par = api.GroupsGet_Parameters()
        if api.GroupsGet(par):
            print api.getResponse()
        print "#####################################"
        print "Test GroupsGet({0}):".format(groupId)
        par = api.GroupsGet_Parameters()
        if api.GroupsGet(par, groupId):
            print api.getResponse()
        print "#####################################"
        print "Test GroupsUsersPost():"
        # need current user id for this
        api.UsersGetCurrent()
        response = json.loads(api.getResponse())
        myUserId = response['user']['id']
        
        par = api.GroupsUsersPost_Parameters()
        par['users'][0]['user'] = {'id':myUserId}
        if api.GroupsUsersPost(par, groupId):
            print api.getResponse()
        print "#####################################"
        print "Test GroupsUsersGet():"
        par = api.GroupsUsersGet_Parameters()
        if api.GroupsUsersGet(par, groupId):
            print api.getResponse()
        print "#####################################"
        print "Test GroupsUsersDelete():"
        if api.GroupsUsersDelete(groupId, myUserId):
            print api.getResponse()

	#After leaving the group we cannot delete the group...
        #print "#####################################"
	#print "Test GroupsDelete:"
        #if api.GroupsDelete(groupId):
        #    print api.getResponse()
        
        print "#####################################"
    testGroups()

#logout
if AUTHENTICATE_SESSIONID:
    print " "
    print "#####################################"
    print "Test LogoutSessionId:"
    
    if api.LogoutSessionId():
        print api.getResponse()
        
    print "#####################################"

