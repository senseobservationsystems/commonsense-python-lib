import json
import string
import dataCoverage
import sys

sys.path.append('../')
import senseapi

# default sourcename
sourceName = 'sense-library'
globalStartTime = None
globalEndTime = None

# get the command line arguments
if len(sys.argv) >= 2:
    if (sys.argv[1] == "-h"):
        print "Usage: python dataCoverageTest.py [start time] [end time] #in epoch miliseconds"
        exit()
    else: 
        globalStartTime = long(sys.argv[1])
if len(sys.argv) >= 3:
    globalEndTime = long(sys.argv[2])

# Get user credentials
try:
    f = open('credentials.txt', 'r')
except:
    print 'missing credentials.txt with username,password and application_key json'
creds = json.load(f)
f.close()

try:
    username = creds['username']
    password = creds['password']
    appKey = creds['application_key']
except:
    print 'session_id authentication not available!'
    username = ''
    password = ''
    appKey = ''

# Set SensorApi settings
api = senseapi.SenseAPI()
api.setVerbosity(False)
api.setServer('live')
api.setAppKey(appKey)
password_md5 = senseapi.MD5Hash(password)

# Login
if not api.AuthenticateSessionId(username, password_md5):
    print api.getError()
    exit()

# Set the data coverage settings
dataCoverage = dataCoverage.DataCoverage()
dataCoverage.setSimpleCoverage(False) # we use the complex coverage comparing individual points

# Get all the data for a sensor
def getSensorData(sensorName, getParameters):
    sensorData = []
    lastTime = 0
    while True:
        # get data multiple times since there is a limit of 1000 points per call
        if api.SensorDataGet(sourceName, sensorName, getParameters):
            response = json.loads(api.getResponse())
            dataArray = response['data']
            # if there is no data then break, or if the last item is the same af previous round
            if len(dataArray) == 0 or lastTime == dataArray[len(dataArray)-1]["time"]:
                break
                
            # if this is the fist time then copy the whole response
            if len(sensorData) == 0:
                sensorData = dataArray
            # else don't copy the first item since, it's inclusive from the previous call
            else:
                sensorData += dataArray[1:]
                
            # we got less then the limit so we can stop now
            if len(dataArray) < 1000:
                break
                
            # get the time of the last item in the list
            lastTime = dataArray[len(dataArray)-1]["time"]
            # use the lastTime to select a new start period and get max 1000 points again
            getParameters['start_time'] = lastTime
        else:
            break
    return sensorData

def getAllSensorData(sensorNames, start_time = globalStartTime, end_time = globalEndTime):
    """
        Returns the data coverage for a specific sensor and a predefined sourceName
        @param sensorNames (string) The sensor names to get the data for and compute the coverage for
        @return (float) The coverage percentage, a value between 0 and 1
         
    """
    getParameters = {"sort":"ASC", "limit":1000}
    if start_time != None:
        getParameters["start_time"] = start_time
    if end_time != None:
        getParameters["end_time"] = end_time
    
    sensorData = []
    for sensorName in sensorNames:
        # get all the sensor data
        data = getSensorData(sensorName, getParameters)
        for item in data:
            item['date'] = item['time']/1000.0
            item['sensor_id'] = 1
            item['sensor_description'] = sensorName
            item['sensor_name'] = sensorName 
            del item['time']           
            sensorData.append(item)
    return sensorData

# get sleep data
sensorData = getAllSensorData(["noise", 
                    "accelerometer", 
                    "battery", 
                    "light", 
                    "position", 
                    "proximity"])
sensorData.sort(key=lambda x: x['date'])
for data in sensorData:
    print json.dumps(data)
