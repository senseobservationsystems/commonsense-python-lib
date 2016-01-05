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
api.setServer('dev')
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

# Print the data coverage
def printCoverage(sensorName, interval, start_time = globalStartTime, end_time = globalEndTime):
    """
        Returns the data coverage for a specific sensor and a predefined sourceName
        @param sensorName (string) The sensor name to get the data for and compute the coverage for
        @param interval (int) The interval used for this sensor
        @return (float) The coverage percentage, a value between 0 and 1
         
    """
    getParameters = {"sort":"ASC", "limit":1000}
    if start_time != None:
        getParameters["start_time"] = start_time
    if end_time != None:
        getParameters["end_time"] = end_time
    
    coverage = 0
    avgInterval = 0
    
    # get all the sensor data
    sensorData = getSensorData(sensorName, getParameters)
    coverage, avgInterval = dataCoverage.coverage(sensorData, interval, start_time, end_time)
    print "{:20} coverage: {:6}%   interval: {:<6} min".format(sensorName, round(coverage*100.0,2), round(avgInterval/60000.0, 2))
          
# Coverage tests
sampling3Minutes = 3 * 60 * 1000
sampling5Minutes = 5 * 60 * 1000
defaultSampleRate = sampling3Minutes
printCoverage("noise", defaultSampleRate)
printCoverage("accelerometer", defaultSampleRate)
printCoverage("battery", defaultSampleRate)
printCoverage("light", defaultSampleRate)
printCoverage("position", defaultSampleRate)
printCoverage("proximity", defaultSampleRate)
printCoverage("sleep", sampling5Minutes)
printCoverage("sleep_estimate", defaultSampleRate)
printCoverage("time_active", defaultSampleRate)

# extra event based sensors
print "\n#Event based sensors"
printCoverage("time_zone", defaultSampleRate)
printCoverage("sense_log", defaultSampleRate)
printCoverage("mental_resilience", defaultSampleRate)
printCoverage("screen", defaultSampleRate)
printCoverage("call", defaultSampleRate)
printCoverage("app_info", defaultSampleRate)