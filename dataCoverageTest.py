import senseapi
import json
import string
import dataCoverage
import sys

# default sourcename
sourceName = 'sense-library'
globalStartTime = None
globalEndTime = None

if len(sys.argv) == 2:
    if (sys.argv[1] == "-h"):
        print "Usage: python dataCoverageTest.py [start time] [end time] #in epoch miliseconds"
        exit()
    else: 
        globalStartTime = long(sys.argv[1])
if len(sys.argv) == 3:
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
dataCoverage.setLeeway(0.5)
dataCoverage.setSimpleCoverage(False)

def printCoverage(sensorName, interval, start_time = globalStartTime, end_time = globalEndTime):
    """
        Returns the data coverage for a specific sensor and a predefined sourceName
        @param sensorName (string) The sensor name to get the data for and compute the coverage for
        @param interval (int) The interval used for this sensor
        @return (float) The coverage percentage, a value between 0 and 1
         
    """
    getParameters = {"sort":"ASC"}
    if start_time != None:
        getParameters["start_time"] = start_time
    if end_time != None:
        getParameters["end_time"] = end_time
    
    coverage = 0
    avgInterval = 0
    
    if api.SensorDataGet(sourceName, sensorName, getParameters):
        response = json.loads(api.getResponse())
        coverage, avgInterval = dataCoverage.coverage(response["data"], interval, start_time, end_time)
    print "{:20} coverage: {:6}%   interval: {:<6} min".format(sensorName, round(coverage*100.0,2), round(avgInterval/60000.0, 2))
          
# Coverage tests
defaultSampleRate = 5 * 60 * 1000
printCoverage("noise", defaultSampleRate)
printCoverage("accelerometer", defaultSampleRate)
printCoverage("battery", defaultSampleRate)
printCoverage("light", defaultSampleRate)
printCoverage("position", defaultSampleRate)
printCoverage("proximity", defaultSampleRate)
printCoverage("sleep", defaultSampleRate)
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