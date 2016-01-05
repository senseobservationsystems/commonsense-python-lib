class DataCoverage:
	
	def __init__(self):
		self.__isSimpleCoverage__ = False
		
	def setSimpleCoverage(self, useSimpleCoverage):
		self.__isSimpleCoverage__ = useSimpleCoverage
		
	def __simpleCoverage__(self, sensorData, interval, startTime = None, endTime = None):
		"""
			Calculates the coverage percentage 
			@param sensorData (JSONArray) a JSON array with sensor data JSON objects
			@param interval (int) the interval between the data points in milisecons
			@return (float, float) The coverage percentage, a value between 0 and 1 and the average interval
		"""
		expectedSize = self.__getExpectedDataCount__(sensorData, interval, startTime, endTime)
		if expectedSize == 0:
			return 0.0, 0.0
		return float(len(sensorData))/float(expectedSize), 0.0
	
	def __getExpectedDataCount__ (self, sensorData, interval, startTime = None, endTime = None):
		dataSize = len(sensorData)
		if dataSize == 0:
			return 0
		if startTime == None:	
			startTime = sensorData[0]['time']
		if endTime == None:
			endTime = sensorData[dataSize-1]['time']
		return 1 + ((endTime-startTime)/interval)
		
	def __fullConverage__(self, sensorData, interval, startTime = None, endTime = None):
		"""
			Calculates the coverage percentage 
			@param sensorData (JSONArray) a JSON array with sensor data JSON objects
			@param interval (int) the interval between the data points in milisecons
			@return (float, float) The coverage percentage, a value between 0 and 1 and the average interval
		"""

		# return 0 is there is no data
		if len(sensorData) == 0:
			return 0.0, 0.0
			
		# set the start and end time based on the specified times or sensor dat
		if startTime == None:
			startTime = sensorData[0]["time"]
		if endTime == None:
			endTime = sensorData[len(sensorData)-1]["time"]
			
		# create an array with bins for each interval step
		intervalArray = [0] * (int(float(endTime-startTime)/float(interval))+1)
		totalDelay = 0
		lastTime = 0
		# loop through the data and point a one in the interval bin if there is data 
		for dataPoint in sensorData:
			newTime = dataPoint['time']
			index = int(float(newTime-startTime)/float(interval))
			intervalArray[index] = 1
			if lastTime != 0:
				totalDelay += newTime-lastTime
			lastTime = newTime
		
		# sum all the bins 
		cnt = sum(intervalArray)
		
		expectedSize = self.__getExpectedDataCount__(sensorData, interval, startTime, endTime)
		averageInterval = float(totalDelay)/float(len(sensorData))
		coverage = float(cnt)/float(expectedSize) 
		return coverage, averageInterval
				
	
	def coverage(self, sensorData, interval, startTime = None, endTime = None):
		"""
			Calculates the coverage percentage
			By default is does a full coverage test 
			@param sensorData a JSON array with sensor data JSON objects
			@param interval the interval between the data points in milisecons
			@return (float, float) The coverage percentage, a value between 0 and 1 and the average interval (average interval is 0.0 with simple coverage)
		"""
		if self.__isSimpleCoverage__:
			return self.__simpleCoverage__(sensorData, interval, startTime, endTime)
		else:
			return self.__fullConverage__(sensorData, interval, startTime, endTime)
					