class DataCoverage:
	
	def __init__(self):
		self.__isSimpleCoverage__ = False
		self.__leeyway__ = 0.5
		
	def setSimpleCoverage(self, useSimpleCoverage):
		self.__isSimpleCoverage__ = useSimpleCoverage
		
	
	def setLeeway(self, leeway):
		"""
			Set the amount of leeway to use to count a data point to be within the iterval
			This leeway value is not used when doing a simple coverage test. By default the leeway is 0.5 
			@param leeway (float) the leeway in percentage, a value between 0 and 1 
		"""
		self.__leeyway__ = leeway
		
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
		lastTime = 0
		cnt = 0
		totalDelay = 0
		for dataPoint in sensorData:
			newTime = dataPoint['time']
			if lastTime != 0:				
				maxInterval = interval + interval*self.__leeyway__
				minInterval = interval - interval*self.__leeyway__
				delay = newTime - lastTime 
				if delay > minInterval and delay < maxInterval:
					cnt += 1
				totalDelay += delay
			lastTime = newTime
		
		expectedSize = self.__getExpectedDataCount__(sensorData, interval, startTime, endTime)
		if expectedSize == 0:
			return 0.0,0.0

		averageInterval = float(totalDelay)/float(len(sensorData))
		coverage = float(cnt)/float(expectedSize) 
		return coverage, averageInterval
				
	
	def coverage(self, sensorData, interval, startTime = None, endTime = None):
		"""
			Calculates the coverage percentage
			By default is does a full coverage test using the leeway
			@param sensorData a JSON array with sensor data JSON objects
			@param interval the interval between the data points in milisecons
			@return (float, float) The coverage percentage, a value between 0 and 1 and the average interval (average interval is 0.0 with simple coverage)
		"""
		if self.__isSimpleCoverage__:
			return self.__simpleCoverage__(sensorData, interval, startTime, endTime)
		else:
			return self.__fullConverage__(sensorData, interval, startTime, endTime)
					