# Usage
## Credentials
For using the tests a credential file is needed. Copy the credentials.txt_example file to credentials.txt and fill in the required fields.
~~~
{
	"username":"",
	"password":"",
	"application_key":""
}
~~~  

## Data coverage
The data coverage test file `dataCoverageTest.py` will preform a data coverage test for the sensors in the sensor profiles list with as source `sense-library` 
By default the script uses the 'staging` server, and uses an default interval of 3 minutes for calculating the coverage.

Run the data coverage on all the data available for the sensors: 
```
$ python dataCoverageTest.py
```  
Run it using a start and/or end time in epoch miliseconds
```
$ python dataCoverageTest.py 1450911600000 1450954800000
```




