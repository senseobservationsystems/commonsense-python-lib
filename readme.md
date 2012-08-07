A Python library that handles communication with the Sense API for you. Implemented as a module that can be imported into your own program.

[b][u]Documentation[/u][/b]
[b]Class: SenseAPI()[/b]
[i]Class that handles communication.[/i]

[font=Courier New]SenseAPI.[b]SenseApiCall[/b]([i]url[/i], [i]method[/i], [i]parameters={}[/i], [i]headers={}[/i])[/font]
[indent]General function that performs any call to the API. Leave 'http://api.sense-os.nl' out form [i]url[/i]. [i]method[/i] specifies the HTTP method to be used ('POST', 'GET', 'DELETE', 'PUT'). [i]parameters[/i] and [i]headers[/i] are expected to be correctly formatted. Returns the body of the response from the server.[/indent]
[font=Courier New]SenseAPI.[b]Login[/b]([i]username[/i], [i]password[/i])[/font]
[indent]Logs in to CommonSense and stores the received session id internally for further use. Uses [i]username[/i] and [i]password[/i] as credentials to login. [i]password[/i] must be an MD5 hash of the actual password. Returns a Python dictionary containing the body of the response by the server or an error notification.[/indent]
[font=Courier New]SenseAPI.[b]Logout[/b]()[/font]
[indent]Logs out of CommonSense and destroys the locally stored session id. Returns a Python dictionary containing the body of the response by the server or an error notification.[/indent]
[font=Courier New]SenseAPI.[b]SensorsGet[/b]([i]parameters[/i])[/font]
[indent]Calls [url=http://www.sense-os.nl/45?nodeId=45&selectedId=11887]'List sensors'[/url] according to [i]parameters[/i]. [i]parameters[/i] should be a Python dictionary containing the necessary parameters. Returns a Python dictionary containing the body of the response by the server or an error notification.[/indent]
[font=Courier New]SenseAPI.[b]SensorsGet_Parameters[/b]()[/font]
[indent]Returns a Python dictionary containing all parameters for [font=Courier New]SenseAPI.[b]SensorsGet[/b]([i]parameters[/i])[/font] with values set to their defaults.[/indent]
[font=Courier New]SenseAPI.[b]SensorsPost[/b]([i]parameters[/i])[/font]
[indent] Calls [url=http://www.sense-os.nl/46?nodeId=46&selectedId=11887]'Create a sensor'[/url] according to [i]parameters[/i]. [i]parameters[/i] should be a Python dictionary containing the parameters of the sensor to be created. Returns a Python dictionary containing the body of the response by the server or an error notification. [/indent]
[font=Courier New]SenseAPI.[b]SensorsPost_Parameters[/b]()[/font]
[indent]Returns a Python dictionary containing all parameters for [font=Courier New]SenseAPI.[b]SensorsPost[/b]([i]parameters[/i])[/font] with values set to empty strings.[/indent]
[font=Courier New]SenseAPI.[b]SensorDataGet[/b]([i]sensor_id[/i], [i]parameters[/i])[/font]
[indent] Calls [url=http://www.sense-os.nl/52?nodeId=52&selectedId=11887]'List sensor data'[/url] for [i]sensor_id[/i] according to [i]parameters[/i]. [i]parameters[/i] should be a Python dictionary containing the necessary parameters. Returns a Python dictionary containing the body of the response by the server or an error notification. [/indent]
[font=Courier New]SenseAPI.[b]SensorDataGet_Parameters[/b]()[/font]
[indent]Returns a Python dictionary containing all parameters for [font=Courier New]SenseAPI.[b]SensorDataGet[/b]([i]sensor_id[/i], [i]parameters[/i])[/font] with values set to their defaults.[/indent]
[font=Courier New]SenseAPI.[b]SensorDataPost[/b]([i]sensor_id[/i], [i]parameters[/i])[/font]
[indent] Calls [url=http://www.sense-os.nl/53?nodeId=53&selectedId=11887]'Upload sensor specific data'[/url] for [i]sensor_id[/i] according to [i]parameters[/i]. [i]parameters[/i] should be a Python dictionary containing the data to upload. Returns a Python dictionary containing the body of the response by the server or an error notification. [/indent]

[font=Courier New][b]MD5Hash[/b]([i]password[/i])[/font]
[indent]Returns the MD5 hash of [i]password[/i].[/indent]
[font=Courier New][b]CheckForError[/b]([i]response[/i])[/font]
[indent]Evaluates [i]response[/i] to check if it contains an error returned by the server. [i]response[/i] should be a Python dictionary containing the body of a response from the server. Return True if an error is present or False otherwise.[/indent]


[b][u]Version History[/u][/b]
[i]Version 0.1[/i] - Initial verison of the library. Has one general function that will interact perform any call to the database, as long as the right URL, parameters and headers are provided. Also has some specific API calls implemented, including [url=http://www.sense-os.nl/autentication/post-login?nodeId=28&selectedId=11887]login[/url], [url=http://www.sense-os.nl/29?nodeId=29&selectedId=11887]logout[/url], [url=http://www.sense-os.nl/45?nodeId=45&selectedId=11887]list sensors[/url], [url=http://www.sense-os.nl/46?nodeId=46&selectedId=11887]create a sensor[/url], [url=http://www.sense-os.nl/52?nodeId=52&selectedId=11887]list sensor data[/url], [url=http://www.sense-os.nl/53?nodeId=53&selectedId=11887]upload specific sensor data[/url]. The goal is to eventually have all or most API calls implemented.
