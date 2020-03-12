# mqttFilePublish

## Purpose

mqttFilePublish publishes a file by first encoding the file in base 64 then forming json packets
with payloads of up to 3000 bytes and publishing the json packets by mqtt to the mqtt-host 
on the mqtt-topic.

At the receiving ending mqttFileSubscribe will write the base 64 encoded file and when it is fully
recieved it will decode the encoded file.   The received file will at the specified location and will be byte for byte idential
but will may not have the same owner group other and permissions.


## Installation


`sudo apt-get install mosquitto-dev`

`sudo apt-get install libjson-c-dev`

`sudo apt-get install libmosquittopp-dev`

`sudo apt-get install libssl1.0-dev`

## Build

`make`

## Command line switches mqttFilePublish

switch|Required/Optional|argument|description
---|---|---|---
--input-file-name|REQUIRED|file name|file to be sent.  The path will striped on sending
--mqtt-topic|REQUIRED|topic|mqtt topic
--mqtt-host|REQUIRED|qualified host|mqtt host operating mqtt server
--mqtt-user-name|maybe REQUIRED|user name|mqtt user name
--mqtt-user-name|maybe REQUIRED|user name|mqtt user name
--mqtt-passwd|maybe REQUIRED|user password|mqtt password
--verbose|OPTIONAL|(none)|sets verbose mode
--mqtt-port|OPTIONAL|number|default is 1883
--disable-mqtt|OPTIONAL|(none)|prevents mqtt publishing
--help|OPTIONAL|(none)|displays help and exits


## Command line switches mqttFileSubscribe

switch|Required/Optional|argument|description
---|---|---|---
--mqtt-topic|REQUIRED|topic|mqtt topic More than one topic can be used
--mqtt-host|REQUIRED|qualified host|mqtt host operating mqtt server
--mqtt-user-name|maybe REQUIRED|user name|mqtt user name
--mqtt-passwd|maybe REQUIRED|user password|mqtt password
--log-dir|OPTIONAL|path to logging directory|default=logLocal
--verbose|OPTIONAL|(none)|sets verbose mode
--mqtt-port|OPTIONAL|number|default is 1883
--help|OPTIONAL|(none)|displays help and exits


## Example mqttFileSubscribe

`./mqttFileSubscribe  --mqtt-host localhost  --mqtt-topic left`

mqttFileSubscribe stays alive until you kill it.    You must start this first or 
any files sent will not be received.


## Example mqttFilePublish

`./mqttFilePublish --input-file-name ./some-file-name.jpg --mqtt-topic left --mqtt-host localhost`


mqttFilePublish will exit after publishing the file.   The file can be of any type or size.   The file
can be captured by mqttLogLocal but at this time mqttFileSubscribe has not been adapted for that purpose.

