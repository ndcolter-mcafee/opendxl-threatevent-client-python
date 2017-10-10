import json
import logging

from dxlclient.callbacks import EventCallback
from dxlbootstrap.util import MessageUtils

import dxlthreateventclient
from constants import *

# Configure local logger
logger = logging.getLogger(__name__)


class CommonThreatEventCallback(EventCallback):
    """
    Concrete instances of this class are used to receive "threat events" sent by event publishers
    over DXL.
    
    The following steps must be performed to create and register a threat event callback
    (as shown in the example below):
    
        * Create a derived class from :class:`CommonThreatEventCallback`
        * Override the :func:`on_threat_event` method to handle threat events
        * Register the callback with the client:
        
                :func:`dxlthreateventclient.client.CommonThreatEventClient.add_threat_event_callback`
                
    **Example Usage**
    
        .. code-block:: python
        
            class MyThreatEventCallback(CommonThreatEventCallback):
                def on_threat_event(self, threat_event_dict, original_event):
                    # Display the DXL topic that the event was received on
                    print "Threat event on topic: " + original_event.destination_topic

                    # Dump the dictionary
                    print json.dumps(threat_event_dict, 
                        sort_keys=True, indent=4, separators=(',', ': '))

            # Create the client
            with DxlClient(config) as client:

                # Connect to the fabric
                client.connect()

                # Create the Common Threat Event client
                threat_event_client = CommonThreatEventClient(client)

                # Create threat event change callback
                threat_event_callback = MyThreatEventCallback()

                # Register callbacks with client to receive threat events
                threat_event_client.add_threat_event_callback(threat_event_callback)

                # Wait forever
                print "Waiting for threat events..."
                while True:
                    time.sleep(60)
    """
    
    def on_event(self, event):
        """
        Invoked when a Threat Event has been received over DXL.

        NOTE: This method should not be overridden (it performs cleanup to format ThreatEvent usage).
        Instead, the :func:`on_threat_event` method must be overridden.

        :param event: The original DXL Threat Event message that was received
        """
        # Decode the event payload
        threat_event_dict = json.loads(MessageUtils.decode_payload(event))

        # Invoke the Threat Event method
        self.on_threat_event(threat_event_dict, event)
        
    
    def on_threat_event(self, threat_event_dict, original_event):
        """
        NOTE: This method must be overridden by derived classes.

        Each `Threat Event` that is received from the DXL fabric will cause this method to be
        invoked with the corresponding `Threat Event information`.

        **Threat Event Information**

            The `Reputation Change` information is provided as a Python ``dict`` (dictionary) via the
            ``threat_event_dict`` parameter.

            An example `Threat Event` ``dict`` (dictionary) is shown below:

            .. code-block:: python

                {
                    "event": {
                        "analyzer": {
                            "contentVersion": "",
                            "detectedUTC": "2016-12-13T22:18:34.000Z",
                            "detectionMethod": "Exploit Prevention",
                            "engineVersion": "",
                            "hostName": "SAMPLE-HOSTNAME",
                            "id": "ENDP_AM_1020",
                            "ipv4": "10.0.0.10",
                            "ipv6": "0:0:0:0:0:FFFF:0A00:0010",
                            "mac": "001122334455",
                            "name": "McAfee Endpoint Security",
                            "version": "10.5.0"
                        },
                        "category": "Host intrusion buffer overflow",
                        "entity": {
                            "groupName": null,
                            "id": "11111111-2222-3333-4444-555555555555",
                            "osPlatform": "Workstation",
                            "osType": "Windows 7",
                            "ruleName": null,
                            "sessionId": null,
                            "type": "device"
                        },
                        "eventDesc": "Buffer Overflow detected and blocked (GBOP)",
                        "files": [],
                        "id": 18052,
                        "otherData": {
                            "count": "1",
                            "definedAt": "My Organization",
                            "responseEventType": "Threat",
                            "responseRuleName": "Send Threat Event via DXL",
                            "threatSeverityString": "Critical"
                        },
                        "source": {
                            "hostName": "",
                            "ipv4": "10.0.0.10",
                            "ipv6": "0:0:0:0:0:FFFF:0A00:0010",
                            "mac": "",
                            "port": null,
                            "processName": "",
                            "url": "",
                            "userName": ""
                        },
                        "target": {
                            "fileName": "C:\\DAC\\IEXPLORE.EXE",
                            "hostName": "SAMPLE-HOSTNAME",
                            "ipv4": "10.0.0.10",
                            "ipv6": "0:0:0:0:0:FFFF:0A00:0010",
                            "mac": "",
                            "port": 0,
                            "processName": "IEXPLORE.EXE",
                            "protocol": "",
                            "userName": "SAMPLE-HOSTNAME\\Administrator"
                        },
                        "threatActionTaken": "blocked",
                        "threatHandled": 1,
                        "threatName": "ExP:Heap",
                        "threatSeverity": 2,
                        "threatType": "Exploit Prevention",
                        "uri": null
                    },
                    "eventMessageType": "McAfee Common Event",
                    "eventMessageVersion": "1.0"
                }


            The property and members names in the dictionary are listed in the following constants classes:

                :class:`dxlthreateventclient.constants.ThreatEventProps`
                
                    :class: `dxlthreateventclient.constants.EventProps`
                    
                        :class: `dxlthreateventclient.constants.AnalyzerProps`
                        
                        :class: `dxlthreateventclient.constants.EntityProps`
                        
                        :class: `dxlthreateventclient.constants.FilesProps`
                        
                            :class: `dxlthreateventclient.constants.HashProps`
                            
                        :class: `dxlthreateventclient.constants.SourceProps`
                        
                        :class: `dxlthreateventclient.constants.TargetProps`
                        

            The `threat event` information is separated into several distinct sections:

                **General Threat Event Information**
                    General information about the threat event, such as the Threat Event message version, and 
                    threat event type. 
                    
                    Keyed in the dictionary by the constants in :class:`dxlthreateventclient.constants.ThreatEventProps`.
                    
                    
                **Event Properties**

                    Keyed in the dictionary by the ```dxlthreateventclient.constants.ThreatEventProps.EVENT`` constant.

                    A ``dict`` (dictionary) of properties, including sub-members which each contain data about the 
                    ``analyzer``, ``entity``, ``files``, ``source``, ``target``, and ``other data`` properties, 
                    respectively. These are keyed in the event dictionary by the constants in 
                    :class:`dxlthreateventclient.constants.EventProps`.


                **Analyzer Properties**

                    Keyed in the dictionary by the ```dxlthreateventclient.constants.EventProps.ANALYZER`` constant.

                    A ``dict`` (dictionary) of properties pertaining to the analyzer used for the threat event. The
                    list of ``analyzer properties`` can be found in the :class:`dxlthreateventclient.constants.AnalyzerProps``
                    constants class.


                **Entity Properties**

                    Keyed in the dictionary by the ```dxlthreateventclient.constants.EventProps.ENTITY`` constant.

                    A ``dict`` (dictionary) of properties pertaining to the entity identified for the threat event. The
                    list of ``entity properties`` can be found in the :class:`dxlthreateventclient.constants.EntityProps``
                    constants class.

                    
                **Files Properties**

                    Keyed in the dictionary by the ```dxlthreateventclient.constants.EventProps.FILES`` constant.

                    A ``dict`` (dictionary) of file members pertaining to the files relevant for the threat event. Each
                    file member has a list of ``file properties``. The list of ``files properties`` can be found in 
                    the :class:`dxlthreateventclient.constants.FilesProps`` constants class.
                    
                    File members may contain one or more ``hash properties`` for the file. The available hash property
                    keys can be found in the :class:`dxlthreateventclient.constants.HashProps` constants class.

                    
                **Source Properties**

                    Keyed in the dictionary by the ```dxlthreateventclient.constants.EventProps.SOURCE`` constant.

                    A ``dict`` (dictionary) of properties pertaining to the source identified for the threat event. The
                    list of ``source properties`` can be found in the :class:`dxlthreateventclient.constants.SourceProps``
                    constants class.

                    
                **Target Properties**

                    Keyed in the dictionary by the ```dxlthreateventclient.constants.EventProps.TARGET`` constant.

                    A ``dict`` (dictionary) of properties pertaining to the source identified for the threat event. The
                    list of ``target properties`` can be found in the :class:`dxlthreateventclient.constants.TargetProps``
                    constants class.

                    
                **Other Data Properties**

                    Keyed in the dictionary by the ```dxlthreateventclient.constants.EventProps.OTHER_DATA`` constant.

                    A ``dict`` (dictionary) of properties pertaining to the source identified for the threat event. The
                    data in these properties can be provided by the threat event sender as one or more of the following:
                        - A single value 
                            - e.g. ``"apiName"``:"send"
                        - A ``dict`` of multiple values of a single property type 
                            - e.g. ``"listOfSourceIPV4"``:"10.0.0.1, 10.0.0.2, 10.0.0.3, 10.0.0.3"
                        - A ``set`` of multiple distinct values of a single property type
                            - e.g. ``"setOfSourceIPV4"``:"10.0.0.1, 10.0.0.2, 10.0.0.3"
                        - A count of the distinct values of a single property type 
                            - e.g. ``"distinctCountOfSourceHostName"``:"3"
                    
                    
        :param threat_event_dict: A Python ``dict`` (dictionary) containing the details of the reputation change
        :param original_event: The original DXL event message that was received
        """
        raise NotImplementedError("Must be implemented in a child class.")
    