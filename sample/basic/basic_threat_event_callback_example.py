# This sample demonstrates registering a ThreatEventCallback with the
# DXL fabric to receive threat events sent by any product.

import logging
import os
import sys
import time
import json

from dxlclient.client import DxlClient
from dxlclient.client_config import DxlClientConfig
from dxlthreateventclient import CommonThreatEventClient
from dxlthreateventclient.callbacks import CommonThreatEventCallback

# Import common logging and configuration
sys.path.append(os.path.dirname(os.path.abspath(__file__)) + "/..")
from common import *

# Configure local logger
logging.getLogger().setLevel(logging.ERROR)
logger = logging.getLogger(__name__)

# Create DXL configuration from file
config = DxlClientConfig.create_dxl_config_from_file(CONFIG_FILE)

class MyThreatEventCallback(CommonThreatEventCallback):
    """
    My threat event callback
    """
    def on_threat_event(self, threat_event_dict, original_event):
        # Display the DXL topic that the event was received on
        print "Threat event on topic: " + original_event.destination_topic

        # Dump the dictionary
        print json.dumps(threat_event_dict, sort_keys=True, indent=4, separators=(',', ': '))

# Create the client
with DxlClient(config) as client:

    # Connect to the fabric
    client.connect()

    # Create the Common Threat Event client
    threat_event_client = CommonThreatEventClient(client)

    # Create threat event change callback
    threat_event_callback = MyThreatEventCallback()

    # Register callbacks with client to receive threat events
    threat_event_client.add_epo_threat_event_response_callback(threat_event_callback)

    # Wait forever
    print "Waiting for threat events..."
    while True:
        time.sleep(60)
