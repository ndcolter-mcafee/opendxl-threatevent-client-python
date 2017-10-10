from dxlclient.message import Request
from dxlbootstrap.util import MessageUtils
from dxlbootstrap.client import Client

# Topic used to subscribe to ePO DXL Threat Events from Automatic Responses
EPO_THREAT_EVENT_RESPONSE_TOPIC = "/mcafee/event/epo/threat/response"

class CommonThreatEventClient(Client):
    """
    The "DXL Common Threat Event Client" client wrapper class.
    """
    
    def __init__(self, dxl_client):
        """
        Constructor parameters:

        :param dxl_client: The DXL client to use for communication with the fabric
        """
        super(CommonThreatEventClient, self).__init__(dxl_client)

    def add_epo_threat_event_response_callback(self, threat_event_callback):
        """
        Registers a :class:`dxlthreateventclient.eventhandlers.CommonThreatEventCallback` with the client to 
        receive `threat events` from ePO.
        See the :class:`dxlthreateventclient.eventhandlers.CommonThreatEventCallback` class documentation for 
        more details.
        
        :param: threat_event_topic: The topic to which to assign the 
            :class:`dxlthreateventclient.eventhandlers.CommonThreatEventCallback`.
        """
        self._dxl_client.add_event_callback(EPO_THREAT_EVENT_RESPONSE_TOPIC, threat_event_callback)

        
    def remove_epo_threat_event_response_callback(self, threat_event_callback):
        """
        Unregisters a :class:`dxlthreateventclient.eventhandlers.CommonThreatEventCallback` from the client so 
        that it will no longer receive `threat events` from ePO.
        
        :param: threat_event_topic: The topic from which to remove the 
            :class:`dxlthreateventclient.eventhandlers.CommonThreatEventCallback`.
        """
        self._dxl_client.remove_event_callback(EPO_THREAT_EVENT_RESPONSE_TOPIC, threat_event_callback)

        
    @staticmethod
    def convert_aggregate_fields(otherData_props):
        """
        Converts all aggregate data fields of input ``dict`` ``aggregate_props`` with lists or sets 
        ('listOf____' or 'setOf______') to appropriate Python data structures. For DXL Threat Events published
        by ePO, these aggregate fields will only exist in the 'otherData' member.
        
        'listOf_____' will be converted to `dict`.
        
        'setOf______' will be converted to `set`.
        
        **Example Usage**
        
        .. code-block:: python
        
            class MyThreatEventCallback(CommonThreatEventCallback):

                def on_threat_event(self, threat_event_dict, original_event):

                    threat_event_member_data = threat_event_dict[ThreatEventProps.EVENT]
                    threat_event_other_data_converted = CommonThreatEventClient.convert_aggregate_fields(
                        threat_event_member_data[EventProps.OTHER_DATA])
                    print "First entry in otherData.listOfSourceIPV4 dict: {0}".format(
                        threat_event_dict["ThreatEventProps.EVENT"]["EventProps.OTHER_DATA"]["listOfSourceIPV4"][0])
        
        :param: aggregate_props: The `dict` object to iterate over while converting aggregate data fields. This
            should be used for the `otherData` `dict` only.
        """
    
        for prop_key, prop_value in otherData_props.iteritems():
                new_prop_value = otherData_props[prop_key]
                if "listOf" in prop_key:
                    new_prop_value = CommonThreatEventClient.create_dict_from_aggregate_listOf(prop_value)
                elif "setOf" in prop_key:
                    new_prop_value = CommonThreatEventClient.create_set_from_aggregate_setOf(prop_value)
                if new_prop_value != otherData_props[prop_key]:
                        otherData_props[prop_key] = new_prop_value
        return otherData_props
    
    
    @staticmethod
    def create_dict_from_aggregate_listOf(list_of):
        """
        Returns a Python dict created from a list of values
        """
        split_list = list_of.split(",")
        dict_of = dict(enumerate(split_list))
        return dict_of
        
        
    @staticmethod   
    def create_set_from_aggregate_setOf(set_of):
        """
        Returns a Python set created from a list of values
        """
        split_set = set_of.split(",")
        true_set_of = set(enumerate(split_set))
        return true_set_of