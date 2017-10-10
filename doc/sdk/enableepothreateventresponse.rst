ePolicy Orchestrator (ePO) Threat Event Configuration
=====================================================

In order for the OpenDXL Threat Event Client to receive ePO threat events, at least
one automatic response on the ePO Server must be enabled and configured to send 
a DXL threat event. 

To use a prepared generic automatic response, you can use the existing 
`"Send DXL Threat Event"` automatic response on the ePO Server.

If you have not enabled the `"Send DXL Threat Event"` automatic response in ePO, 
or are unsure if it is already enabled, the steps to do so are below:

1. Navigate to **Automatic Responses** in your ePO Server menu. 

    The `"Send DXL Threat Event"` response should be present. If it is not, you 
    may need to upgrade the DXL extensions on your ePO Server.
    
    .. image:: enableresponse1.png

2. Check the box next to `"Send DXL Threat Event"`, and select **Enabled Responses**
    from the **Actions** menu.
    
    .. image:: enableresponse2.png

Editing the Send Threat Event Action
------------------------------------

Clicking the **Edit** link on the `"Send DXL Threat Event"` row in **Automatic
Responses** will display the following configurable settings. If you wish to know
more information about automatic responses, see the ePO product documentation.

1. **Description** - This is the basic description of the automatic response. 

    .. image:: enableresponse3.png
    
2. **Filter** - These settings provide control over that types of ePO threat events
can trigger this automatic response.
    
    .. image:: enableresponse4.png
    
3. **Aggregation** - Available settings for threat event aggregation behavior for 
this automatic response.
    
    .. image:: enableresponse5.png
    
4. **Actions** - This is the section that enables the automatic response to 
**Send DXL Event** when triggered.
   
   Here, you can select what information from the threat event you would like this
   automatic response to include when sending the DXL Threat Event. After you have 
   finished selecting the information you would like to send over DXL, you can click
   **Save** in the lower-right corner to save the changes and exit.
   
   .. image:: enableresponse6.png
   
5. **Summary** - Overview of the configured settings for this automatic response.