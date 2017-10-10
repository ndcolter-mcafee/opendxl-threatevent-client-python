# -*- coding: utf-8 -*-
################################################################################
# Copyright (c) 2017 McAfee Inc. - All Rights Reserved.
################################################################################

import time
import struct
import uuid

        
class ThreatEventProps:
    """
        +-----------------------+-------------------------------------------------------------------+
        | Name                  | Description                                                       |
        +=======================+===================================================================+
        | EVENT_MESSAGE_TYPE    | Type of message                                                   |    
        |                       |                                                                   |
        |                       | Example: "McAfee Common Event"                                    |
        +-----------------------+-------------------------------------------------------------------+
        | EVENT_MESSAGE_VERSION | Version number of the event message.                              |
        |                       |                                                                   |
        |                       | Example: "1.0"                                                    |
        +-----------------------+-------------------------------------------------------------------+
        | EVENT                 | The member name for the event data,  which contains the event     |
        |                       | properties.                                                       |
        |                       |                                                                   |
        |                       | See the :class:`EventProps` constants class for the list of       |
        |                       | properties and members inside of the `event` member.              |
        +-----------------------+-------------------------------------------------------------------+
        | RECEIVED_UTC          | The time that the threat event was received by ePO.               |
        +-----------------------+-------------------------------------------------------------------+
    """
    EVENT_MESSAGE_TYPE = "eventMessageType"
    EVENT_MESSAGE_VERSION = "eventMessageVersion"
    EVENT = "event"
    RECEIVED_UTC = "_receivedUTC"


class EventProps:
    """
    The standard set of properties that are included with each `event` member in the threat event

        +---------------------+---------------------------------------------------------------------+
        | Name                | Description                                                         |
        +=====================+=====================================================================+
        | CATEGORY            | The category of the threat event.                                   |                                                        |
        +---------------------+---------------------------------------------------------------------+
        | EVENT_DESCRIPTION   | The description of the threat event.                                |
        +---------------------+---------------------------------------------------------------------+
        | EVENT_ID            | External ID designated for the event.                               |
        |                     |                                                                     |
        |                     | Example: The Windows Event ID ("10016")                             |
        +---------------------+---------------------------------------------------------------------+
        | THREAT_ACTION_TAKEN | Action taken as part of the threat event.                           |
        +---------------------+---------------------------------------------------------------------+
        | THREAT_HANDLED      | Indicates whether the threat was handled or not.If the event is not |
        |                     | threat oriented, set to null.                                       |
        +---------------------+---------------------------------------------------------------------+
        | THREAT_NAME         | Name of this threat, such as a virus, a firewall rule name, etc.    |
        +---------------------+---------------------------------------------------------------------+
        | THREAT_SEVERITY     | Severity of the event instance on a numeric scale:                  |
        |                     |                                                                     |
        |                     | (Highest Severity) 1 - 7 (Lowest Severity)                          |
        +---------------------+---------------------------------------------------------------------+
        | THREAT_TYPE         | Analyzer-dependent classification of the event type.                | 
        +---------------------+---------------------------------------------------------------------+
        | URI                 | URI pointo to data source.                                          |    
        +---------------------+---------------------------------------------------------------------+
        | ANALYZER            | The member name for the analyzer data,  which contains the analyzer |
        |                     | properties.                                                         |
        |                     |                                                                     |
        |                     | See the :class:`AnalyzerProps` constants class for the list of      |
        |                     | properties and members inside of the `analyzer` member.             |
        +---------------------+---------------------------------------------------------------------+
        | ENTITY              | The member name for the entity data,  which contains the entity     |
        |                     | properties.                                                         |
        |                     |                                                                     |
        |                     | See the :class:`EntityProps` constants class for the list of        |
        |                     | properties and members inside of the `entity` member.               |
        +---------------------+---------------------------------------------------------------------+
        | FILES               | The member name for the files data,  which contains the properties  |
        |                     | of each file.                                                       |
        |                     |                                                                     |
        |                     | See the :class:`FilesProps` constants class for the list of         |
        |                     | properties and members inside of the `files` member.                |
        +---------------------+---------------------------------------------------------------------+
        | OTHER_DATA          | The member name for the `otherData` section, which contains the     |
        |                     | additional data selected by the threat event sender.                |
        +---------------------+---------------------------------------------------------------------+
        | SOURCE              | The member name for the source data, which contains the source      |
        |                     | properties.                                                         |
        |                     |                                                                     |
        |                     | See the :class:`SourceProps` constants class for the list of        |
        |                     | properties and members inside of the `source` member.               |
        +---------------------+---------------------------------------------------------------------+
        | TARGET              | The member name for the target data,  which contains target         |
        |                     | properties.                                                         |
        |                     |                                                                     |
        |                     | See the :class:`TargetProps` constants class for the list of        |
        |                     | properties and members inside of the `target` member.               |
        +---------------------+---------------------------------------------------------------------+
    """
    CATEGORY = "category"
    EVENT_DESCRIPTION = "eventDesc"
    EVENT_ID = "id"
    THREAT_ACTION_TAKEN = "threatActionTaken"
    THREAT_HANDLED = "threatHandled"
    THREAT_NAME = "threatName"
    THREAT_SEVERITY = "threatSeverity"
    THREAT_TYPE = "threatType"
    URI = "uri"
    ANALYZER = "analyzer"
    ENTITY = "entity"
    FILES = "files"
    OTHER_DATA = "otherData"
    SOURCE = "source"
    TARGET = "target"

    
class AnalyzerProps:
    """
        +---------------------+---------------------------------------------------------------------+
        | Name                | Description                                                         |
        +=====================+=====================================================================+
        | CONTENT_VERSION     | Analyzer content version.                                           |
        +---------------------+---------------------------------------------------------------------+
        | DETECTION_METHOD    | Detection method used by the analyzer for this event.               |
        +---------------------+---------------------------------------------------------------------+
        | DETECTED_UTC        | The date/time when the analyzer detected this event.                |
        +---------------------+---------------------------------------------------------------------+
        | ENGINE_VERSION      | Analyzer engine version.                                            |
        +---------------------+---------------------------------------------------------------------+
        | HOST_NAME           | Network host name of the machine, including domain prefix as        |
        |                     | needed.                                                             |
        +---------------------+---------------------------------------------------------------------+
        | ID                  | The ID software/hardware generating this event.                     |    
        |                     |                                                                     |
        |                     | This is analogous to the ePO traditional SoftwareID or ProductCode. |
        +---------------------+---------------------------------------------------------------------+
        | IPV4                | The 32-bit IPv4 address of the analyzer.                            |
        +---------------------+---------------------------------------------------------------------+
        | IPV6                | The 128-bit IPv6 address of the analyzer.                           |
        +---------------------+---------------------------------------------------------------------+
        | MAC                 | The MAC address of the analyzer.                                    |
        +---------------------+---------------------------------------------------------------------+
        | NAME                | The product name as a string.                                       |
        +---------------------+---------------------------------------------------------------------+
        | VERSION             | Version string of the analyzer.                                     |
        +---------------------+---------------------------------------------------------------------+
    """
    CONTENT_VERSION = "contentVersion"
    DETECTION_METHOD = "detectionMethod"
    DETECTED_UTC = "detectedUTC"
    ENGINE_VERSION = "engineVersion"
    HOST_NAME = "hostName"
    ID = "id"
    IPV4 = "ipv4"
    IPV6 = "ipv6"
    MAC = "mac"
    NAME = "name"
    VERSION = "version"

    
class EntityProps:
    """
        +-------------------+-----------------------------------------------------------------------+
        | Name              | Description                                                           |
        +===================+=======================================================================+
        | GROUP_NAME        |                                                                       | 
        +-------------------+-----------------------------------------------------------------------+
        | ID                | A unique Id referencing this entity.                                  |
        |                   |                                                                       |
        |                   | Example: AgentGUID, user SID.                                         |
        +-------------------+-----------------------------------------------------------------------+
        | NODE_TEXT_PATH    | Entity's location in the ePO system tree.                             |
        +-------------------+-----------------------------------------------------------------------+
        | OS_PLATFORM       | Entity operating system platform.                                     |
        +-------------------+-----------------------------------------------------------------------+
        | OS_TYPE           | Entity operating system.                                              |
        +-------------------+-----------------------------------------------------------------------+
        | RULE_NAME         | FW / IPS / Threat Protection rule name, etc.                          |
        +-------------------+-----------------------------------------------------------------------+
        | SESSION_ID        | Entity session ID.                                                    |
        +-------------------+-----------------------------------------------------------------------+
        | TYPE              | Type of entity.                                                       |
        +-------------------+-----------------------------------------------------------------------+
    """
    GROUP_NAME = "groupName"
    ID = "id"
    NODE_TEXT_PATH = "_nodeTextPath"
    OS_PLATFORM = "osPlatform"
    OS_TYPE = "osType"
    RULE_NAME = "ruleName"
    SESSION_ID = "sessionID"
    TYPE = "type"

    
class FilesProps:
    """
        +-------------------+-----------------------------------------------------------------------+
        | Name              | Description                                                           |
        +===================+=======================================================================+
        | NAME              | The threat target filename where applicable.                          |            
        +-------------------+-----------------------------------------------------------------------+
        | HASH              | Member name for the hash data, which contains properties with         |
        |                   | provided hashes of the file.                                          |
        |                   |                                                                       |
        |                   | See the :class:`HashProps` constants class for the list of            |
        |                   | properties and members inside of the `hash` member.                   |    
        +-------------------+-----------------------------------------------------------------------+
    """
    NAME = "name"
    HASH = "hash"

    
class SourceProps:
    """
        +-------------------+-----------------------------------------------------------------------+
        | Name              | Description                                                           |
        +===================+=======================================================================+
        | HOST_NAME         | The threat source host name (where applicable).                       |
        +-------------------+-----------------------------------------------------------------------+
        | IPV4              | The threat source 32-bit IPv4 address.                                |
        +-------------------+-----------------------------------------------------------------------+
        | IPV6              | The threat source 128-bit IPv6 address.                               |
        +-------------------+-----------------------------------------------------------------------+
        | MAC               | The threat source MAC address (where applicable).                     |    
        +-------------------+-----------------------------------------------------------------------+
        | PORT              | The threat source port for network-homed threat classes.              |
        +-------------------+-----------------------------------------------------------------------+
        | PROCESS_NAME      | The threat source process name if detectable.                         |
        +-------------------+-----------------------------------------------------------------------+
        | URL               | The threat source URL if detectable.                                  |
        +-------------------+-----------------------------------------------------------------------+
        | USER_NAME         | The threat source user name or email address.                         |
        +-------------------+-----------------------------------------------------------------------+
    """
    HOST_NAME = "hostName"
    IPV4 = "ipv4"
    IPV6 = "ipv6"
    MAC = "mac"
    PORT = "port"
    PROCESS_NAME = "processName"
    URL = "url"
    USER_NAME = "userName"
    
    
class TargetProps:
    """
        +-------------------+-----------------------------------------------------------------------+
        | Name              | Description                                                           |
        +===================+=======================================================================+
        | FILE_NAME         | Target file name.                                                     |
        +-------------------+-----------------------------------------------------------------------+
        | HOST_NAME         | The threat target host name where applicable                          |
        +-------------------+-----------------------------------------------------------------------+
        | IPV4              | The 32-bit threat target IPv4 address.                                |
        +-------------------+-----------------------------------------------------------------------+
        | IPV6              | The 128-bit threat target IPv6 address.                               |
        +-------------------+-----------------------------------------------------------------------+
        | MAC               | The threat target MAC address where applicable.                       |
        +-------------------+-----------------------------------------------------------------------+
        | PORT              | The threat target port for network-homed threat classes.              |
        +-------------------+-----------------------------------------------------------------------+
        | PROCESS_NAME      | The threat target process name where applicable.                      |
        +-------------------+-----------------------------------------------------------------------+
        | PROTOCOL          | The threat target protocol for network-homed threat classes.          |    
        +-------------------+-----------------------------------------------------------------------+
        | USER_NAME         | The threat target user name or email address.                         |
        +-------------------+-----------------------------------------------------------------------+
    """
    FILE_NAME = "fileName"
    HOST_NAME = "hostName"
    IPV4 = "ipv4"
    IPV6 = "ipv6"
    MAC = "mac"
    PORT = "port"
    PROCESS_NAME = "processName"
    PROTOCOL = "protocol"
    USER_NAME = "userName"

    
class HashProps:
    """
    Properties that are used to indicate `hash type`.
    
        +--------+-------------------------------------------------------+
        | Type   | Description                                           |
        +========+=======================================================+
        | MD5    | The MD5 algorithm (128-bit)                           |
        +--------+-------------------------------------------------------+
        | SHA1   | The Secure Hash Algorithm 1 (SHA-1) (160-bit)         |
        +--------+-------------------------------------------------------+
        | SHA256 | The Secure Hash Algorithm 2, 256 bit digest (SHA-256) |
        +--------+-------------------------------------------------------+
    """
    MD5 = "MD5"
    SHA1 = "SHA-1"
    SHA256 = "SHA-256"