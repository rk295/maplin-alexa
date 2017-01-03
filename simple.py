#!/usr/bin/env bash
import logging
import os
import paho.mqtt.subscribe as subscribe
import paho.mqtt.publish as publish
import sys
import json
import base64

logging.basicConfig()
logger = logging.getLogger()
logger.setLevel(logging.DEBUG)

logger.info("Starting")


def lambda_handler(event=None, context=None):
    #
    # lambda_handler is the main entry point for AWS lambda, it receives an
    # 'event' and a lamba context object.
    #
    # Parsing the event lets us figure out if this is a service discovery event
    # or a control event (Switch something on or off)
    #
    logger.debug("incoming event=%s" % json.dumps(event))

    # Get all these from env vars set inside the lambda job.
    hostname = os.getenv('MQTT_HOST')
    port = os.getenv('MQTT_PORT')
    config_topic = os.getenv('MQTT_CONFIG_TOPIC')
    action_topic = os.getenv('MQTT_ACTION_TOPIC')
    username = os.getenv('MQTT_USERNAME', None)
    password = os.getenv('MQTT_PASSWORD', None)

    if username is not None and password is not None:
        logging.debug("Connecting to MQTT with authentication")
        auth = {'username': username, 'password': password}
    else:
        logging.debug("Connecting to MQTT without authentication")

    logger.debug("MQTT connecting to host=%s:%s" % (hostname, port))
    logger.debug("config_topic=%s" % config_topic)
    logger.debug("action_topic=%s" % action_topic)

    if event['header']['namespace'] == 'Alexa.ConnectedHome.Discovery':
        # If this is a Discovery request, hit up the config_topic and parse the
        # JSON in the retained message. This will give us all the possible room
        # names.
        logger.info("service discovery request")
        try:
            switch_config = get_config(hostname, port, auth, config_topic)
        except Exception as e:
            logger.error("get_config failed, can't continue")
            logger.error(e.msg)
            sys.exit(1)

        # handle_discovery walks the dict from get_config constructing a valid
        # Alexa response for a discovery request.
        return handle_discovery(switch_config)

    elif event['header']['namespace'] == 'Alexa.ConnectedHome.Control':

        # If its an action request simply pass on all the bits to
        # `handle_control`
        logger.info("control action request")
        return handle_control(event, hostname, port, auth, action_topic)

    return


def handle_discovery(switch_config):
    #
    # Requires the original inbound lambda event, and a switch config
    # dictionary which is the parsed JSON object that sits as a retained
    # message on the topic defined in 'config_topic'.

    # First we create a header, and then for each room we bung a device section
    # into the 'discoveredAppliances' array, inside the payload object of the
    # response.

    # Template for each individual device.
    device_data_template = {
        "friendlyDescription": "",
        "modelName": "model 01",
        "version": "0.1",
        "manufacturerName": "RK Industries",
        "actions": [
            "turnOn",
            "turnOff"
        ],
        "isReachable": True
    }

    # Template for the main response, devices get stored under
    # the payload.discoveredAppliances array..
    data = {
        "header": {
            "payloadVersion": "2",
            "namespace": "Alexa.ConnectedHome.Discovery",
            "name": "DiscoverAppliancesResponse"
        },
        "payload": {
            "discoveredAppliances": []
        }
    }

    # Holding list for all the devices.
    appliances = []

    # For each switch under the 'rooms' top level object, store a device object
    # in the appliances list.
    for switch in switch_config["rooms"]:

        logger.debug("Processing %s" % switch)

        # Grab a copy of the template.
        switch_data = device_data_template

        # Push in a friendly description.
        switch_data["friendlyDescription"] = (
            "The Maplin socket for the %s" % switch)

        # The actual name of the switch.
        switch_data["friendlyName"] = switch

        # The unique id of the device, simply base64 encode the name
        switch_data["applianceId"] = base64.b64encode(switch)

        # using .copy() here to avoid adding a reference to the list
        appliances.append(switch_data.copy())

    # Push the entire appliances list into the response payload.
    data["payload"]["discoveredAppliances"] = appliances
    logger.debug("Final response data =%s" % json.dumps(data))

    # return the whole object.
    return data


def handle_control(event, hostname, port, auth, action_topic):

    # Grab the actual action
    event_action = event["header"]["name"]

    # Its either on or off, or an error
    if event_action == "TurnOnRequest":
        action = "on"
        action_confirmation = "TurnOnConfirmation"
    elif event_action == "TurnOffRequest":
        action = "off"
        action_confirmation = "TurnOffConfirmation"
    else:
        logger.error("Action wasn't TurnOnRequest or TurnOffConfirmation")
        logger.error("Can't continue")
        sys.exit(1)

    # Grab the applianceId (Was base64 encoded by handle_discovery.
    b64_switch_name = event["payload"]["appliance"]["applianceId"]
    logger.debug("Read switch name=%s" % b64_switch_name)

    # Decode that into the real name.
    switch_name = base64.b64decode(b64_switch_name)
    logger.debug("Decoded switch name=%s" % switch_name)

    # Construct a dictionary of the format our maplin-mqtt listener on the
    # Pi expects.
    mqtt_payload = {"switch": switch_name, "action": action}
    logger.debug("mqtt_payload=%s" % mqtt_payload)

    # Try and publish this to MQTT, using websockets as a transport here,
    # because thats all I expose externally for MQTT.
    try:
        publish.single(action_topic,
                       payload=json.dumps(mqtt_payload),
                       retain=False,
                       hostname=hostname,
                       port=port,
                       auth=auth,
                       transport="websockets")
    except Exception as e:
        # There is nowt much we can do here, so bail.
        # TODO: Figure out how to tell Alexa something went wrong.
        logging.error("failed to connect: %s" % e)
        sys.exit(1)

    # This is the format of a reply Alexa likes, probably should generate a
    # unique message id.
    reply = {
        "header": {
            "messageId": "26fa11a8-accb-4f66-a272-8b1ff7abd722",
            "name": action_confirmation,
            "namespace": "Alexa.ConnectedHome.Control",
            "payloadVersion": "2"
        },
        "payload": {}
    }

    logger.debug("replying message=%s" % reply)
    return reply


def get_config(hostname, port, auth, config_topic):

    try:
        logger.debug("Retrieving a single message from topic=%s" %
                     config_topic)
        msg = subscribe.simple(config_topic,
                               hostname=hostname,
                               port=port,
                               auth=auth,
                               transport="websockets"
                               )
        logger.debug("Retrieved a message payload=%s" % msg.payload)
    except Exception as e:
        logging.error("failed to connect: %s" % e)
        sys.exit(1)

    try:
        switches = json.loads(msg.payload)
    except Exception as e:
        logger.error("Failed to parse JSON from message")
        raise

    return switches


if __name__ == "__main__":

    # These two are used for testing from outside of Lambda.
    #
    # The first is a sample discovery request.
    # The second is a sample On request for a given room (In this case 'Tank'
    # base64 decoded from 'applianceId'
    sample_dsicovery = {
        "header": {
            "payloadVersion": "2",
            "namespace": "Alexa.ConnectedHome.Discovery",
            "name": "DiscoverAppliancesRequest"
        },
        "payload": {
            "accessToken": "someaccesstoken"
        }
    }

    sample_action = {
        "header": {
            "messageId": "01ebf625-0b89-4c4d-b3aa-32340e894688",
            "name": "TurnOffRequest",
            "namespace": "Alexa.ConnectedHome.Control",
            "payloadVersion": "2"
        },
        "payload": {
            "accessToken": "[OAuth Token here]",
            "appliance": {
                "additionalApplianceDetails": {},
                "applianceId": "VGFuaw=="
            }
        }
    }

    print "Doing a sample discovery"
    lambda_handler(sample_dsicovery)
    print "Doing a toggle (tank)"
    lambda_handler(sample_action)
