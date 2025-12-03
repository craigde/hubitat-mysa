/**
 * Mysa Thermostat MQTT Driver
 * Version: 2.2.0
 * Author: Craig Dewar
 *
 * Features:
 *  - Standard Hubitat Thermostat capability
 *  - Real-time updates via MQTT over WebSocket
 *  - Temperature/mode control via MQTT
 *  - Model-specific body.type for V1/V2 devices
 *  - Power monitoring (for devices with current sensor)
 */

import groovy.json.JsonSlurper
import groovy.json.JsonOutput
import groovy.transform.Field

@Field static final String DRIVER_VERSION = "2.2.0"

metadata {
    definition(name: "Mysa Thermostat MQTT", namespace: "craigde", author: "Craig Dewar") {
        capability "Thermostat"
        capability "ThermostatHeatingSetpoint"
        capability "ThermostatMode"
        capability "ThermostatOperatingState"
        capability "TemperatureMeasurement"
        capability "RelativeHumidityMeasurement"
        capability "PowerMeter"  // For V1/V2 devices with current sensor
        capability "PresenceSensor"
        capability "Refresh"
        capability "Initialize"

        attribute "rssi", "number"
        attribute "lastUpdate", "string"
        attribute "mqttStatus", "string"
        attribute "dutyCycle", "number"  // 0.0-1.0 heating duty cycle
        attribute "model", "string"  // Device model (BB-V1-1, BB-V2-0, etc.)
        
        command "heat"
        command "off"
        command "setHeatingSetpoint", [[name: "temperature", type: "NUMBER", description: "Temperature setpoint"]]
        command "connectMqtt"
        command "disconnectMqtt"
    }

    preferences {
        input name: "debugLogging", type: "bool", title: "Enable Debug Logging", defaultValue: false
    }
}

def installed() {
    logDebug "Installed"
    sendEvent(name: "supportedThermostatModes", value: ["off", "heat"])
    sendEvent(name: "supportedThermostatFanModes", value: [])
    sendEvent(name: "thermostatFanMode", value: "auto")
    initialize()
}

def updated() {
    logDebug "Updated"
    initialize()
}

def initialize() {
    logDebug "Initializing..."
    
    // Check if this device is the MQTT master
    if (getDataValue("mqttMaster") == "true") {
        logInfo "This device is the MQTT master - establishing WebSocket connection"
        sendEvent(name: "mqttStatus", value: "connecting")
        runIn(5, "connectMqtt")
    } else {
        sendEvent(name: "mqttStatus", value: "slave")
    }
}

def uninstalled() {
    logDebug "Uninstalled"
    disconnectMqtt()
}

def refresh() {
    logDebug "Refresh called"
    parent?.childRefresh(device.deviceNetworkId)
}

/* =========================
 * WebSocket MQTT Connection
 * ========================= */

def connectMqtt() {
    logInfo "Connecting to MQTT via WebSocket..."
    
    if (getDataValue("mqttMaster") != "true") {
        logDebug "Not the MQTT master, skipping connection"
        return
    }
    
    try {
        def mqttDetails = parent?.getMqttConnectionDetails()
        
        if (!mqttDetails?.success) {
            logWarn "Failed to get MQTT details: ${mqttDetails?.error}"
            sendEvent(name: "mqttStatus", value: "error: ${mqttDetails?.error}")
            // Retry in 60 seconds
            runIn(60, "connectMqtt")
            return
        }
        
        state.userId = mqttDetails.userId
        state.userEmail = mqttDetails.userEmail  // Email for src.ref in MQTT commands
        state.subscribeTopics = mqttDetails.subscribeTopics
        state.publishTopicBase = mqttDetails.publishTopicBase
        
        logDebug "Connecting to WebSocket with presigned URL (length: ${mqttDetails.presignedUrl?.length()})"
        logDebug "Will subscribe to topics: ${mqttDetails.subscribeTopics}"
        
        // Connect via WebSocket interface
        // Note: The URL is already a wss:// URL with SigV4 auth in query params
        interfaces.webSocket.connect(
            mqttDetails.presignedUrl,
            byteInterface: true,  // MQTT uses binary framing
            pingInterval: 30,
            headers: [
                "Sec-WebSocket-Protocol": "mqtt"
            ]
        )
        
    } catch (e) {
        logWarn "MQTT connection failed: ${e.message}"
        sendEvent(name: "mqttStatus", value: "error: ${e.message}")
        // Retry in 60 seconds
        runIn(60, "connectMqtt")
    }
}

def disconnectMqtt() {
    logInfo "Disconnecting MQTT..."
    try {
        interfaces.webSocket.close()
    } catch (e) {
        logDebug "Error closing WebSocket: ${e}"
    }
    sendEvent(name: "mqttStatus", value: "disconnected")
}

/* =========================
 * WebSocket Callbacks
 * ========================= */

def webSocketStatus(String message) {
    logDebug "WebSocket status: ${message}"
    
    if (message?.startsWith("status: open")) {
        logInfo "WebSocket connected!"
        sendEvent(name: "mqttStatus", value: "ws-connected")
        // Send MQTT CONNECT packet
        sendMqttConnect()
    } else if (message?.startsWith("status: closing") || message?.startsWith("failure:")) {
        logWarn "WebSocket closed/failed: ${message}"
        state.mqttConnected = false
        sendEvent(name: "mqttStatus", value: "disconnected")
        // Reconnect after delay
        if (getDataValue("mqttMaster") == "true") {
            runIn(30, "connectMqtt")
        }
    }
}

def parse(String message) {
    // Messages come in as hex-encoded bytes when byteInterface: true
    logDebug "Received message (${message?.length()} chars)"
    
    try {
        byte[] data = hubitat.helper.HexUtils.hexStringToByteArray(message)
        parseMqttPacket(data)
    } catch (e) {
        logWarn "Failed to parse message: ${e.message}"
    }
}

/* =========================
 * MQTT Protocol Implementation
 * ========================= */

def sendMqttConnect() {
    logDebug "Sending MQTT CONNECT packet"
    
    // Generate a unique client ID
    def clientId = "hubitat-mysa-${device.id}-${now()}"
    
    // Build MQTT CONNECT packet
    // Protocol Name: "MQTT" (length-prefixed string)
    // Protocol Level: 4 (MQTT 3.1.1)
    // Connect Flags: 0x02 (Clean Session)
    // Keep Alive: 60 seconds
    
    ByteArrayOutputStream packet = new ByteArrayOutputStream()
    
    // Variable header
    // Protocol Name
    def protocolName = "MQTT".getBytes("UTF-8")
    packet.write(0)  // Length MSB
    packet.write(protocolName.length)  // Length LSB
    packet.write(protocolName)
    
    // Protocol Level (4 = MQTT 3.1.1)
    packet.write(4)
    
    // Connect Flags (Clean Session)
    packet.write(0x02)
    
    // Keep Alive (60 seconds)
    packet.write(0)
    packet.write(60)
    
    // Payload - Client ID
    def clientIdBytes = clientId.getBytes("UTF-8")
    packet.write(0)  // Length MSB
    packet.write(clientIdBytes.length)  // Length LSB
    packet.write(clientIdBytes)
    
    // Build fixed header
    def variableHeader = packet.toByteArray()
    int remainingLength = variableHeader.length
    
    ByteArrayOutputStream fullPacket = new ByteArrayOutputStream()
    fullPacket.write(0x10)  // CONNECT packet type
    
    // Encode remaining length (variable length encoding)
    while (remainingLength > 0) {
        int encodedByte = remainingLength % 128
        remainingLength = remainingLength.intdiv(128)
        if (remainingLength > 0) {
            encodedByte = encodedByte | 0x80
        }
        fullPacket.write(encodedByte)
    }
    
    fullPacket.write(variableHeader)
    
    // Send as hex string
    def hexPacket = hubitat.helper.HexUtils.byteArrayToHexString(fullPacket.toByteArray())
    interfaces.webSocket.sendMessage(hexPacket)
    
    logDebug "Sent MQTT CONNECT packet"
}

def sendMqttSubscribe(String topic) {
    logDebug "Sending MQTT SUBSCRIBE for: ${topic}"
    
    state.packetId = (state.packetId ?: 0) + 1
    def packetId = state.packetId
    
    ByteArrayOutputStream packet = new ByteArrayOutputStream()
    
    // Packet ID
    packet.write((packetId >> 8) & 0xFF)
    packet.write(packetId & 0xFF)
    
    // Topic filter (length-prefixed)
    def topicBytes = topic.getBytes("UTF-8")
    packet.write((topicBytes.length >> 8) & 0xFF)
    packet.write(topicBytes.length & 0xFF)
    packet.write(topicBytes)
    
    // QoS (1)
    packet.write(1)
    
    // Build fixed header
    def variableHeader = packet.toByteArray()
    
    ByteArrayOutputStream fullPacket = new ByteArrayOutputStream()
    fullPacket.write(0x82)  // SUBSCRIBE packet type + QoS 1
    writeRemainingLength(fullPacket, variableHeader.length)
    fullPacket.write(variableHeader)
    
    def hexPacket = hubitat.helper.HexUtils.byteArrayToHexString(fullPacket.toByteArray())
    interfaces.webSocket.sendMessage(hexPacket)
}

def sendMqttPublish(String topic, String payload, int qos = 0) {
    logDebug "Sending MQTT PUBLISH to: ${topic}"
    
    ByteArrayOutputStream packet = new ByteArrayOutputStream()
    
    // Topic (length-prefixed)
    def topicBytes = topic.getBytes("UTF-8")
    packet.write((topicBytes.length >> 8) & 0xFF)
    packet.write(topicBytes.length & 0xFF)
    packet.write(topicBytes)
    
    // Packet ID (only if QoS > 0)
    if (qos > 0) {
        state.packetId = (state.packetId ?: 0) + 1
        def packetId = state.packetId
        packet.write((packetId >> 8) & 0xFF)
        packet.write(packetId & 0xFF)
    }
    
    // Payload
    def payloadBytes = payload.getBytes("UTF-8")
    packet.write(payloadBytes)
    
    // Build fixed header
    def variableHeader = packet.toByteArray()
    def fixedHeader = 0x30 | (qos << 1)  // PUBLISH packet type
    
    ByteArrayOutputStream fullPacket = new ByteArrayOutputStream()
    fullPacket.write(fixedHeader)
    writeRemainingLength(fullPacket, variableHeader.length)
    fullPacket.write(variableHeader)
    
    def hexPacket = hubitat.helper.HexUtils.byteArrayToHexString(fullPacket.toByteArray())
    interfaces.webSocket.sendMessage(hexPacket)
}

def sendMqttPingreq() {
    logDebug "Sending MQTT PINGREQ"
    // PINGREQ is just 0xC0 0x00
    interfaces.webSocket.sendMessage("C000")
}

private void writeRemainingLength(ByteArrayOutputStream out, int length) {
    if (length == 0) {
        out.write(0)
        return
    }
    while (length > 0) {
        int encodedByte = length % 128
        length = length.intdiv(128)
        if (length > 0) {
            encodedByte = encodedByte | 0x80
        }
        out.write(encodedByte)
    }
}

def parseMqttPacket(byte[] data) {
    if (data.length < 2) {
        logWarn "Packet too short"
        return
    }
    
    def packetType = (data[0] & 0xF0) >> 4
    
    switch (packetType) {
        case 2:  // CONNACK
            logInfo "Received MQTT CONNACK"
            handleConnack(data)
            break
        case 3:  // PUBLISH
            logDebug "Received MQTT PUBLISH"
            handlePublish(data)
            break
        case 4:  // PUBACK
            logDebug "Received MQTT PUBACK"
            break
        case 9:  // SUBACK
            logDebug "Received MQTT SUBACK"
            break
        case 13:  // PINGRESP
            logDebug "Received MQTT PINGRESP"
            break
        default:
            logDebug "Unknown MQTT packet type: ${packetType}"
    }
}

def handleConnack(byte[] data) {
    // CONNACK format: [0x20, 0x02, session_present, return_code]
    if (data.length >= 4) {
        def returnCode = data[3] & 0xFF
        if (returnCode == 0) {
            logInfo "MQTT connection accepted"
            state.mqttConnected = true
            sendEvent(name: "mqttStatus", value: "connected")
            
            // Subscribe to topics
            state.subscribeTopics?.each { topic ->
                sendMqttSubscribe(topic)
            }
            
            // Schedule periodic ping
            schedule("0 */1 * * * ?", "sendMqttPingreq")  // Every minute
        } else {
            logWarn "MQTT connection refused, return code: ${returnCode}"
            state.mqttConnected = false
            sendEvent(name: "mqttStatus", value: "refused: ${returnCode}")
        }
    }
}

def handlePublish(byte[] data) {
    // Parse the PUBLISH packet
    try {
        def offset = 1
        
        // Parse remaining length (variable length encoding)
        def remainingLength = 0
        def multiplier = 1
        def encodedByte = 0x80  // Initialize to enter loop
        while ((encodedByte & 0x80) != 0) {
            encodedByte = data[offset++] & 0xFF
            remainingLength += (encodedByte & 0x7F) * multiplier
            multiplier *= 128
        }
        
        def variableHeaderStart = offset
        
        // Topic length
        def topicLengthMSB = data[offset++] & 0xFF
        def topicLengthLSB = data[offset++] & 0xFF
        def topicLength = (topicLengthMSB << 8) | topicLengthLSB
        
        // Topic
        def topic = new String(data, offset, topicLength, "UTF-8")
        offset += topicLength
        
        // QoS
        def qos = (data[0] & 0x06) >> 1
        
        // Packet ID (if QoS > 0)
        if (qos > 0) {
            def packetIdMSB = data[offset++] & 0xFF
            def packetIdLSB = data[offset++] & 0xFF
            def packetId = (packetIdMSB << 8) | packetIdLSB
            // Send PUBACK
            sendMqttPuback(packetId)
        }
        
        // Payload - everything after variable header
        def payloadLength = remainingLength - (offset - variableHeaderStart)
        def payload = ""
        if (payloadLength > 0) {
            payload = new String(data, offset, payloadLength, "UTF-8")
        }
        
        logInfo "MQTT PUBLISH received: topic=${topic}"
        logDebug "MQTT PUBLISH payload: ${payload?.take(300)}"
        
        // Parse JSON payload and forward to parent with topic
        try {
            def jsonPayload = new JsonSlurper().parseText(payload)
            parent?.processMqttMessage(device, topic, jsonPayload)
        } catch (e) {
            logDebug "Non-JSON payload received: ${e.message}"
        }
        
    } catch (e) {
        logWarn "Error parsing PUBLISH: ${e.message}"
    }
}

def sendMqttPuback(int packetId) {
    logDebug "Sending MQTT PUBACK for packet ${packetId}"
    ByteArrayOutputStream packet = new ByteArrayOutputStream()
    packet.write(0x40)  // PUBACK packet type
    packet.write(0x02)  // Remaining length = 2
    packet.write((packetId >> 8) & 0xFF)
    packet.write(packetId & 0xFF)
    
    def hexPacket = hubitat.helper.HexUtils.byteArrayToHexString(packet.toByteArray())
    interfaces.webSocket.sendMessage(hexPacket)
}

/* =========================
 * Thermostat Commands
 * ========================= */

def setHeatingSetpoint(temperature) {
    logInfo "setHeatingSetpoint: ${temperature}"
    
    def deviceId = getDataValue("mysaId")
    if (!deviceId) {
        logWarn "No device ID set"
        return
    }
    
    logDebug "state.mqttConnected = ${state.mqttConnected}"
    
    // Try MQTT first, fall back to REST
    if (state.mqttConnected == true) {
        logInfo "Sending setpoint via MQTT"
        def command = buildMysaCommand("sp", temperature)
        publishMqttCommand(deviceId, command)
    } else {
        logInfo "MQTT not connected, falling back to parent (REST)"
        // Fall back to REST API via parent
        parent?.childSetHeatingSetpoint(device.deviceNetworkId, temperature)
    }
}

def setThermostatMode(mode) {
    logInfo "setThermostatMode: ${mode}"
    
    def deviceId = getDataValue("mysaId")
    if (!deviceId) {
        logWarn "No device ID set"
        return
    }
    
    def modeValue = (mode == "heat") ? 3 : 1
    
    if (state.mqttConnected) {
        def command = buildMysaCommand("md", modeValue)
        publishMqttCommand(deviceId, command)
    } else {
        parent?.childSetThermostatMode(device.deviceNetworkId, mode)
    }
}

def heat() {
    setThermostatMode("heat")
}

def off() {
    setThermostatMode("off")
}

def auto() {
    logWarn "Auto mode not supported by Mysa"
}

def cool() {
    logWarn "Cool mode not supported by Mysa"
}

def emergencyHeat() {
    logWarn "Emergency heat mode not supported by Mysa"
}

def setCoolingSetpoint(temperature) {
    logWarn "Cooling setpoint not supported by Mysa"
}

def setThermostatFanMode(fanMode) {
    logWarn "Fan mode not supported by Mysa"
}

def fanAuto() {
    logWarn "Fan mode not supported by Mysa"
}

def fanCirculate() {
    logWarn "Fan mode not supported by Mysa"
}

def fanOn() {
    logWarn "Fan mode not supported by Mysa"
}

/* =========================
 * MQTT Command Building
 * ========================= */

def buildMysaCommand(String cmdType, value) {
    // Build Mysa MQTT command format based on bourquep's mysa-js-sdk
    // Format for /v1/dev/$DID/in with QOS=1
    def timestamp = (long)(now() / 1000)
    def timestampMs = now()
    def deviceId = getDataValue("mysaId")
    def model = getDataValue("model") ?: "Unknown"
    
    // Get userEmail from state (set by MQTT master from app)
    // Per bourquep's SDK: src.ref should be the username (email), not the UUID
    def srcRef = state.userEmail ?: state.userId ?: "unknown"
    
    logDebug "Building command: cmdType=${cmdType}, value=${value}, model=${model}, srcRef=${srcRef}"
    
    // For setpoint changes, value should be in Celsius
    // If the device is set to Fahrenheit, convert
    def valueToSend = value
    if (cmdType == "sp") {
        def format = getDataValue("format") ?: "celsius"
        logDebug "Device format: ${format}"
        if (format == "fahrenheit") {
            // Convert Fahrenheit to Celsius for the API
            valueToSend = fahrenheitToCelsius(value)
            logDebug "Converted ${value}°F to ${valueToSend}°C"
        }
        // Round to 0.5 degree increments
        valueToSend = Math.round(valueToSend * 2) / 2.0
        logDebug "Rounded setpoint: ${valueToSend}°C"
    }
    
    // Determine body type based on device model
    // Per bourquep's mysa-js-sdk MysaApiClient.ts:
    // BB-V1-* → type: 1
    // AC-V1-* → type: 2
    // BB-V2-*-L (Lite) → type: 5
    // BB-V2-* (non-Lite) → type: 4
    // Default → type: 0
    def bodyType = 0
    if (model.startsWith("BB-V1")) {
        bodyType = 1
    } else if (model.startsWith("AC-V1")) {
        bodyType = 2
    } else if (model.startsWith("BB-V2")) {
        if (model.endsWith("-L")) {
            bodyType = 5  // V2 Lite
        } else {
            bodyType = 4  // V2 non-Lite
        }
    } else if (model.startsWith("INF-V1")) {
        bodyType = 1  // Floor heater, assume V1 format
    }
    
    logDebug "Model '${model}' -> body.type = ${bodyType}"
    
    // Command format from bourquep's SDK:
    // body.cmd contains array with the command object
    def cmdObj = [tm: -1]
    cmdObj[cmdType] = valueToSend
    
    def command = [
        Timestamp: timestamp,
        body: [
            cmd: [cmdObj],
            type: bodyType,
            ver: 1
        ],
        dest: [
            ref: deviceId,
            type: 1
        ],
        id: timestampMs,
        msg: 44,
        resp: 2,
        src: [
            ref: srcRef,
            type: 100
        ],
        time: timestamp,
        ver: "1.0"
    ]
    
    logDebug "Built command: ${command}"
    return command
}

private BigDecimal fahrenheitToCelsius(value) {
    return (value - 32) * 5 / 9
}

def publishMqttCommand(String deviceId, Map command) {
    if (getDataValue("mqttMaster") != "true") {
        // Forward to master device
        def masterDevice = parent?.getChildDevices()?.find { it.getDataValue("mqttMaster") == "true" }
        if (masterDevice) {
            masterDevice.publishMqttCommand(deviceId, command)
        }
        return
    }
    
    // Correct topic format: /v1/dev/{deviceId}/in
    def topic = "/v1/dev/${deviceId}/in"
    def payload = JsonOutput.toJson(command)
    
    logInfo "Publishing command to ${topic}"
    logDebug "Command payload: ${payload?.take(300)}"
    sendMqttPublish(topic, payload, 1)
}

/* =========================
 * Logging
 * ========================= */

private void logDebug(msg) { if (debugLogging) log.debug "[MysaThermostat] ${msg}" }
private void logInfo(msg) { log.info "[MysaThermostat] ${msg}" }
private void logWarn(msg) { log.warn "[MysaThermostat] ${msg}" }
