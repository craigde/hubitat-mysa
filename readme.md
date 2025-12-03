# Mysa Thermostat Integration for Hubitat

A complete Hubitat Elevation integration for Mysa smart thermostats with real-time MQTT control.

## Features

- **Real-time updates** via MQTT over WebSocket - no polling delay
- **Full thermostat control** - temperature setpoint and mode (heat/off)
- **Live sensor data** - temperature, humidity, and operating state
- **Power monitoring** - for devices with current sensors (V1, V2 non-Lite)
- **Multi-device support** - manage all your Mysa thermostats from one app
- **Standard Hubitat capabilities** - works with dashboards, Rule Machine, and other apps

## Supported Devices

| Model | Name | Body Type | Power Monitoring |
|-------|------|-----------|------------------|
| BB-V1-1 | Mysa Baseboard V1 | 1 | ✅ Yes |
| BB-V2-0 | Mysa Baseboard V2 | 4 | ✅ Yes |
| BB-V2-0-L | Mysa Baseboard V2 Lite | 5 | ❌ No |
| INF-V1-0 | Mysa In-Floor V1 | 1 | ✅ Yes |
| AC-V1-* | Mysa for AC | 2 | Varies |

## Requirements

- Hubitat Elevation hub (firmware 2.3.0 or later recommended)
- Mysa thermostat(s) configured and working with the Mysa mobile app
- Mysa account credentials (email and password)

## Installation

### Step 1: Install the Driver

1. In Hubitat, go to **Drivers Code**
2. Click **New Driver**
3. Copy and paste the contents of `MysaThermostatDriver_MQTT.groovy`
4. Click **Save**

### Step 2: Install the App

1. In Hubitat, go to **Apps Code**
2. Click **New App**
3. Copy and paste the contents of `MysaApp_MQTT.groovy`
4. Click **Save**

### Step 3: Configure the App

1. Go to **Apps** → **Add User App**
2. Select **Mysa Integration MQTT**
3. Click **Configure Credentials**
4. Enter your Mysa account email and password
5. Click **Done** to save

### Step 4: Discover Devices

1. Open the Mysa Integration app
2. Click **Manage Devices**
3. Click **Discover Devices** - your thermostats will appear in the list
4. Click **Create All Devices** to add them to Hubitat

### Step 5: Enable MQTT (Real-time Updates)

1. In the app, click **MQTT Settings**
2. Click **Initialize MQTT** to establish the connection
3. The first device created becomes the "MQTT Master" and manages the WebSocket connection

## Configuration Options

### App Settings

| Setting | Description | Default |
|---------|-------------|---------|
| Poll Interval | Backup polling frequency (MQTT provides real-time updates) | 15 minutes |
| Enable MQTT | Enable real-time MQTT updates | On |
| Debug Logging | Enable detailed logging for troubleshooting | Off |

### Driver Settings

| Setting | Description | Default |
|---------|-------------|---------|
| Debug Logging | Enable detailed logging for troubleshooting | Off |

## Device Capabilities

The driver exposes standard Hubitat capabilities:

| Capability | Attributes | Commands |
|------------|------------|----------|
| Thermostat | temperature, heatingSetpoint, thermostatMode, thermostatOperatingState | setHeatingSetpoint, heat, off |
| TemperatureMeasurement | temperature | - |
| ThermostatHeatingSetpoint | heatingSetpoint | setHeatingSetpoint |
| ThermostatMode | thermostatMode | heat, off |
| ThermostatOperatingState | thermostatOperatingState | - |
| RelativeHumidityMeasurement | humidity | - |
| PowerMeter | power | - |
| Refresh | - | refresh |

### Custom Attributes

| Attribute | Description |
|-----------|-------------|
| model | Device model (BB-V1-1, BB-V2-0, etc.) |
| dutyCycle | Heating duty cycle (0.0 to 1.0) |
| mqttStatus | MQTT connection status |
| lastUpdate | Timestamp of last update |

## How It Works

This integration uses the same cloud APIs as the official Mysa mobile app:

1. **Authentication**: AWS Cognito SRP (Secure Remote Password) protocol
2. **Device Discovery**: Mysa REST API
3. **Real-time Control**: MQTT over WebSocket to AWS IoT Core
4. **Message Format**: JSON commands with model-specific body types

### Architecture

```
┌─────────────┐     ┌─────────────┐     ┌─────────────┐
│   Hubitat   │────▶│  AWS IoT    │────▶│    Mysa     │
│     Hub     │◀────│   (MQTT)    │◀────│ Thermostat  │
└─────────────┘     └─────────────┘     └─────────────┘
       │                                       │
       │           ┌─────────────┐            │
       └──────────▶│  Mysa API   │◀───────────┘
                   │   (REST)    │
                   └─────────────┘
```

## Troubleshooting

### MQTT Not Connecting

1. Check that your credentials are correct in the app settings
2. Ensure "Enable MQTT" is turned on
3. Go to MQTT Settings and click "Initialize MQTT"
4. Check the logs for connection errors

### Commands Not Working

1. Verify MQTT status shows "connected" on the device page
2. Check that the device model is detected correctly (shown in Data section)
3. Enable debug logging and check the logs for command details
4. Ensure your Mysa account can control the device via the mobile app

### Device Not Discovered

1. Ensure the thermostat is set up and working in the Mysa mobile app
2. Check your credentials are correct
3. Click "Discover Devices" again
4. Check the logs for any API errors

### Temperature Units

The integration respects the temperature format configured in your Mysa app (Celsius or Fahrenheit). This is stored per-device and used for display and commands.

## Technical Details

### MQTT Topics

- **Subscribe**: `/v1/dev/{deviceId}/out` - messages from thermostat
- **Publish**: `/v1/dev/{deviceId}/in` - commands to thermostat

### Command Format

```json
{
  "Timestamp": 1733250000,
  "body": {
    "cmd": [{"sp": 21.0, "tm": -1}],
    "type": 4,
    "ver": 1
  },
  "dest": {"ref": "deviceId", "type": 1},
  "id": 1733250000123,
  "msg": 44,
  "resp": 2,
  "src": {"ref": "user@email.com", "type": 100},
  "time": 1733250000,
  "ver": "1.0"
}
```

### Authentication Flow

1. SRP authentication with AWS Cognito User Pool
2. Exchange tokens for AWS Cognito Identity credentials
3. Generate SigV4 presigned WebSocket URL for AWS IoT
4. Connect via WebSocket with MQTT protocol

## Credits

This integration was developed with insights from:

- [dlenski/mysotherm](https://github.com/dlenski/mysotherm) - MQTT message format documentation
- [bourquep/mysa-js-sdk](https://github.com/bourquep/mysa-js-sdk) - Command structure and model-specific types
- [AWS Amplify](https://github.com/aws-amplify/amplify-js) - SRP authentication reference

## Disclaimer

This integration is not affiliated with, endorsed by, or connected to Mysa Smart Thermostats or Empowered Homes. It uses undocumented APIs that may change at any time. Use at your own risk.

## License

MIT License - See [LICENSE](LICENSE) for details.

## Version History

### 2.2.0
- Updated namespace to `craigde`
- Added PowerMeter capability for devices with current sensors
- Added dutyCycle and model attributes
- Code cleanup and documentation

### 2.1.0
- Fixed body.type for V2 devices (type 4 for BB-V2-0)
- Fixed src.ref to use email instead of identity ID
- Commands now work correctly for all device models

### 2.0.0
- Complete rewrite with MQTT support
- Real-time updates via WebSocket
- Correct topic structure (`/v1/dev/{deviceId}/in` and `/out`)
- Removed non-functional REST API control

### 1.x
- Initial REST API only version (polling only, no control)
