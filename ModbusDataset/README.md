### Note 

The download dataset must be extracted here having benign/attack folders.

# Modbus Attack Methods Review


Modbus is a communication protocol widely used in industrial automation systems. 
```md
[an intro to modbus/tcp ](https://unserver.xyz/modbus-guide/)
```

review various attack methods that can be used to compromise Modbus systems, analyzed through network traffic captures using Wireshark and csv log files.
The attacks are categorized into three main sections based on their origin: external attacks, attacks from a compromised SCADA, and attacks from a compromised IED.
Some attack .pcap files/logs are missed or have some common data.

#### Logs (CSV Files)

- Timestamp: The timestamp of the attack event. (Date/Time)
- TargetIP: The IP address of the targeted device. (String)
- Attack: The type of attack. (String)
- TransactionID: The ID of the transaction associated with the attack. (String)


## External Attacks

Attacks from an unknown IP address (185.175.0.7) targeting 185.175.0.4.

| Attack Type            | Description                                                                                                   |
|-----------------------|---------------------------------------------------------------------------------------------------------------|
| Reconnaissance        | Reading queries for all available addresses (up to 65535) or a specific range (e.g., 5) using various function codes across multiple connections in further attacks. |
| Query Flooding        | Sending multiple read queries (e.g., 30) in a burst within a single connection to overwhelm the system.       |
| Length Manipulation   | Altering the length header of Modbus/TCP query packets to a random incorrect value, preventing Wireshark from recognizing the Modbus protocol. |
| Replay Attack         | Resending a previous query payload without proper transaction ID handling.                                    |
| Payload Injection     | Sending a malicious payload (e.g., reading 2 words instead of 1 from reference 8) that deviates from expected patterns, potentially causing system crashes. (Just one sample exists. Maybe wrong implementation.) |
| Stacked Modbus Frames | Sending multiple Modbus frames within a single packet. (Just one sample exists. Maybe wrong implementation.)   |
| Brute Force or Specific | Attempting to write to a specific coil reference with all possible transaction IDs (e.g., 0 to 11024) across multiple connections. |

## Compromised SCADA Attacks

Attacks from 185.175.0.3 targeting 185.175.0.4 and 185.175.0.8. Days 12 to 15 missed in attack logs. Day 21 Attack log TimeStamp format is corrupted (no year-month-day-hour, just minutes and seconds, rounded upwards).

| Attack Type            | Description                                                                                                   |
|-----------------------|---------------------------------------------------------------------------------------------------------------|
| Length Manipulation   | Changing the Modbus/TCP query length header to an incorrect value or more than real one,could making the protocol unrecognizable to Wireshark. |
| Payload Injection     | Appending random payloads (e.g., 5 bytes) to read queries.                                                    |
| Replay Attack         | Resending previous queries in a last-in-first-out (LIFO) order.                                               |
| Query Flooding        | Sending multiple read queries (e.g., 30) in a burst within one connection, with transaction IDs increasing from 0 to 30. It must be said that Query Flooding completed in the log. |
| Stacked Modbus Frames | Sending multiple identical Modbus payloads (e.g., 5) in a single query.                                       |
| Brute Force           | Sending read queries for large data lengths (e.g., 2000 bits of coil) that trigger illegal data address errors, and repeating queries with illegal payloads (Illegal payload for single coil (ffff)). |
| Reconnaissance        | Reading queries for all available addresses (up to 2000) or a specific range (e.g., 5) using various function codes across multiple connections in further attacks. |

## Compromised IED Attacks

Attacks from 185.175.0.5 targeting 185.175.0.2.

| Attack Type            | Description                                                                                                   |
|-----------------------|---------------------------------------------------------------------------------------------------------------|
| Baseline Replay       | Sending identical responses to queries to evade detection by the Human-Machine Interface (HMI).               |
| Starting Payload Injection | Adding random bytes (e.g., 5) to the end of response packets.                                            |
| Delay Response Attack | Intentionally delaying responses (e.g., by 8 seconds) to disrupt system timing.                               |
| False Data Injection  | Responding with incorrect data (e.g., "abcd").                                                                |
| Query Flooding        | Sending multiple identical responses (e.g., 20), with the last one having multiple Modbus payloads.           |
| Frame Stacking        | Including multiple Modbus payloads in a single response.                                                      |
| Length Manipulation   | Modifying the length of responses to prevent Wireshark from detecting the Modbus/TCP protocol.                |