# Honeycomb & Hive overview
Hive is the name given to the infrastructure that communicates and controls
infected hosts. There are a few components in this system:
- Infected client: The victim.
- VPS proxy: A reverse proxy to avoid detection.
- Blot server: Actual control & communication.
- Cover server: A fake server that responds like a legitimate website.
- Honeycomb: Logger.

## Blot
The server seems to be capable of communicating with the infected host and
obtaining a root shell within it.

## Honeycomb
Specifically, Honeycomb has the job of receiving "beacons" produced by the Blot
server containing client data and logging them into `.rsi` files, which later
get tranferred to the "RipperSnapper" servers.

The actual data sent from the Blot servers is encrypted with the xtea algorithm,
with the key being generated by the Honeycomb server and being sent back to the
blot server in the clear.

These log files contain the following data, among others:
- MAC address
- IP address
- Uptime
- Client OS
- List of running processes
- `ipconfig` data
- `netstat -rn` (routing) & `netstat -an` data
