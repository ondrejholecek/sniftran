# SnifTran

Program to convert plain text traffic capture from FortiGate and other Fortinet appliances to PCAPng usable in Wireshark. 

## Features

* Automatically adds the interface name and traffic direction to PCAPng comments section. 
* Ability to select only some interfaces to include from the capture (--include or --exclude parameters)
* Ability to decode captures on p2p (ppp) interfaces 
* Ability to decode capture taken with FortiGate sniffer option "5"

## Usage

1. Capture the plaintext packets into a text file
  - For FortiGate use: "diag sniffer packet ..." with the parameter 6 (full packets with interface and data).
  - For FortiAuthenticator use: "tcpdump -XXe -s0 -tt -ni ..."
 
2. Run sniftran with --in parameter specifying the text file with packets

3. File with the same name and ".pcapng" suffix will be created. If you want different name for the PCAPng, use the --out parameter.

## Wireshark

The main benefit of this script compared to the old official one (besides the better speed) is that it includes the interface name and traffic direction in the packet comments. This can be then added as a column to the packet list and/or filtered by. 

The comments will look like: "(out) port33" or "(in)  port34". If you want to see only packets on the interface port33 in both directions, you can use following Wireshark filter: 

```
frame.comment contains "port33"
```

## Binaries

The Binaries directory contains the "binaries" for Windows/Linux/MacOS and a new one can created by running "make" in the target platform (pyinstaller is needed).

However, be aware that these are not really binaries, but rather the executables containing the Python interpreter and the bytecode. It may still be necessary to have the right Python version installed in your environment.

## Other parameters

```
$ ./sniftran.py -h

===
=== SnifTran - written by Ondrej Holecek <ondrej at holecek dot eu>
===

usage: ./sniftran.py --in <inputfile> [optional_parameters...]

   mandatory parameters:
    --in <inputfile>                   ... text file with captured packets, "-in" can be used for compatability

   optional parameters:
    --out <outputfile>                 ... name of the output pcap file, by default <inputfile>.pcapng
    --no-overwrite                     ... do not overwrite the output file if it already exists
    --no-compat                        ... disable the compatability with new FE and FAC sniffers outputs
    --skip <number>                    ... skip first <number> packets
    --limit <number>                   ... save only <number> packets
    --no-checks                        ... disable packet integrity checks
    --no-normalize-lines               ... do not try to normalize packet lines before parsing them
    --no-wireshark-ipsec               ... do not update Wireshark config file with found IPSec tunnels
    --include <interface>              ... save only packets from/to this interface (can be used multiple times)
    --exclude <interface>              ... ignore packets from/to this interface (can be used multiple times)
    --p2p <interface>                  ... mark interface as point-to-point, will try to correctly remove artifical ethernet header
    --nolink <interface>               ... for this interface, do not expect any link layer information (for sniffer with parameter 5)

   pcapng parameters:
    --section-size <number>            ... amount if packets in one SHB, default unlimited (Wireshark does not support anything else!)
    --max-packets <count>              ... maximum amount of packets in one pcapng file, writes multiple files if neceesary

   debug options:
    --debug <level>                    ... enable debug on specified level (1 - ?)
    --show-packets                     ... prints binary content of each packet and additional info (timestamp, interface, ...)
    --show-timestamps                  ... for performance test, show timestamp before each main operation block
    --stop-on-error                    ... raise an exception when packet parsing error occurres
    --include-packet-line              ... inserts the first line in the original file where the packet was found
    --progress                         ... show progress when parsing and assembling packets, be aware of small speed penalty

notes:
   FortiGate           - "diagnose sniffer packet ..." must be run with level 6
                       - if there are issues with considering also non-packet lines, disable FE & FAC compatibility mode
   FortiMail           - with compatibility mode (default) even the new format is recognized
   FortiAuthenticator  - command to collect packets must be "tcpdump -XXe -s0 -tt -ni <interface> <filter>..."
```

