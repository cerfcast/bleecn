## Cerf-Bleecn - Detect ECN Bleeching

_Cerf-Bleecn_ is part of the _Cerfcast_ suite of tools. The goal of _Cerf-Bleecn_ is to help a user determine whether their network is "bleaching" explicit congestion notification (ECN) markings present in IP packets.

A network stack can include ECN markings in an IP packet in order to alert its peer host (and other hosts along the path between it and its peer) that it contains logic to respond to non-packet-drop notifications of network congestion. Prior to ECN, the only way for a host (or the network) to signal to another host that the network path was congested was to drop a packet. Thanks to ECN, it is possible for network devices to signal "early" to a host on the network that congestion is present _without_ having to drop a packet.

For more information about ECN, read the [IETF RFC](https://datatracker.ietf.org/doc/html/rfc3168).

Some network devices "bleach" these markings -- in other words, they take whatever values are set for these markings in the IP header and either remove them or reset them to some default value. No matter how a packet's ECN markings are bleached, the presence of a bleaching node means that new network optimization techniques (e.g., [L4S](https://datatracker.ietf.org/doc/rfc9330/)) cannot function.

_Cerf-Bleecn_ is meant to help users determine whether their networks are bleaching ECN markings _and_ help network administrators determine if other networks are bleaching ECN markings.

### The Technique

More to come.

### Usage

#### Building

TODO

#### Running

TODO

#### Collecting Results

TODO