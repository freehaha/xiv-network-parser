# Usage

Create a zmq publisher socket on `/tmp/ffxiv_packets` listening to ff packets on `eth0`:

```
./ffxiv-network-parser eth0 /tmp/ffxiv_packets
```

add `sudo` if you don't have the permission to listen to the interface, or use the following command to set its capabilities.

The broadcasted packets takes the form of:

| position | bytes | field                                              |
| -------- | ----- | -------------------------------------------------- |
| 0-1      | 2     | 'p '                                               |
| 2        | 1     | a serial number 1-128 indicating the sequence      |
| 3-10     | 8     | 64 bit time, msec since Epoch. This is server time |
| 11-eof   | \*    | packet content (binary)                            |

## Set permissions

You can setcap the parser if you don't want to sudo it all the time.

```sh
sudo setcap cap_net_raw,cap_net_admin=+eip ./bin/ffxiv-network-parser
```

# Build

```sh
cargo build --release
```

# Usage with Node.js

```javascript
const zmq = require("zeromq/v5-compat");
const bparser = require("binary-parser").Parser;
const { unpackPacket, parsePackets } = require("xiv-packet");

let packetHeader = new bparser()
  .endianess("little")
  .seek(3) // skip the sn number
  .uint64le("time", {
    formatter: function (time) {
      return Number(time);
    },
  })
  .buffer("rawPacket", {
    readUntil: "eof",
  });

let sock = zmq.socket("sub");
sock.connect("ipc:///tmp/ffxiv_packets");
sock.subscribe("p");
sock.on("message", (msg) => {
  let header = packetHeader.parse(msg);
  let packet = unpackPacket(header.rawPacket, header.time);
  let events = parsePackets([packet]);
  console.log(events);
});
```

can also be found in the `example` directory
