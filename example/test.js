const zmq = require("zeromq/v5-compat");
const bparser = require("binary-parser").Parser;
const { unpackPacket, parsePackets } = require("xiv-packet");

let packetHeader = new bparser()
  .endianess("little")
  .seek(3)
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
