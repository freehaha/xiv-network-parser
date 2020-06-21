# Usage
Create a zmq publisher socket on `/tmp/ffxiv_packets` listening to ff packets on `eth0`:
```
./ffxiv-network-parser eth0 /tmp/ffxiv_packets
```
add `sudo` if you don't have the permission to listen to the interface, or use the following command to set its capabilities.

## Set permissions

You can setcap the parser if you don't want to sudo it all the time.
```sh
sudo setcap cap_net_raw,cap_net_admin=+eip ./bin/ffxiv-network-parser
```


# Build
```sh
cargo build --release
```
