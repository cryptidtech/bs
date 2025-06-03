# Interoperability tests

This test:

- Create a native [BsPeer](../bs-peer/) instance.
- Serve the Multiaddr of the native BsPeer
- Await for the browser BsPeer to connect to the native BsPeer
- Upon Connection, native peer looks up the PeerId from the DHT to get the plog head Cid
- native peer fetches the browser's Plog from head Cid via bitswap, recursively, then verifies it.
- assert! and close test

- Create a browser [BsPeer](../bs-peer/) instance
- Use BsPeer to generate a new Plog
- That Plog will be saved to the Browser blockstore.
- Publish the Plog head Cid to the DHT
- Dial the server node.
- how to know to assert and close the test?
