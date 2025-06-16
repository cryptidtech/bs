# Interoperability tests

This test:

On the server side:

- Create a native [BsPeer](../bs-peer/) instance.
- Serve the Multiaddr of the native BsPeer
- Await for the browser BsPeer to connect to the native BsPeer
- Upon Connection, native peer looks up the PeerId from the DHT to get the plog head Cid
- native peer fetches the browser's Plog from head Cid via bitswap, recursively, then verifies it.
- assert! and close test

On the browser side:

- Create a browser [BsPeer](../bs-peer/) instance
- Use BsPeer to generate a new Plog
- That Plog will be saved to the Browser blockstore.
- Publish the Plog head Cid to the DHT
- Dial the server node.
- how to know to assert and close the test?

## Run the test

```bash
just serve-interop
```

Then open the browser at `http://localhost:8080/`. 
