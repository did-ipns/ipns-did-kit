# IPNS DID Kit

The IPNS DID Kit is a JavaScript library designed to facilitate the creation, management, and utilization of decentralized identities (DIDs) based on IPNS (InterPlanetary Name System). This library enables users to create and maintain DIDs that are compatible with IPFS (InterPlanetary File System) pinning platforms and supports DNSLink, enhancing web compatibility and DNS-based resolution.

## Features

- **DID Creation and Management:** Generate and manage DID documents with support for multiple cryptographic proof methods, including `secp256k1`.
- **Persistence on IPNS and IPFS:** Persist DID documents on IPNS and IPFS to ensure decentralized and reliable storage.
- **Compatibility with DNSLink:** Integrate with DNSLink to facilitate DNS-based resolution of DIDs, linking DIDs with human-readable domain names.
- **Audit and Version Control:** Track changes and revisions to DID documents, providing a method for auditing document history.
- **Dynamic Service Endpoint Management:** Modify and manage service endpoints associated with a DID, allowing the DID to interact with various decentralized services.
- **Cryptographic Functionality:** Generate random keys, sign messages, verify signatures, and more, all using built-in cryptographic functions.

## Installation

To install the library, you can use npm:

```bash
npm install @did-ipns/kit
```

## Usage

### Initialization

```javascript
import IpnsDidKit from 'path-to-IpnsDidKit';

const ipnsDidKit = new IpnsDidKit(yourHeliaConfig);
```

### Creating a New DID Document

```javascript
const privateKey = ipnsDidKit.generateRandomKey();
const didDocument = ipnsDidKit.create('your-unique-id', privateKey);
```

### Signing and Verifying Messages

```javascript
const signature = ipnsDidKit.sign('your-did-id', privateKey, 'message-to-sign');
const isValid = ipnsDidKit.verifySignature('your-did-id', publicKey, signature, 'message-to-sign');
```

### Managing Service Endpoints

```javascript
didDocument = ipnsDidKit.modifyServiceEndpoint(didDocument, 'serviceId', 'type', 'newEndpoint');
```

## Contributing

Contributions are welcome! Please fork the repository and submit pull requests with your enhancements.

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## More Information

For more details on IPNS, IPFS, and DIDs, please refer to their respective official documentation. This will help you understand the broader context in which this library operates.

This README provides a basic overview of the library's capabilities and usage. For more advanced features and detailed documentation, please refer to the source code or further documentation provided with the library.# ipns-did-kit
