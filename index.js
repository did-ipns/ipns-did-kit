import { keyBy } from "lodash";
import { DIDDocument } from "did-doc";
import { Resolver } from "did-resolver";
import { getResolver } from "ipns-did-resolver";
import elliptic from "elliptic";
import QRCode from "qrcode";
import { createHash } from "crypto";
import crypto from "node:crypto";

export default class IpnsDidKit {
  #resolver;
  #provider;
  #ec = new elliptic.ec("secp256k1");
  #defaultVerificationKey = "main";

  constructor(helia, provider = undefined) {
    const ipnsResolver = getResolver(helia);
    this.#resolver = new Resolver({
      ...ipnsResolver,
    });
    this.#provider = provider;
  }

  generateRandomKey(byteSize = 32, encoding = "hex") {
    return crypto.randomBytes(size).toString(encoding);
  }

  create(id, prv = null, previous = null, contents = undefined) {
    const document = new DIDDocument(`did:ipns:${id}`, contents);
    if (typeof contents === "undefined") {
      document.created = new Date().toISOString().slice(0, 19) + "Z";
    }
    document.updated = document.created;
    if (prv !== null) {
      const key = this.#ec.keyFromPrivate(prv, "hex");
      const pub = key.getPublic();
      const defaultVerificationId = `did:ipns:${id}#${this.#defaultVerificationKey}`;
      document.addVerificationMethod({
        id: defaultVerificationId,
        type: "JsonWebKey2020",
        controller: `did:ipns:${id}`,
        publicKeyJwk: {
          kty: "EC",
          crv: "secp256k1",
          x: pub.x.toBuffer().toString("hex"),
          y: pub.y.toBuffer().toString("hex"),
        },
      });
      document.addToSet("authentication", defaultVerificationId);
      document.addToSet("assertionMethod", defaultVerificationId);
    }
    if (previous) {
      document.previous = previous;
    }
    return document;
  }

  present(id) {
    return QRCode.toDataURL(id);
  }

  generateChallenge() {
    return this.generateRandomKey();
  }

  sign(id, prv, message) {
    const key = this.#ec.keyFromPrivate(prv, "hex"),
      messageHash = createHash("sha256").update(message).digest("hex");
    return key.sign(messageHash);
  }

  verifySignature(id, pub, signature, message) {
    const key = this.#ec.keyFromPublic(pub, "hex"),
      messageHash = createHash("sha256").update(message).digest("hex");
    return key.verify(messageHash, signature);
  }

  resolve(id) {
    return this.#resolver.resolve(id);
  }

  async audit(document, versionId, revisions = {}) {
    revisions[document.updated] = versionId;
    if (document.previous) {
      const resolvedDocument = await this.#resolver.resolve(document);
      return this.audit(
        resolvedDocument.document,
        resolvedDocument.versionId,
        revisions,
      );
    }
    return revisions;
  }

  rotate(document, versionId, key) {
    let verificationMethods = keyBy(document.verificationMethod, "id");
    verificationMethods[`${document.id}#${this.#defaultVerificationKey}`] =
      undefined;
    document.verificationMethod = Object.values(verificationMethods);
    return this.create(document.id, key, versionId, document);
  }

  modifyServiceEndpoint(document, serviceId, type, serviceEndpoint) {
    let serviceEndpoints = keyBy(document.service, "id");
    serviceEndpoints[serviceId] = { id: serviceId, type, serviceEndpoint };
    document.service = Object.values(serviceEndpoints);
    return document;
  }

  removeServiceEndpoint(document, serviceId) {
    let serviceEndpoints = keyBy(document.service, "id");
    delete serviceEndpoints[serviceId];
    document.service = Object.values(serviceEndpoints);
    return document;
  }

  forward(id, document, destinationId) {
    document.forward = destinationId;
    return document;
  }

  deactivate(id, document, timestamp = Date.now()) {
    document.deactivated = timestamp;
    return document;
  }

  parseDocument(id, contents) {
    return new DIDDocument(`did:ipns:${id}`, contents);
  }
}
