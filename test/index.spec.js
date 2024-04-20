import { test } from "node:test";
import assert from "node:assert/strict";
import IpnsDidKit from "../src/index.js";
import { createHeliaHTTP } from "@helia/http";
import { trustlessGateway } from "@helia/block-brokers";
import { delegatedHTTPRouting } from "@helia/routers";

const helia = await createHeliaHTTP({
  blockBrokers: [
    trustlessGateway({
      gateways: ["http://127.0.0.1:8080"],
    }),
  ],
  routers: [delegatedHTTPRouting("http://127.0.0.1:8080/routing/v1")],
});
const ipnsDidKit = new IpnsDidKit(helia);

const TEST_CID = process.env.TEST_NAME_CID || "QmTESTa321";
const TEST_DID = `did:ipns:${TEST_CID}`;
const TEST_MESSAGE_TO_SIGN = `Mr. Watson, Come Here, I Want You!`;

test("generate random key", () => {
  const randomKey = ipnsDidKit.generateRandomKey();
  assert.strictEqual(randomKey.length, 64);
});

test("create document", () => {
  const privateKey = ipnsDidKit.generateRandomKey();
  const document = ipnsDidKit.create(TEST_CID, privateKey);
  assert.strictEqual(document.id, TEST_DID);
});

test("present document", async () => {
  const privateKey = ipnsDidKit.generateRandomKey();
  const document = ipnsDidKit.create(TEST_CID, privateKey);
  const generatedPresentation = await ipnsDidKit.present(document.id);
  assert.strictEqual(typeof generatedPresentation, "string");
});

test("generate challenge", () => {
  const challenge = ipnsDidKit.generateChallenge();
  assert.strictEqual(challenge.length, 64);
});

test("sign message", () => {
  const privateKey = ipnsDidKit.generateRandomKey();
  const document = ipnsDidKit.create(TEST_CID, privateKey);
  const signedMessage = ipnsDidKit.sign(
    document.id,
    privateKey,
    TEST_MESSAGE_TO_SIGN,
  );
  assert.strictEqual(typeof signedMessage.r, "object");
});

test("verify signature", () => {
  const privateKey = ipnsDidKit.generateRandomKey();
  const document = ipnsDidKit.create(TEST_CID, privateKey);
  const signature = ipnsDidKit.sign(
    document.id,
    privateKey,
    TEST_MESSAGE_TO_SIGN,
  );
  const verifiedMessage = ipnsDidKit.verifySignature(
    document.id,
    document.verificationMethod[0].publicKeyJwk,
    signature,
    TEST_MESSAGE_TO_SIGN,
  );
  assert.strictEqual(verifiedMessage, true);
});

test("fail verifying signature", () => {
  const privateKey = ipnsDidKit.generateRandomKey();
  const document = ipnsDidKit.create(TEST_CID, privateKey);
  const signature = ipnsDidKit.sign(
    document.id,
    privateKey,
    TEST_MESSAGE_TO_SIGN,
  );
  const verifiedMessage = ipnsDidKit.verifySignature(
    document.id,
    document.verificationMethod[0].publicKeyJwk,
    signature,
    TEST_MESSAGE_TO_SIGN + "JUNK_DATA",
  );
  assert.strictEqual(verifiedMessage, false);
});

test("rotate key", () => {
  const privateKey = ipnsDidKit.generateRandomKey();
  const document = ipnsDidKit.create(TEST_CID, privateKey);
  const newKey = ipnsDidKit.generateRandomKey();
  const updatedDocument = ipnsDidKit.rotate(document, "1", newKey);
  assert.strictEqual(updatedDocument.id, TEST_DID);
});

test("modify service endpoint", () => {
  const privateKey = ipnsDidKit.generateRandomKey();
  const document = ipnsDidKit.create(TEST_CID, privateKey);
  const documentWithServiceEndpoint = ipnsDidKit.modifyServiceEndpoint(
    document,
    "stor-acme",
    "pinning_provider",
    "api.stor-acme.service",
  );
  assert.strictEqual(documentWithServiceEndpoint.service.length, 1);
});

test("remove service endpoint", () => {
  const privateKey = ipnsDidKit.generateRandomKey();
  const document = ipnsDidKit.create(TEST_CID, privateKey);
  const documentWithServiceEndpoint = ipnsDidKit.modifyServiceEndpoint(
    document,
    "stor-acme",
    "pinning_provider",
    "api.stor-acme.service",
  );
  const documentWithServiceEndpointRemoved = ipnsDidKit.removeServiceEndpoint(
    documentWithServiceEndpoint,
    "stor-acme",
  );
  assert.strictEqual(documentWithServiceEndpointRemoved.service.length, 0);
});

test("forward did", () => {
  const privateKey = ipnsDidKit.generateRandomKey();
  const document = ipnsDidKit.create(TEST_CID, privateKey);
  const destination = "did:ipns:forwarded-provider.local";
  const forwardedDocument = ipnsDidKit.forward(document, destination);
  assert.strictEqual(forwardedDocument.forward, destination);
});

test("deactivate did", () => {
  const privateKey = ipnsDidKit.generateRandomKey();
  const document = ipnsDidKit.create(TEST_CID, privateKey);
  const deactivatedDocument = ipnsDidKit.deactivate(document);
  assert.equal(typeof deactivatedDocument.deactivated, "string");
});
