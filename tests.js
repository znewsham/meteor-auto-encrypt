/* global describe, beforeEach, it */
import crypto from "crypto";
import chai from "chai";
import { MongoInternals } from "meteor/mongo";

import { EncryptedCollection, EncryptionSchema, patchCollection } from "./server.js";

const KeyVaultCollection = new Meteor.Collection("keyVault");

const masterKey = crypto.randomBytes(96);

const encOptions = {
  keyVaultNamespace: "meteor.keyVault",
  kmsProviders: {
    local: {
      key: masterKey
    }
  },
  masterKey,
  provider: "local",
  keyAltName: "everything",
  algorithm: "AEAD_AES_256_CBC_HMAC_SHA_512-Deterministic"
};


const collection = new EncryptedCollection("dummy", encOptions);

describe("EncryptionSchema", () => {
  it("should throw when encrypting at multiple layers", () => {
    chai.assert.throws(() => {
      new EncryptionSchema({
        object: true,
        "object.inner": true
      });
    });
  });
  it("should work for a flat schema", () => {
    const schema = new EncryptionSchema({
      "object.inner": true
    });

    chai.assert.isOk(schema.encryptionOptions("object.inner"));
  });

  it("should work for a nested schema", () => {
    const schema = new EncryptionSchema({
      object: {
        inner: true
      }
    });

    chai.assert.isOk(schema.encryptionOptions("object.inner"));
  });

  it("should work for an array schema", () => {
    const schema = new EncryptionSchema({
      array: {
        $: true
      }
    });

    chai.assert.isOk(schema.encryptionOptions("array.$"));
  });

  it("should work for an array and nested object schema", () => {
    const schema = new EncryptionSchema({
      array: {
        $: {
          inner: true
        }
      }
    });

    chai.assert.isOk(schema.encryptionOptions("array.inner"));
  });

  it("should return false for array", () => {
    const schema = new EncryptionSchema({
      array: {
        $: true
      }
    });

    chai.assert.isNotOk(schema.encryptionOptions("array"));
  });

  it("should return false for objects when nested", () => {
    const schema = new EncryptionSchema({
      object: {
        inner: true
      }
    });

    chai.assert.isNotOk(schema.encryptionOptions("object"));
  });

  it("should return false for objects when nested (wildcard)", () => {
    const schema = new EncryptionSchema({
      object: {
        "*": true
      }
    });

    chai.assert.isNotOk(schema.encryptionOptions("object"));
  });

  it("should work for wildcard objects", () => {
    const schema = new EncryptionSchema({
      object: {
        "*": true
      }
    });

    chai.assert.isOk(schema.encryptionOptions("object.inner"));
  });
});
describe("EncryptedCollection", () => {
  beforeEach(() => {
    EncryptedCollection.reset();
    KeyVaultCollection.remove({});
    collection.remove({});
  });

  describe("Update", () => {
    it("should allow setting simple fields", () => {
      collection.configureEncryption(encOptions, false);
      collection.configureEncryption({
        schema: {
          string: true
        }
      });

      const result = collection._encryptMutator({
        $set: {
          string: "hello"
        }
      });

      chai.assert.isOk(result.$set.string instanceof Buffer);
    });
    it("should allow setting simple fields", () => {
      collection.configureEncryption(encOptions, false);
      collection.configureEncryption({
        schema: {
          string: true
        }
      });

      const result = collection._encryptMutator({
        $inc: {
          string: 1
        }
      });

      chai.assert.equal(1, result.$inc.string);
    });

    it("should allow setting simple nested fields", () => {
      collection.configureEncryption(encOptions, false);
      collection.configureEncryption({
        schema: {
          "object.inner": true
        }
      });

      const result = collection._encryptMutator({
        $set: {
          "object.inner": "hello"
        }
      });

      chai.assert.isOk(result.$set["object.inner"] instanceof Buffer);
    });

    it("should allow setting simple nested fields(wildcard)", () => {
      collection.configureEncryption(encOptions, false);
      collection.configureEncryption({
        schema: {
          "object.*": true
        }
      });

      const result = collection._encryptMutator({
        $set: {
          "object.inner": "hello"
        }
      });

      chai.assert.isOk(result.$set["object.inner"] instanceof Buffer);
    });

    it("should allow setting simple entire objects", () => {
      collection.configureEncryption(encOptions, false);
      collection.configureEncryption({
        schema: {
          "object.inner": true
        }
      });

      const result = collection._encryptMutator({
        $set: {
          object: {
            inner: "hello"
          }
        }
      });

      chai.assert.isOk(result.$set.object.inner instanceof Buffer);
    });

    it("should allow setting simple entire objects(wildcard)", () => {
      collection.configureEncryption(encOptions, false);
      collection.configureEncryption({
        schema: {
          "object.*": true
        }
      });

      const result = collection._encryptMutator({
        $set: {
          object: {
            inner: "hello"
          }
        }
      });

      chai.assert.isOk(result.$set.object.inner instanceof Buffer);
    });

    it("should allow pushing to arrays", () => {
      collection.configureEncryption(encOptions, false);
      collection.configureEncryption({
        schema: {
          "array.$": true
        }
      });

      const result = collection._encryptMutator({
        $push: {
          array: "hello"
        }
      });

      chai.assert.isOk(result.$push.array instanceof Buffer);
    });

    it("should allow pushing $each to arrays", () => {
      collection.configureEncryption(encOptions, false);
      collection.configureEncryption({
        schema: {
          "array.$": true
        }
      });

      const result = collection._encryptMutator({
        $push: {
          array: {
            $each: ["hello"]
          }
        }
      });

      chai.assert.isOk(result.$push.array.$each[0] instanceof Buffer);
    });

    it("should allow addToSet to arrays", () => {
      collection.configureEncryption(encOptions, false);
      collection.configureEncryption({
        schema: {
          "array.$": true
        }
      });

      const result = collection._encryptMutator({
        $addToSet: {
          array: "hello"
        }
      });

      chai.assert.isOk(result.$addToSet.array instanceof Buffer);
    });

    it("should allow pushing $each to arrays", () => {
      collection.configureEncryption(encOptions, false);
      collection.configureEncryption({
        schema: {
          "array.$": true
        }
      });

      const result = collection._encryptMutator({
        $addToSet: {
          array: {
            $each: ["hello"]
          }
        }
      });

      chai.assert.isOk(result.$addToSet.array.$each[0] instanceof Buffer);
    });

    it("should allow setting arrays", () => {
      collection.configureEncryption(encOptions, false);
      collection.configureEncryption({
        schema: {
          "array.$": true
        }
      });

      const result = collection._encryptMutator({
        $set: {
          array: ["hello"]
        }
      });

      chai.assert.isOk(result.$set.array[0] instanceof Buffer);
    });
  });

  describe("Selector", () => {
    it("should Encrypt Simple fields", () => {
      collection.configureEncryption(encOptions, false);
      collection.configureEncryption({
        schema: {
          string: true
        }
      });
      const result = collection._encryptSelector({
        string: "hello"
      });
      chai.assert.isOk(result.string instanceof Buffer);
    });

    it("should Encrypt Array fields when querying over individual entries", () => {
      collection.configureEncryption(encOptions, false);
      collection.configureEncryption({
        schema: {
          "array.$": true
        }
      });
      const result = collection._encryptSelector({
        array: "hello"
      });
      chai.assert.isOk(result.array instanceof Buffer);
    });

    it("should Encrypt specific Array fields", () => {
      collection.configureEncryption(encOptions, false);
      collection.configureEncryption({
        schema: {
          "array.$": true
        }
      });
      const result = collection._encryptSelector({
        "array.0": "hello"
      });
      chai.assert.isOk(result["array.0"] instanceof Buffer);
    });

    it("should Encrypt Array fields when querying over entire array", () => {
      collection.configureEncryption(encOptions, false);
      collection.configureEncryption({
        schema: {
          "array.$": true
        }
      });
      const result = collection._encryptSelector({
        array: ["hello"]
      });
      chai.assert.equal(Array.isArray(result.array), true);
      chai.assert.isOk(result.array[0] instanceof Buffer);
    });

    it("should Encrypt Object fields", () => {
      collection.configureEncryption(encOptions, false);
      collection.configureEncryption({
        schema: {
          "object.inner": true
        }
      });
      const result = collection._encryptSelector({
        "object.inner": "hello"
      });
      chai.assert.isOk(result["object.inner"] instanceof Buffer);
    });

    it("should Encrypt Object fields(wildcard)", () => {
      collection.configureEncryption(encOptions, false);
      collection.configureEncryption({
        schema: {
          "object.*": true
        }
      });
      const result = collection._encryptSelector({
        "object.inner": "hello"
      });
      chai.assert.isOk(result["object.inner"] instanceof Buffer);
    });

    it("should Encrypt Object fields when querying entire object", () => {
      collection.configureEncryption(encOptions, false);
      collection.configureEncryption({
        schema: {
          "object.inner": true
        }
      });
      const result = collection._encryptSelector({
        object: {
          inner: "hello"
        }
      });
      chai.assert.equal(result.object instanceof Object, true);
      chai.assert.isOk(result.object.inner instanceof Buffer);
    });

    it("should Encrypt Object fields when querying entire object(wildcard)", () => {
      collection.configureEncryption(encOptions, false);
      collection.configureEncryption({
        schema: {
          "object.*": true
        }
      });
      const result = collection._encryptSelector({
        object: {
          inner: "hello"
        }
      });
      chai.assert.equal(result.object instanceof Object, true);
      chai.assert.isOk(result.object.inner instanceof Buffer);
    });

    it("should Encrypt $in", () => {
      collection.configureEncryption(encOptions, false);
      collection.configureEncryption({
        schema: {
          string: true
        }
      });
      const result = collection._encryptSelector({
        string: { $in: ["hello"] }
      });
      chai.assert.equal(Array.isArray(result.string.$in), true);
      chai.assert.isOk(result.string.$in[0] instanceof Buffer);
    });

    it("should Encrypt $eq", () => {
      collection.configureEncryption(encOptions, false);
      collection.configureEncryption({
        schema: {
          string: true
        }
      });
      const result = collection._encryptSelector({
        string: { $eq: "hello" }
      });
      chai.assert.isOk(result.string.$eq instanceof Buffer);
    });

    it("should Encrypt $not$eq", () => {
      collection.configureEncryption(encOptions, false);
      collection.configureEncryption({
        schema: {
          string: true
        }
      });
      const result = collection._encryptSelector({
        string: { $not: { $eq: "hello" } }
      });
      chai.assert.isOk(result.string.$not.$eq instanceof Buffer);
    });

    it("should Encrypt $not$in", () => {
      collection.configureEncryption(encOptions, false);
      collection.configureEncryption({
        schema: {
          string: true
        }
      });
      const result = collection._encryptSelector({
        string: { $not: { $in: ["hello"] } }
      });
      chai.assert.equal(Array.isArray(result.string.$not.$in), true);
      chai.assert.isOk(result.string.$not.$in[0] instanceof Buffer);
    });

    it("should Encrypt $nin", () => {
      collection.configureEncryption(encOptions, false);
      collection.configureEncryption({
        schema: {
          string: true
        }
      });
      const result = collection._encryptSelector({
        string: { $nin: ["hello"] }
      });
      chai.assert.equal(Array.isArray(result.string.$nin), true);
      chai.assert.isOk(result.string.$nin[0] instanceof Buffer);
    });

    it("should Encrypt $or", () => {
      collection.configureEncryption(encOptions, false);
      collection.configureEncryption({
        schema: {
          string: true
        }
      });
      const result = collection._encryptSelector({
        $or: [{ string: "hello" }, { string: "goodbye" }]
      });
      chai.assert.equal(Array.isArray(result.$or), true);
      chai.assert.isOk(result.$or[0].string instanceof Buffer);
      chai.assert.isOk(result.$or[1].string instanceof Buffer);
    });

    it("should Encrypt $and", () => {
      collection.configureEncryption(encOptions, false);
      collection.configureEncryption({
        schema: {
          string: true
        }
      });
      const result = collection._encryptSelector({
        $and: [{ string: "hello" }, { string: "goodbye" }]
      });
      chai.assert.equal(Array.isArray(result.$and), true);
      chai.assert.isOk(result.$and[0].string instanceof Buffer);
      chai.assert.isOk(result.$and[1].string instanceof Buffer);
    });

    it("should Encrypt $and$not$in", () => {
      collection.configureEncryption(encOptions, false);
      collection.configureEncryption({
        schema: {
          string: true
        }
      });
      const result = collection._encryptSelector({
        $and: [{ string: { $not: { $in: ["hello"] } } }]
      });
      chai.assert.isOk(result.$and[0].string.$not.$in[0] instanceof Buffer);
    });

    it("should Encrypt $exists", () => {
      collection.configureEncryption(encOptions, false);
      collection.configureEncryption({
        schema: {
          string: true
        }
      });
      const result = collection._encryptSelector({
        string: { $exists: true }
      });
      chai.assert.equal(result.string.$exists, true);
    });

    it("should Encrypt $size", () => {
      collection.configureEncryption(encOptions, false);
      collection.configureEncryption({
        schema: {
          "array.$": true
        }
      });
      const result = collection._encryptSelector({
        array: { $size: 3 }
      });
      chai.assert.equal(result.array.$size, 3);
    });

    it("should Encrypt entire array of objects", () => {
      collection.configureEncryption(encOptions, false);
      collection.configureEncryption({
        schema: {
          "array.$.inner": true
        }
      });

      const result = collection._encryptSelector({
        array: [{ inner: "hello" }]
      });
      chai.assert.equal(Array.isArray(result.array), true);
      chai.assert.equal(result.array[0] instanceof Buffer, false);
      chai.assert.isOk(result.array[0].inner instanceof Buffer);
    });

    it("should Encrypt array of object keys", () => {
      collection.configureEncryption(encOptions, false);
      collection.configureEncryption({
        schema: {
          "array.$.inner": true
        }
      });

      const result = collection._encryptSelector({
        "array.inner": "hello"
      });
      chai.assert.isOk(result["array.inner"] instanceof Buffer);
    });
          collection.configureEncryption(encOptions, false);
  });

  describe("Insert", () => {
    it("should Encrypt Simple fields", () => {
      collection.configureEncryption(encOptions, false);
      collection.configureEncryption({
        schema: {
          string: true
        }
      });
      const result = collection._encryptInsert({
        string: "hello"
      });
      chai.assert.isOk(result.string instanceof Buffer);
    });

    it("should Encrypt Full Arrays", () => {
      collection.configureEncryption({ ...encOptions, algorithm: "AEAD_AES_256_CBC_HMAC_SHA_512-Random" }, false);
      collection.configureEncryption({
        schema: {
          array: true
        }
      });

      const result = collection._encryptInsert({
        array: [1, 2, 3]
      });
      chai.assert.isOk(result.array instanceof Buffer);
    });

    it("should Encrypt Elements Of Array", () => {
      collection.configureEncryption(encOptions, false);
      collection.configureEncryption({
        schema: {
          "array.$": true
        }
      });

      const result = collection._encryptInsert({
        array: [1, 2, 3]
      });
      chai.assert.lengthOf(result.array, 3);
      result.array.forEach((res) => {
        chai.assert.isOk(res instanceof Buffer);
      });
    });

    it("should Encrypt object sub-keys", () => {
      collection.configureEncryption(encOptions, false);
      collection.configureEncryption({
        schema: {
          "object.inner": true
        }
      });

      const result = collection._encryptInsert({
        object: {
          inner: "hello"
        }
      });
      chai.assert.equal(result.object instanceof Object, true);
      chai.assert.isOk(result.object.inner instanceof Buffer);
    });

    it("should Encrypt entire objects", () => {
      collection.configureEncryption({ ...encOptions, algorithm: "AEAD_AES_256_CBC_HMAC_SHA_512-Random" }, false);
      collection.configureEncryption({
        schema: {
          object: true
        }
      });

      const result = collection._encryptInsert({
        object: {
          inner: "hello"
        }
      });
      chai.assert.isOk(result.object instanceof Buffer);
    });

    it("should Encrypt all sub-keys of object", () => {
      collection.configureEncryption(encOptions, false);
      collection.configureEncryption({
        schema: {
          "object.*": true
        }
      });

      const result = collection._encryptInsert({
        object: {
          inner: "hello",
          inner2: "goodbye"
        }
      });
      chai.assert.equal(result.object instanceof Object, true);
      chai.assert.isOk(result.object.inner instanceof Buffer);
      chai.assert.isOk(result.object.inner2 instanceof Buffer);
    });

    it("should Encrypt array sub-keys of object", () => {
      collection.configureEncryption(encOptions, false);
      collection.configureEncryption({
        schema: {
          "object.inner.$": true
        }
      });

      const result = collection._encryptInsert({
        object: {
          inner: [1, 2, 3]
        }
      });
      chai.assert.equal(result.object instanceof Object, true);
      chai.assert.equal(Array.isArray(result.object.inner), true);

      result.object.inner.forEach(res => chai.assert.isOk(res instanceof Buffer));
    });

    it("should Encrypt object subkeys of arrays", () => {
      collection.configureEncryption(encOptions, false);
      collection.configureEncryption({
        schema: {
          "array.$.inner": true
        }
      });

      const result = collection._encryptInsert({
        array: [{ inner: "hello" }]
      });
      chai.assert.equal(Array.isArray(result.array), true);
      chai.assert.equal(result.array[0] instanceof Buffer, false);
      chai.assert.isOk(result.array[0].inner instanceof Buffer);
    });

    it("should Encrypt object subkeys of arrays (wildcard)", () => {
      collection.configureEncryption(encOptions, false);
      collection.configureEncryption({
        schema: {
          "array.$.*": true
        }
      });

      const result = collection._encryptInsert({
        array: [{ inner: "hello" }]
      });
      chai.assert.equal(Array.isArray(result.array), true);
      chai.assert.equal(result.array[0] instanceof Buffer, false);
      chai.assert.isOk(result.array[0].inner instanceof Buffer);
    });
  });

  describe("find", () => {
    const docsAndSchemas = [
      {
        name: "array", doc: { _id: "1", array: [1, 2, 3] }, schema: { "array.$": true }, queries: [{ array: 1 }, { array: [1, 2, 3] }]
      },
      {
        name: "string", doc: { _id: "2", string: "hello" }, schema: { string: true }, queries: [{ string: "hello" }, { string: { $in: ["hello"] } }]
      },
      {
        name: "object", doc: { _id: "3", object: { inner: "hello" } }, schema: { "object.inner": true }, queries: [{ "object.inner": "hello" }, { object: { inner: "hello" } }]
      },
      {
        name: "object(wildcard)", doc: { _id: "4", object: { inner: "hello" } }, schema: { "object.*": true }, queries: [{ "object.inner": "hello" }, { object: { inner: "hello" } }]
      },
      {
        name: "object array", doc: { _id: "5", object: { array: [1, 2, 3] } }, schema: { "object.array.$": true }, queries: [{ "object.array": [1, 2, 3] }, { object: { array: [1, 2, 3] } }, { "object.array": 1 }]
      },
      {
        name: "array object", doc: { _id: "6", array: [{ inner: "hello" }] }, schema: { "array.$.inner": true }, queries: [{ array: [{ inner: "hello" }] }, { "array.inner": "hello" }, { array: { inner: "hello" } }]
      },
      {
        name: "array object(wildcard)", doc: { _id: "7", array: [{ inner: "hello" }] }, schema: { "array.$.*": true }, queries: [{ array: [{ inner: "hello" }] }, { "array.inner": "hello" }, { array: { inner: "hello" } }]
      }
    ];

    [true, false]
    .forEach((quick) => {
      [{ fnType: "raw", fn: options => options }, { fnType: "a fn", fn: options => (() => options) }]
      .forEach(({ fnType, fn }) => {
        docsAndSchemas.forEach(({
          doc, schema, name, queries
        }) => {
          describe(name, () => {
            beforeEach(() => {
              collection.configureEncryption(encOptions, false);
              collection.configureEncryption(fn({ schema, algorithm: "AEAD_AES_256_CBC_HMAC_SHA_512-Deterministic" }));
              collection.insert(doc);
            });
            it(`should decrypt a ${name} correctly when options provided by ${fnType}`, () => {
              const result = collection.findOne({ _id: doc._id }, { fastAutoEncryption: quick });
              chai.assert.deepEqual(result, doc);
            });
            if (queries) {
              queries.forEach((query) => {
                it(`should findOne a ${name} with ${JSON.stringify(query)}`, () => {
                  const result = collection.findOne(query, { fastAutoEncryption: quick });
                  chai.assert.deepEqual(result, doc);
                });
                it(`should find.fetch a ${name} with ${JSON.stringify(query)}`, () => {
                  const result = collection.find(query, { fastAutoEncryption: quick }).fetch();
                  chai.assert.deepEqual(result, [doc]);
                });
                it(`should find.map a ${name} with ${JSON.stringify(query)}`, () => {
                  let called = 0;
                  const result = collection.find(query, { fastAutoEncryption: quick }).map((a) => {
                    chai.assert.deepEqual(a, doc);
                    called++;
                    return a;
                  });
                  chai.assert.deepEqual(result, [doc]);
                  chai.assert.equal(called, 1);
                });
                it(`should find.forEach a ${name} with ${JSON.stringify(query)}`, () => {
                  let called = 0;
                  collection.find(query, { fastAutoEncryption: quick }).forEach((a) => {
                    chai.assert.deepEqual(a, doc);
                    called++;
                  });
                  chai.assert.equal(called, 1);
                });
              });
            }
          });
        });
      });
    });
  });
  describe("Per field options", () => {
    beforeEach(() => {
      collection.configureEncryption(encOptions, false);
    });
    describe("functions should be called with the correct arguments", () => {
      it("should call function on findOne correctly", () => {
        let called = 0;
        const _selector = { field: 1 };
        const _options = { b: 1 };
        collection.configureEncryption({
          schema: {
            field(methodName, {
              document, selector, mutator, options
            }) {
              called++;
              chai.assert.equal(methodName, "findOne");
              chai.assert.equal(selector, _selector);
              chai.assert.equal(options, _options);
              chai.assert.notOk(document);
              chai.assert.notOk(mutator);
            }
          }
        });
        collection.findOne(_selector, _options);
        chai.assert.equal(1, called);
      });

      it("should call function on remove correctly", () => {
        let called = 0;
        const _selector = { field: 1 };
        const _options = { b: 1 };
        collection.configureEncryption({
          schema: {
            field(methodName, {
              document, selector, mutator, options
            }) {
              called++;
              chai.assert.equal(methodName, "remove");
              chai.assert.equal(selector, _selector);
              chai.assert.equal(options, _options);
              chai.assert.notOk(document);
              chai.assert.notOk(mutator);
            }
          }
        });
        collection.remove(_selector, _options);
        chai.assert.equal(1, called);
      });

      it("should call function on find correctly", () => {
        let called = 0;
        const _selector = { field: 1 };
        const _options = { b: 1 };
        collection.configureEncryption({
          schema: {
            field(methodName, {
              document, selector, mutator, options
            }) {
              called++;
              chai.assert.equal(methodName, "find");
              chai.assert.equal(selector, _selector);
              chai.assert.equal(options, _options);
              chai.assert.notOk(document);
              chai.assert.notOk(mutator);
            }
          }
        });
        collection.find(_selector, _options);
        chai.assert.equal(1, called);
      });

      it("should call function on insert correctly", () => {
        let called = 0;
        const _document = { field: 1 };
        const _options = { b: 1 };
        collection.configureEncryption({
          schema: {
            field(methodName, {
              document, selector, mutator, options
            }) {
              called++;
              chai.assert.equal(methodName, "insert");
              chai.assert.notOk(selector);
              chai.assert.equal(options, _options);
              chai.assert.equal(document, _document);
              chai.assert.notOk(mutator);
            }
          }
        });
        collection.insert(_document, _options);
        chai.assert.equal(1, called);
      });

      it("should call function on update correctly", () => {
        let called = 0;
        const _selector = { field: 1 };
        const _mutator = { $set: { field: 1 } };
        const _options = { b: 1 };
        collection.configureEncryption({
          schema: {
            field(methodName, {
              document, selector, mutator, options
            }) {
              called++;
              chai.assert.equal(methodName, "update");
              chai.assert.equal(selector, _selector);
              chai.assert.equal(options, _options);
              chai.assert.notOk(document);
              chai.assert.equal(mutator, _mutator);
            }
          }
        });
        collection.update(_selector, _mutator, _options);

        // once for the selector, once for the mutator
        chai.assert.equal(2, called);
      });

      it("should call function on fetch correctly", () => {
        let called = 0;
        const _selector = { };
        const _options = { b: 1 };
        collection.configureEncryption({
          schema: {
            field(methodName, {
              document, selector, mutator, options
            }) {
              if (methodName === "insert") {
                return true;
              }
              called++;
              chai.assert.equal(methodName, "fetch");
              chai.assert.equal(selector, _selector);
              chai.assert.equal(options, _options);
              chai.assert.ok(document?.field);
              chai.assert.notOk(mutator);
              return true;
            }
          }
        });
        collection.insert({
          field: 1
        });
        collection.find(_selector, _options).fetch();

        // once for the selector, once for the mutator
        chai.assert.equal(1, called);
      });

      it("should call function on map correctly", () => {
        let called = 0;
        const _selector = { };
        const _options = { b: 1 };
        collection.configureEncryption({
          schema: {
            field(methodName, {
              document, selector, mutator, options
            }) {
              if (methodName === "insert") {
                return true;
              }
              called++;
              chai.assert.equal(methodName, "map");
              chai.assert.equal(selector, _selector);
              chai.assert.equal(options, _options);
              chai.assert.ok(document?.field);
              chai.assert.notOk(mutator);
              return true;
            }
          }
        });
        collection.insert({
          field: 1
        });
        collection.find(_selector, _options).map(a => a);

        // once for the selector, once for the mutator
        chai.assert.equal(1, called);
      });

      it("should call function on forEach correctly", () => {
        let called = 0;
        const _selector = { };
        const _options = { b: 1 };
        collection.configureEncryption({
          schema: {
            field(methodName, {
              document, selector, mutator, options
            }) {
              if (methodName === "insert") {
                return true;
              }
              called++;
              chai.assert.equal(methodName, "forEach");
              chai.assert.equal(selector, _selector);
              chai.assert.equal(options, _options);
              chai.assert.ok(document?.field);
              chai.assert.notOk(mutator);
              return true;
            }
          }
        });
        collection.insert({
          field: 1
        });
        collection.find(_selector, _options).forEach(a => a);

        // once for the selector, once for the mutator
        chai.assert.equal(1, called);
      });
    });
  });

  describe("Flex", () => {
    const masterKey1 = crypto.randomBytes(96);
    const masterKey2 = crypto.randomBytes(96);
    const configs = {
      account1: {
        kmsProviders: {
          local: {
            key: masterKey1
          }
        },
        keyAltName: "everything1",
        __keys: [masterKey1, masterKey2],
        masterKey: masterKey1,
        fields: {
          field1: true,
          field2: true
        }
      },
      account2: {
        kmsProviders: {
          local: {
            key: masterKey2
          }
        },
        __keys: [masterKey1, masterKey2],
        masterKey: masterKey2,
        keyAltName: "everything2",
        fields: {
          field3: true,
          field4: true
        }
      }
    };
    beforeEach(() => {
      collection.configureEncryption(encOptions, false);
      collection.configureEncryption((methodName, { document, selector }) => {
        const { accountId } = document || selector;
        const config = configs[accountId];
        if (!config) {
          return undefined;
        }
        const ret = {};
        Object.keys(config.fields).forEach((field) => {
          ret[`flex.${field}.value`] = () => config;
          ret[`flex.${field}.searchableValue.$`] = () => config;
        });
        return {
          schema: ret
        };
      });
    });

    it("should encrypt field1 and field2 but not field3 or field4 when using account1", () => {
      const doc = {
        _id: "1",
        accountId: "account1",
        flex: {
          field1: {
            value: "Hello World",
            searchableValue: ["hello world", "hello", "world"]
          },
          field2: {
            value: "Hello World",
            searchableValue: ["hello world", "hello", "world"]
          },
          field3: {
            value: "Hello World",
            searchableValue: ["hello world", "hello", "world"]
          },
          field4: {
            value: "Hello World",
            searchableValue: ["hello world", "hello", "world"]
          }
        }
      };
      collection.insert(doc);
      const found = Promise.await(collection.rawCollection().findOne({ _id: doc._id }));

      // NOTE: because we're directly accessing the DB the type will be Binary, not Buffer
      chai.assert.ok(found.flex.field1.value instanceof MongoInternals.NpmModule.Binary);
      chai.assert.ok(found.flex.field1.searchableValue[0] instanceof MongoInternals.NpmModule.Binary);
      chai.assert.ok(found.flex.field2.value instanceof MongoInternals.NpmModule.Binary);
      chai.assert.ok(found.flex.field2.searchableValue[0] instanceof MongoInternals.NpmModule.Binary);
      chai.assert.typeOf(found.flex.field3.value, "string");
      chai.assert.typeOf(found.flex.field3.searchableValue[0], "string");
      chai.assert.typeOf(found.flex.field4.value, "string");
      chai.assert.typeOf(found.flex.field4.searchableValue[0], "string");
    });

    it("should encrypt field3 and field4 but not field1 or field2 when using account2", () => {
      const doc = {
        _id: "1",
        accountId: "account2",
        flex: {
          field1: {
            value: "Hello World",
            searchableValue: ["hello world", "hello", "world"]
          },
          field2: {
            value: "Hello World",
            searchableValue: ["hello world", "hello", "world"]
          },
          field3: {
            value: "Hello World",
            searchableValue: ["hello world", "hello", "world"]
          },
          field4: {
            value: "Hello World",
            searchableValue: ["hello world", "hello", "world"]
          }
        }
      };
      collection.insert(doc);
      const found = Promise.await(collection.rawCollection().findOne({ _id: doc._id }));

      // NOTE: because we're directly accessing the DB the type will be Binary, not Buffer
      chai.assert.ok(found.flex.field3.value instanceof MongoInternals.NpmModule.Binary);
      chai.assert.ok(found.flex.field3.searchableValue[0] instanceof MongoInternals.NpmModule.Binary);
      chai.assert.ok(found.flex.field4.value instanceof MongoInternals.NpmModule.Binary);
      chai.assert.ok(found.flex.field4.searchableValue[0] instanceof MongoInternals.NpmModule.Binary);
      chai.assert.typeOf(found.flex.field1.value, "string");
      chai.assert.typeOf(found.flex.field1.searchableValue[0], "string");
      chai.assert.typeOf(found.flex.field2.value, "string");
      chai.assert.typeOf(found.flex.field2.searchableValue[0], "string");
    });

    it("should decrypt all fields when finding without a selector", () => {
      const doc1 = {
        _id: "1",
        accountId: "account1",
        flex: {
          field1: {
            value: "Hello World",
            searchableValue: ["hello world", "hello", "world"]
          },
          field2: {
            value: "Hello World",
            searchableValue: ["hello world", "hello", "world"]
          },
          field3: {
            value: "Hello World",
            searchableValue: ["hello world", "hello", "world"]
          },
          field4: {
            value: "Hello World",
            searchableValue: ["hello world", "hello", "world"]
          }
        }
      };
      const doc2 = {
        _id: "2",
        accountId: "account2",
        flex: {
          field1: {
            value: "Hello World",
            searchableValue: ["hello world", "hello", "world"]
          },
          field2: {
            value: "Hello World",
            searchableValue: ["hello world", "hello", "world"]
          },
          field3: {
            value: "Hello World",
            searchableValue: ["hello world", "hello", "world"]
          },
          field4: {
            value: "Hello World",
            searchableValue: ["hello world", "hello", "world"]
          }
        }
      };
      collection.insert(doc1);
      collection.insert(doc2);

      const [found1, found2] = collection.find({}, { sort: { _id: 1 } }).fetch();

      // NOTE: because we're directly accessing the DB the type will be Binary, not Buffer
      chai.assert.typeOf(found1.flex.field1.value, "string");
      chai.assert.typeOf(found1.flex.field1.searchableValue[0], "string");
      chai.assert.typeOf(found1.flex.field2.value, "string");
      chai.assert.typeOf(found1.flex.field2.searchableValue[0], "string");
      chai.assert.typeOf(found1.flex.field3.value, "string");
      chai.assert.typeOf(found1.flex.field3.searchableValue[0], "string");
      chai.assert.typeOf(found1.flex.field4.value, "string");
      chai.assert.typeOf(found1.flex.field4.searchableValue[0], "string");

      // NOTE: because we're directly accessing the DB the type will be Binary, not Buffer
      chai.assert.typeOf(found2.flex.field3.value, "string");
      chai.assert.typeOf(found2.flex.field3.searchableValue[0], "string");
      chai.assert.typeOf(found2.flex.field4.value, "string");
      chai.assert.typeOf(found2.flex.field4.searchableValue[0], "string");
      chai.assert.typeOf(found2.flex.field1.value, "string");
      chai.assert.typeOf(found2.flex.field1.searchableValue[0], "string");
      chai.assert.typeOf(found2.flex.field2.value, "string");
      chai.assert.typeOf(found2.flex.field2.searchableValue[0], "string");
    });
  });

  describe("Unencrypted", () => {
    // these tests ensure coverage of branches for un-initiated collections

    beforeEach(() => {
      collection.configureEncryption(encOptions, false);
      collection.insert({ _id: "1" });
    });

    it("Should remove", () => {
      collection.remove({ _id: "1" });
      chai.assert.equal(0, collection.find().count());
    });

    it("Should insert", () => {
      collection.insert({ _id: "2" });
      chai.assert.equal(2, collection.find().count());
    });

    it("Should update", () => {
      collection.update({ _id: "1" }, { $set: { value: "hello" } });
      chai.assert.equal("hello", collection.findOne().value);
    });

    it("Should findOne", () => {
      const res = collection.findOne({ _id: "1" });
      chai.assert.equal(res._id, "1");
    });

    it("Should findOne (string)", () => {
      const res = collection.findOne("1");
      chai.assert.equal(res._id, "1");
    });

    it("Should find (string)", () => {
      const res = collection.find("1").fetch()[0];
      chai.assert.equal(res._id, "1");
    });

    it("Should find.fetch", () => {
      const res = collection.find({ _id: "1" }).fetch();
      chai.assert.equal(res[0]._id, "1");
    });

    it("Should find.map", () => {
      const res = collection.find({ _id: "1" }).map(a => a);
      chai.assert.equal(res[0]._id, "1");
    });

    it("Should find.forEach", () => {
      collection.find({ _id: "1" }).forEach(a => chai.assert.equal(a._id, "1"));
    });
  });

  describe("Maybe Unencrypted", () => {
    // these tests ensure coverage of branches for un-initiated collections

    beforeEach(() => {
      collection.configureEncryption(encOptions, false);
      collection.configureEncryption((method) => {
        if (!["fetch", "forEach", "map", "result"].includes(method)) {
          return {
            schema: {}
          };
        }
      });
      collection.insert({ _id: "1" });
    });

    it("Should remove", () => {
      collection.remove({ _id: "1" });
      chai.assert.equal(0, collection.find().count());
    });

    it("Should insert", () => {
      collection.insert({ _id: "2" });
      chai.assert.equal(2, collection.find().count());
    });

    it("Should update", () => {
      collection.update({ _id: "1" }, { $set: { value: "hello" } });
      chai.assert.equal("hello", collection.findOne().value);
    });

    it("Should findOne", () => {
      const res = collection.findOne({ _id: "1" });
      chai.assert.equal(res._id, "1");
    });

    it("Should findOne (string)", () => {
      const res = collection.findOne("1");
      chai.assert.equal(res._id, "1");
    });

    it("Should find (string)", () => {
      const res = collection.find("1").fetch()[0];
      chai.assert.equal(res._id, "1");
    });

    it("Should find.fetch", () => {
      const res = collection.find({ _id: "1" }).fetch();
      chai.assert.equal(res[0]._id, "1");
    });

    it("Should find.map", () => {
      const res = collection.find({ _id: "1" }).map(a => a);
      chai.assert.equal(res[0]._id, "1");
    });

    it("Should find.forEach", () => {
      collection.find({ _id: "1" }).forEach(a => chai.assert.equal(a._id, "1"));
    });
  });

  describe("After Encryption", () => {
    it("Should allow fetching an un-encrypted simple value when encryption is added", () => {
      collection.configureEncryption(encOptions, false);
      collection.insert({
        _id: "1",
        withoutEncryption: "Hello World"
      });

      const doc = collection.findOne({ _id: "1" });
      chai.assert.equal(doc.withoutEncryption, "Hello World");

      collection.configureEncryption({ safe: true, schema: { withoutEncryption: true } });

      const doc1 = collection.findOne({ _id: "1" });
      chai.assert.equal(doc1.withoutEncryption, "Hello World");

      const missing = collection.findOne({ withoutEncryption: "Hello World" });
      chai.assert.notOk(missing);
      collection.update({ _id: "1" }, { $set: { withoutEncryption: "Hello World" } });

      const doc3 = collection.findOne({ withoutEncryption: "Hello World" });
      chai.assert.equal(doc3.withoutEncryption, "Hello World");
    });
  });

  describe("Patch collection", () => {
    it("Should patch a collection", () => {
      patchCollection(collection, encOptions);
    });
  });

  describe("Transform", () => {
    class Thing {}
    const collection2 = new EncryptedCollection("test", { ...encOptions, transform: doc => new Thing(doc) });

    beforeEach(() => {
      collection2.remove({});
      collection2.configureEncryption({ schema: { field: true } });
      collection2.insert({ _id: "1", field: "test" });
    });

    it("findOne should transform", () => {
      chai.assert.ok(collection2.findOne() instanceof Thing);
    });

    it("find.fetch should transform", () => {
      chai.assert.ok(collection2.find().fetch()[0] instanceof Thing);
    });

    it("find.map should transform", () => {
      chai.assert.ok(collection2.find().map(a => a)[0] instanceof Thing);
    });

    it("find.forEach should transform", () => {
      collection2.find().forEach((aThing) => {
        chai.assert.ok(aThing instanceof Thing);
      });
    });
  });

  describe("Advanced cases", () => {
    it("Should update positional", () => {
      collection.configureEncryption(encOptions, false);
      collection.configureEncryption({
        schema: {
          "array.$.inner": true
        }
      });
      collection.insert({ _id: "1", array: [{ inner: 1 }, { inner: 2 }] });

      collection.update({ "array.inner": 2 }, { $set: { "array.$.inner": 3 } });

      const result = collection.findOne();

      chai.assert.equal(result.array[0].inner, 1);
      chai.assert.equal(result.array[1].inner, 3);
    });
  });
});
