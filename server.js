import { ClientEncryption } from "mongodb-client-encryption";
import { EJSON } from "meteor/ejson";
import { MongoInternals } from "meteor/mongo";

function flatten(obj, prefix, ret = {}) {
  Object.keys(obj).forEach((key) => {
    if (typeof obj[key] === "object") {
      flatten(obj[key], prefix ? `${prefix}.${key}` : key, ret);
    }
    else {
      ret[prefix ? `${prefix}.${key}` : key] = obj[key];
    }
  });
  return ret;
}

function __decryptConversionFunction(encryptionClient, options, value) {
  if (!(value instanceof Uint8Array) && options.safe) {
    return value;
  }
  return EncryptedCollection.decryptValue(
    encryptionClient,
    // this is more back and forth than I'd like, but meteor swaps binaries for UINT8Array - and Mongo REALLY wants a binary+buffer
    new MongoInternals.NpmModule.Binary(Buffer.from(value))
  );
}

function __encryptConversionFunction(encryptionClient, entryEncryptionOptions, value) {
  return EncryptedCollection.encryptValue(encryptionClient, entryEncryptionOptions, value).buffer;
}

const passthroughOperators = new Set(["$exists", "$size"]);
const supportedOperators = new Set(["$in", "$not", "$nin", "$eq", "$ne", "$nor", "$and", "$or", "$exists", "$each", "$size"]);
const arrayOperators = new Set(["$and", "$or", "$nor"]);

// even though $in and $nin and $each take arrays they aren't really "array" operators
const nestedOperators = new Set(["$in", "$nin", "$not", "$each", "$eq"]);

const allowedOptions = ["keyVaultNamespace", "kmsProviders", "masterKey", "keyAltName", "algorithm", "provider", "safe"];

const encryptionClientsByMongoClient = new Map();

const dataKeysByEncryptionClient = new Map();

const origFunctions = {
  findOne: Meteor.Collection.prototype.findOne,
  find: Meteor.Collection.prototype.find,
  insert: Meteor.Collection.prototype.insert,
  update: Meteor.Collection.prototype.update,
  remove: Meteor.Collection.prototype.remove
};

function newFunction({
  conversionFn,
  currentObj,
  currentSchema,
  originalMethodName,
  originalMethodArgs,
  encryptionOptions,
  isSelectorOrMutator = false,
  actualKey // we pass this in with operators, so we know what we're operating over
}) {
  if (!currentSchema) {
    return currentObj;
  }
  const ret = Array.isArray(currentObj) ? [] : {};
  Array.from(currentObj.entries ? currentObj.entries() : Object.entries(currentObj))
  .forEach(([key, value]) => {
    if (passthroughOperators.has(key)) {
      ret[key] = value;
    }
    else if (typeof value === "object" && supportedOperators.has(key)) {
      if (arrayOperators.has(key)) {
        ret[key] = value.map(v => newFunction({
          conversionFn,
          currentObj: v,
          currentSchema,
          originalMethodName,
          originalMethodArgs,
          isSelectorOrMutator,
          encryptionOptions,
          actualKey
        }));
      }
      if (nestedOperators.has(key)) {
        ret[key] = newFunction({
          conversionFn,
          currentObj: value,
          currentSchema,
          originalMethodName,
          originalMethodArgs,
          isSelectorOrMutator,
          encryptionOptions,
          actualKey
        });
      }
    }
    else if (typeof value === "object" && !Array.isArray(value) && Object.keys(value).find(k => supportedOperators.has(k))) {
      ret[key] = newFunction({
        conversionFn,
        currentObj: value,
        currentSchema,
        originalMethodName,
        originalMethodArgs,
        isSelectorOrMutator,
        encryptionOptions,
        actualKey: key
      });
    }
    else {
      let entryEncryptionOptions = currentSchema.encryptionOptions(actualKey || (Number.isInteger(key) ? "$" : key), originalMethodName, originalMethodArgs);

      // we're in a selector/mutator so { array: value } should encrypt value, even though array does not have an encryption entry
      if (!entryEncryptionOptions && isSelectorOrMutator && !Array.isArray(value)) {
        const subSchema = currentSchema.get(actualKey || (Number.isInteger(key) ? "$" : key));
        entryEncryptionOptions = (subSchema instanceof EncryptionSchema) && subSchema.encryptionOptions("$", originalMethodName, originalMethodArgs);
      }
      if (entryEncryptionOptions) {
        const mergedOptions = { ...encryptionOptions };
        Object.assign(mergedOptions, entryEncryptionOptions || {});
        const encryptionClient = EncryptedCollection.ensureEncryptionClient(mergedOptions);
        ret[key] = conversionFn(encryptionClient, mergedOptions, value);
      }
      else if (typeof value === "object") {
        ret[key] = newFunction({
          conversionFn,
          currentSchema: currentSchema.get(actualKey || (Number.isInteger(key) ? "$" : key)),
          currentObj: value,
          originalMethodName,
          encryptionOptions,
          originalMethodArgs,
          isSelectorOrMutator
        });
      }
      else {
        ret[key] = value;
      }
    }
  });

  return ret;
}


/** @this EncryptedCollection */
function wrapCursor(cursor, rootEncryptionOptions, originalMethodArgs) {
  const origFetch = cursor.fetch;
  const origForEach = cursor.forEach;
  const origMap = cursor.map;
  const quickEncrypt = originalMethodArgs?.options?.fastAutoEncryption;

  cursor.fetch = (...args) => {
    const results = origFetch.call(cursor, ...args);
    return results.map((doc) => {
      const encryptionOptions = quickEncrypt ? rootEncryptionOptions : this.encryptionOptions("fetch", { document: doc, ...originalMethodArgs });
      if (!encryptionOptions?.schema) {
        return doc;
      }
      return newFunction({
        conversionFn: __decryptConversionFunction,
        currentObj: doc,
        currentSchema: encryptionOptions.schema,
        originalMethodArgs: { document: doc, ...originalMethodArgs },
        originalMethodName: "fetch",
        encryptionOptions
      });
    });
  };

  cursor.forEach = (fn) => {
    origForEach.call(cursor, (doc, ...args) => {
      const encryptionOptions = quickEncrypt ? rootEncryptionOptions : this.encryptionOptions("forEach", { document: doc, ...originalMethodArgs });
      if (!encryptionOptions?.schema) {
        return doc;
      }
      const decrypted = newFunction({
        conversionFn: __decryptConversionFunction,
        currentObj: doc,
        currentSchema: encryptionOptions.schema,
        originalMethodArgs: { document: doc, ...originalMethodArgs },
        originalMethodName: "forEach",
        encryptionOptions
      });
      fn(decrypted, ...args);
    });
  };

  cursor.map = fn => origMap.call(cursor, (doc, ...args) => {
    const encryptionOptions = quickEncrypt ? rootEncryptionOptions : this.encryptionOptions("map", { document: doc, ...originalMethodArgs });
    if (!encryptionOptions?.schema) {
      return doc;
    }
    const decrypted = newFunction({
      conversionFn: __decryptConversionFunction,
      currentObj: doc,
      currentSchema: encryptionOptions.schema,
      originalMethodArgs: { document: doc, ...originalMethodArgs },
      originalMethodName: "map",
      encryptionOptions
    });
    return fn(decrypted, ...args);
  });
}

export class EncryptionSchema {
  constructor(schema, parent) {
    this._parent = parent;
    schema = flatten(schema);
    this._map = new Map();
    this._deepMap = new Map();
    this._isArray = false;
    const keys = Object.keys(schema);
    const addedKeys = [];
    keys.forEach((rawKey) => {
      const foundExisting = addedKeys.find(existing => existing.startsWith(`${rawKey}.`) || rawKey.startsWith(`${existing}.`));
      if (foundExisting) {
        throw new Meteor.Error("bad-schema", `You can't encrypt both ${foundExisting} and ${rawKey}`);
      }
      addedKeys.push(rawKey);
      this.addKey(rawKey, schema[rawKey]);
    });
  }

  addKey(str, value) {
    this._map.set(str, value);
    const parts = str.split(".");
    if (parts.length > 1) {
      const prefix = parts[0];
      if (!this._map.has(prefix)) {
        this._map.set(prefix, new EncryptionSchema({}, this));
      }
      this._map.get(prefix).addKey(parts.slice(1).join("."), value);
    }
    else {
      this._map.set(parts[0], value);
    }
  }

  encryptionOptions(str, ...args) {
    let ret = this.get(str);
    if (!ret && !["*", "$"].includes(str)) {
      ret = this.get("*"); // wildcard!
    }
    if (!ret && !["*", "$"].includes(str)) {
      ret = this.get("$");
    }
    if (!ret || ret instanceof EncryptionSchema) {
      return false;
    }
    return (typeof ret) === "function" ? ret(...args) : (ret === true ? {} : ret);
  }

  get(str) {
    let subSchema;

    // first check the shorthand - do we have this exact key?
    if (this._map.has(str)) {
      subSchema = this._map.get(str);
      return subSchema;
    }

    // we don't, is this field an array ($) or a wildcard (*)?
    subSchema = str !== "*" && this._map.get("$");
    if (subSchema) {
      if (subSchema instanceof EncryptionSchema) {
        return subSchema.get(str);
      }
      return subSchema;
    }
    subSchema = str !== "$" && this._map.get("*");
    if (subSchema) {
      return subSchema;
    }

    // we're not in an array or wildcard field, so we've got to traverse down from here using prefixes
    const parts = str.split(".");

    // if we're already at the lowest level, and haven't found a match - then there is no match.
    if (parts.length === 1) {
      return false;
    }
    subSchema = this._map.get(parts[0]);
    if (subSchema instanceof EncryptionSchema && parts.length > 1) {
      return subSchema.get(parts.slice(1).join("."));
    }
    return subSchema;
  }
}

export class EncryptedCollection extends Meteor.Collection {
  // used by testing
  static reset() {
    encryptionClientsByMongoClient.clear();
    dataKeysByEncryptionClient.clear();
  }

  static ensureEncryptionClient({
    mongoClient,
    kmsProviders,
    keyVaultNamespace
  }) {
    if (!encryptionClientsByMongoClient.has(mongoClient)) {
      encryptionClientsByMongoClient.set(mongoClient, new Map());
    }
    const hash = EJSON.stringify({ kmsProviders, keyVaultNamespace }, { canonical: true });
    const mongoClientEncryptionClients = encryptionClientsByMongoClient.get(mongoClient);
    if (!mongoClientEncryptionClients.has(hash)) {
      mongoClientEncryptionClients.set(hash, new ClientEncryption(mongoClient, { keyVaultNamespace, kmsProviders }));
    }
    return mongoClientEncryptionClients.get(hash);
  }

  static ensureDataKey(encryptionClient, { provider, masterKey, keyAltName }) {
    if (!dataKeysByEncryptionClient.has(encryptionClient)) {
      dataKeysByEncryptionClient.set(encryptionClient, new Map());
    }
    const clientDataKeys = dataKeysByEncryptionClient.get(encryptionClient);
    if (!clientDataKeys.has(keyAltName)) {
      const promise = encryptionClient._keyVaultClient
      .db(encryptionClient._keyVaultNamespace.split(".")[0])
      .collection(encryptionClient._keyVaultNamespace.split(".").slice(1).join("."))
      .find({}, { _id: 1, keyAltNames: 1, masterKey: 1 })
      .toArray();
      const existingKeys = Promise.await(promise);
      existingKeys.forEach(({ keyAltNames, _id }) => {
        keyAltNames.forEach((aKeyAltName) => {
          clientDataKeys.set(aKeyAltName, { masterKey, dataKeyId: _id });
        });
      });
      if (!clientDataKeys.has(keyAltName)) {
        const dataKeyId = Promise.await(encryptionClient.createDataKey(provider, { masterKey, keyAltNames: [keyAltName] }));
        clientDataKeys.set(keyAltName, { masterKey: { provider, ...masterKey }, dataKeyId });
      }
    }
  }

  static encryptValue(
    encryptionClient,
    {
      provider, masterKey, keyAltName, algorithm
    },
    value
  ) {
    EncryptedCollection.ensureDataKey(encryptionClient, { provider, masterKey, keyAltName });
    return Promise.await(encryptionClient.encrypt(value, { keyAltName, algorithm }));
  }

  static decryptValue(
    encryptionClient,
    buffer
  ) {
    return Promise.await(encryptionClient.decrypt(buffer));
  }

  constructor(name, options) {
    super(name, options);
    this.configureEncryption(options);
  }

  configureEncryption(optionsOrFn, extendOptions = true) {
    if (!this.__encryptionOptions || extendOptions === false) {
      extendOptions = false; // we're doing the initial setup
      this.__encryptionOptions = {
        mongoClient: this._driver.mongo.client
      };
      this._encryptionOptions = undefined;
    }

    // this is slightly weird, we want the behaviour of calling for the first time
    // to be that the package sets defaults that can later be overwritten by specifics
    // this will almost always be via a function
    if (!extendOptions && typeof optionsOrFn !== "function") {
      allowedOptions.forEach((option) => {
        if (optionsOrFn[option]) {
          this.__encryptionOptions[option] = optionsOrFn[option];
        }
      });
    }
    if (typeof optionsOrFn === "function") {
      this._encryptionOptions = (...args) => {
        const returnedConfig = optionsOrFn(...args) || {};
        const options = Object.assign({}, this.__encryptionOptions);
        allowedOptions.forEach((option) => {
          if (returnedConfig[option]) {
            options[option] = returnedConfig[option];
          }
        });
        if (returnedConfig?.schema) {
          options.schema = new EncryptionSchema(returnedConfig.schema);
        }
        return options;
      };
    }
    else {
      this._encryptionOptions = Object.assign(
        {},
        this.__encryptionOptions, {
          schema: optionsOrFn?.schema && new EncryptionSchema(optionsOrFn.schema)
        }
      );

      allowedOptions.forEach((option) => {
        if (optionsOrFn[option]) {
          this._encryptionOptions[option] = optionsOrFn[option];
        }
      });
    }
  }

  encryptionOptions(originalMethodName, originalMethodArgs) {
    return typeof this._encryptionOptions === "function" ? this._encryptionOptions(originalMethodName, originalMethodArgs) : this._encryptionOptions;
  }

  _encryptSelector(selector, originalMethodName, originalMethodArgs, encryptionOptions = this.encryptionOptions(originalMethodName, originalMethodArgs)) {
    if (!encryptionOptions || !encryptionOptions.schema) {
      return selector;
    }
    return newFunction({
      conversionFn: __encryptConversionFunction,
      currentObj: selector,
      currentSchema: encryptionOptions.schema,
      originalMethodArgs,
      originalMethodName,
      encryptionOptions,
      isSelectorOrMutator: true
    });
  }

  // the meteor mongo_driver does NOT like this to be setup for you - it wants you to give it a buffer and let it convert.
  // so everywhere we're doing encryptValue().buffer
  _encryptInsert(doc, originalMethodArgs, encryptionOptions = this.encryptionOptions("insert", originalMethodArgs)) {
    return newFunction({
      conversionFn: __encryptConversionFunction,
      currentObj: doc,
      currentSchema: encryptionOptions.schema,
      originalMethodArgs,
      originalMethodName: "insert",
      encryptionOptions
    });
  }

  _encryptMutator(mutator, originalMethodArgs, encryptionOptions = this.encryptionOptions("insert", originalMethodArgs)) {
    const encryptedMutator = {};
    Object.keys(mutator).forEach((key) => {
      if (key === "$set") {
        encryptedMutator[key] = newFunction({
          conversionFn: __encryptConversionFunction,
          currentObj: mutator[key],
          currentSchema: encryptionOptions.schema,
          originalMethodArgs,
          originalMethodName: "update",
          encryptionOptions,
          isSelectorOrMutator: true
        });
      }
      else if (["$push", "$addToSet", "$pull"].includes(key)) {
        encryptedMutator[key] = newFunction({
          conversionFn: __encryptConversionFunction,
          currentObj: mutator[key],
          currentSchema: encryptionOptions.schema,
          originalMethodArgs,
          originalMethodName: "update",
          encryptionOptions,
          isSelectorOrMutator: true
        });
      }
      else {
        encryptedMutator[key] = mutator[key];
      }
    });
    return encryptedMutator;
  }

  _find(...args) {
    // check for stupid lazy strings
    if (typeof args[0] === "string") {
      args[0] = { _id: args[0] };
    }
    const argsForFn = { selector: args[0], options: args[1] };
    const encryptionOptions = this.encryptionOptions?.("find", argsForFn);
    if (args[0] && encryptionOptions) {
      args[0] = args[0] && this._encryptSelector(args[0], "find", argsForFn, encryptionOptions);
    }
    const cursor = origFunctions.find.call(this, ...args);
    if (!encryptionOptions) {
      return cursor;
    }
    // we can't chcek for the existance of a schema here, because the schema may not be defined until after we get the document back
    wrapCursor.call(this, cursor, encryptionOptions, argsForFn);
    return cursor;
  }

  _findOne(...args) {
    // check for stupid lazy strings
    if (typeof args[0] === "string") {
      args[0] = { _id: args[0] };
    }
    const argsForFn = { selector: args[0], options: args[1] };
    let encryptionOptions = this.encryptionOptions?.("findOne", argsForFn);
    if (args[0] && encryptionOptions) {
      args[0] = args[0] && this._encryptSelector(args[0], "findOne", argsForFn, encryptionOptions);
    }
    const result = origFunctions.findOne.call(this, ...args);
    if (!result || !encryptionOptions) {
      return result;
    }

    encryptionOptions = this.encryptionOptions("result", { document: result, selector: args[0], options: args[1] });
    if (!encryptionOptions?.schema) {
      return result;
    }
    return newFunction({
      conversionFn: __decryptConversionFunction,
      currentObj: result,
      currentSchema: encryptionOptions.schema,
      originalMethodArgs: { document: result, selector: args[0], options: args[1] },
      originalMethodName: "findOne",
      encryptionOptions
    });
  }

  _remove(...args) {
    const argsForFn = { selector: args[0], options: args[1] };
    const encryptionOptions = this.encryptionOptions?.("findOne", argsForFn);
    if (args[0] && encryptionOptions?.schema) {
      args[0] = args[0] && this._encryptSelector(args[0], "remove", argsForFn, encryptionOptions);
    }
    return origFunctions.remove.call(this, ...args);
  }

  _insert(doc, ...args) {
    const argsForFn = { document: doc, options: args[0] };
    const encryptionOptions = this.encryptionOptions?.("insert", argsForFn);
    if (!encryptionOptions?.schema) {
      return origFunctions.insert.call(this, doc, ...args);
    }
    const toInsert = this._encryptInsert(doc, argsForFn, encryptionOptions);
    return origFunctions.insert.call(this, toInsert, ...args);
  }

  _update(selector, mutator, ...args) {
    const options = args[0] || {};
    const argsForFn = { selector, mutator, options: args[0] };
    const encryptionOptions = this.encryptionOptions?.("update", argsForFn);
    /* if (this._c2 && !options?.bypassCollection2 && doValidate) {
      doValidate(this, "update", [selector, mutator, ...args], true, Meteor.userId(), true);
    } */
    if (!encryptionOptions?.schema) {
      return origFunctions.update.call(this, selector, mutator, ...args);
    }
    const actualSelector = this._encryptSelector(selector, "update", argsForFn, encryptionOptions);
    const actualMutator = this._encryptMutator(mutator, argsForFn, encryptionOptions);
    return origFunctions.update.call(this, actualSelector, actualMutator, ...args /* { ...options, bypassCollection2: true } */);
  }
}


const funcitonsToPatch = ["configureEncryption", "encryptionOptions", "_encryptSelector", "_encryptMutator", "_encryptInsert"];
export function patchCollection(collection, initialOptions) {
  funcitonsToPatch.forEach((functionName) => {
    collection[functionName] = EncryptedCollection.prototype[functionName];
  });
  collection.configureEncryption(initialOptions, false);
}

Meteor.Collection.prototype.update = EncryptedCollection.prototype._update;
Meteor.Collection.prototype.insert = EncryptedCollection.prototype._insert;
Meteor.Collection.prototype.remove = EncryptedCollection.prototype._remove;
Meteor.Collection.prototype.find = EncryptedCollection.prototype._find;
Meteor.Collection.prototype.findOne = EncryptedCollection.prototype._findOne;
