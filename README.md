# Auto Client-side Field Level Encryption

Provides similar behaviour to https://docs.mongodb.com/manual/core/security-automatic-client-side-encryption/ but for self-hosted community versioned clusters. Additionally, supports querying over encrypted arrays.

## Basic Usage
To allow for support with `aldeed:collection2` and schemas in general, we have to monkey-patch `Mongo.Collection`'s `insert`, `update`, `remove`, `find` and `findOne` methods. As such, all collections will have the ability to have encrypted fields. However, to support both encrypted fields and schema validation, `znewsham:auto-encrypt` must be listed before `aldeed:collection2` in `.meteor/packages`.

If you are defining a new collection, using the `EncryptedCollection` is the easiest way to go. Passing in the encryption options to the collection. as the second parameter:
```js
import { EncryptedCollection } from "meteor/znewsham:auto-encrypt";
import crypto from "crypto";

const masterKey = crypto.randomBytes(96);

const encOptions = {
  keyVaultNamespace: "meteor.keyVault", // you are responsible for ensuring a unique key on this collection on keyAltName
  // not suitable for production - use aws
  kmsProviders: {
    local: {
      key: masterKey
    }
  },
  masterKey,
  provider: "local",
  keyAltName: "myKeyName", // creation of this key is automatic - though you can use an existing one as well
  algorithm: "AEAD_AES_256_CBC_HMAC_SHA_512-Deterministic",
  schema: {
    field: true,
    "object.inner": true,
    "array.$": true,
    "anotherArray.$.inner": true,
    "wild.*": true,
    anotherObject: {
      inner: true,
      another: true
    }
  }
};

const collection = new EncryptedCollection("myCollection", encOptions);
```

If you're adding encryption to an existing collection that cannot extend from `EncryptedCollection` you can do:

```js
Meteor.users.configureEncryption(encOptions);
```

At this point all supported operations over `field`, `object.inner`, `array.$` or `anotherArray.$.inner` will be encrypted - this includes find, update, remove, insert.

```js
collection.insert({
  field: "Encrypted",
  object: {
    inner: "Encrypted",
    another: "Not Encrypted"
  },
  array: ["Encrypted"],
  anotherArray: [{
    inner: "Encrypted",
    another: "Not Encrypted"
  }],
  wild: {
    inner: "Encrypted",
    another: "Encrypted"
  }
});
```

## Advanced Usage
You may want to apply different encryption over different fields - consider:
```js
const collection = new EncryptedCollection("myCollection", encOptions);
collection.configureEncryption({
  schema:
  {
    field: true, // we want this to be deterministic (as specified by default)
    array: true // we need this to be random (as required by mongo)
  }
});

collection.insert({
  field: "Encrypted",
  array: ["Will Throw Error"]
})
```

In the current situation, mongo will throw an error when trying to encrypt `array` as it is using the `AEAD_AES_256_CBC_HMAC_SHA_512-Deterministic` algorithm. Instead:
```js
const collection = new EncryptedCollection("myCollection", encOptions);
collection.configureEncryption({
  schema: {
    field: true, // we want this to be deterministic (as specified by default)
    array() { // we need this to be random (as required by mongo)
      return {
        algorithm: "AEAD_AES_256_CBC_HMAC_SHA_512-Random";
      }
    }
  }
});

collection.insert({
  field: "Encrypted",
  array: ["Entire array will be encrypted"]
})
```

You can override any of the default options on a per-field basis, `algorithm` is the most common though.

### Multi-Tenant Systems
Consider a multi-tenant system, where you want to use a different `keyAltName` (or potentially a different `masterKey`) for each tenancy:

```js
collection.configureEncryption((methodName, { selector, document }) => {
  let { tenancyId } = document || selector;
  return {
    keyAltName: tenancyId,
    masterKey: getMasterKeyForTenancy(tenancyId), // determine this however you want
    local: getLocalForTenancy(tenancyId) // determine this however you want,
    schema: {
      field: true,
      ...
    }
  };
});
```

`configureEncryption` can take either an object, or a function that returns an object. In the case of a function, it will be called every time you issue `insert`, `update`, `remove` or `find` commands AND once per document returned by `fetch`, `map`, `forEach` or `findOne`. As such - caching of the result of this function is vital. Similarly, each field defined by the schema should either be a boolean - or a function that returns either a boolean, or an object of options to override - you CANNOT specify the override options directly on the key.

This is particularly useful when using AWS, when the credentials required for each tenancy's `masterKey` may be different.

Let's take this example on step further - not only is the system multi-tenant, but it allows for flexible (but known) schemas on a per-tenancy basis. Not only are the global options different, but the available fields, whether to encrypt them (and how to do it) and the structure of the fields all depend on the tenancy:

```js
// a basic example - doesn't consider all combinations of options.
collection.configureEncryption((methodName, { selector, document }) => {
  let { tenancyId } = document || selector;
  const fields = getFieldsForTenancy(tenancyId);
  const schema = {};
  fields.forEach(({ fieldName, encryptionAlgorithm, isArray, internalKeys }) => {
    if (!encryptionAlgorithm) {
      return;
    }
    if (isArray) {
      schema[`${fieldName}.$`] = () => ({ algorithm: encryptionAlgorithm});
    }
    else if (internalKeys) {
      internalKeys.forEach((internalKey) => {
        schema[`${fieldName}.${internalKey}`] = () => ({ algorithm: encryptionAlgorithm});
      });
    }
  });
  return {
    keyAltName: tenancyId,
    masterKey: getMasterKeyForTenancy(tenancyId), // determine this however you want
    local: getLocalForTenancy(tenancyId) // determine this however you want,
    schema
  };
});
```

## Supported Operations

Currently only `update`, `insert`, `remove`, `find` (`fetch`, `forEach` and `map`) and `findOne` are supported - future support is planned for `aggregate` and `distinct`.

## Supported Operators

There are limitations as specified in https://docs.mongodb.com/manual/reference/security-client-side-query-aggregation-support/ that apply at the database level (e.g., are not related to Mongo's own AutoEncrypt behaviour). These limits (e.g., only supporting random encryption over whole objects and arrays) cannot be avoided. As such, this document assumes that you are adhering to these limitations.


### Selector

Relevant to `find` and the selector argument of `update` and `remove`.

Just like the mongo supported AutoEncrypt feature, this package supports `$eq`, `$ne`, `$in`, `$nin`, `$and`, `$or`, `$nor`, `$not` operators with encryption. The `$size` and `$exists` operators are passed through un-modified.

In addition to this - this package also supports querying over encrypted elements of arrays, `$size` only makes sense in this context and is passed through un-encrypted. However, the following also works:

```js
collection.configureEncryption({ schema: { "array.$": true } });

collection.find({ array: "value" }) // "value" will be encrypted

collection.find({ array: ["value1", "value2"] }) //value1 and value2 will be encrypted.
```

### Update

This package supports the `$set`, `$unset`, `$push`, `$addToSet` and `$each` operators of the mutator argument to update - obviously `$push`, `$addToSet` and `$each` only work when using encryption at the per-entry level of an array field, additionally `$addToSet` will only work "correctly" when using deterministic encryption:

```js
collection.configureEncryption({ schema: { "array.$": true } });

collection.update({}, { $push: { array: "value" } }) // value will be encrypted and added to array.

collection.update({}, { $addToSet: { array: { $each: ["value1", "value2"] } } }) // value1 and value2 will be encrypted and added to array, if their encrypted values do NOT already exist.

```

## Performance
EncryptedCollection uses a cache for both instances of `ClientEncryption`, and references of `keyAltName`. The former is unique per configuration options (e.g., master key, etc) AND by it's external connection (e.g., the actual connection to the database). `keyAltName` are cached - just so we don't always need to ensure they exist, the first DB operation will be slower as it fetches from `keyVaultNamespace`.

In the case that your configuration is a static object, containing static field definitions, the performance should be similar to that of the native driver. It will scale according to the number of encrypted fields you have, and the number of fields in each operation (keys in selector, document or mutator). For each of these keys the lookup time is `O(n)` per depth of field, e.g., `a.b.c ~ O(3)` `a ~ O(1)`.

If you use functions for either the overall, or per-field settings, these functions will be called once per `remove` and `insert`, twice for `update`, and once per document + once globally for `find`/`findOne`. This is because for each document it is possible there will be different settings. However, if you know that all documents for a specific query will always use the same settings (e.g., your settings depend on `tenancyId` and your query will include `tenancyId`), you can pass in `{ fastAutoEncryption: true }` as the third parameter to `find`/`findOne` and it will skip the per-document lookup.

## Migrating un-encrypted collections
Obviously, if you have an existing application with un-encrypted data that you'll want to add encryption to, you need a way of reading the unencrypted data then writing back encrypted data:

```js
collection.configureEncryption({
  schema: {
    aPreviouslyUnencryptedField: true
  },
  safe: true // don't error out if trying to decrypt a field and it isn't encrypted.
});

collection.find().forEach((doc) => {
  collection.update({ _id: doc._id }, { $set: { aPreviouslyUnencryptedField: doc.aPreviouslyUnencryptedField } });
});
```

After running this all document's `aPreviouslyUnencryptedField` will now be encrypted.
