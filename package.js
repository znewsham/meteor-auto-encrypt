Package.describe({
  name: "znewsham:auto-encrypt",
  version: "0.0.4",
  // Brief, one-line summary of the package.
  summary: "Provides a MongoDB like auto-encrypt feature for self-hosted clusters"
});

Npm.depends({
  "mongodb-client-encryption": "1.1.0",
  mongodb: "3.5.9",
  // chai: "4.2.0", // - enable for testing
  // "babel-plugin-istanbul": "5.2.0" // - enable for testing
});

Package.onUse((api) => {
  api.versionsFrom(["METEOR@1.10"]);
  api.use(["ecmascript", "mongo", "ejson"]);
  api.mainModule("server.js", "server");
  api.mainModule("client.js", "client");
});


Package.onTest((api) => {
  api.use(["lmieulet:meteor-legacy-coverage@0.1.0", "lmieulet:meteor-coverage@3.0.0", "lmieulet:meteor-packages-coverage@0.2.0", "ecmascript", "meteortesting:mocha", "mongo", "ejson", "znewsham:auto-encrypt"]);
  api.mainModule("tests.js", "server");
});