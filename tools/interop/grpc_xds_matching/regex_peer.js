'use strict';
const fs = require('node:fs');
const {RE2} = require('../grpc_locality/node_modules/re2-wasm');
const cases = JSON.parse(fs.readFileSync(process.argv[2], 'utf8'));
const results = cases.map(value => {
  let pattern;
  try {
    // RE2 full-match syntax, matching grpc-core StringMatcher::Match.
    pattern = new RE2(`^(?:${value.pattern})$`, 'u');
    return {err:null, matches:value.inputs.map(text => pattern.test(text))};
  } catch(error) { return {err:'InvalidRegex', matches:[]}; }
  finally { pattern?.wrapper.delete(); }
});
console.log(JSON.stringify(results));
