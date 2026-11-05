'use strict';
const fs = require('node:fs');
const {RE2} = require('../grpc_locality/node_modules/re2-wasm');
const cases = JSON.parse(fs.readFileSync(process.argv[2], 'utf8'));
function toJsReplacement(substitution) {
  let out = '';
  for (let i = 0; i < substitution.length; i++) {
    const byte = substitution[i];
    if (byte === '\\') {
      i++;
      if (i >= substitution.length) return null;
      const escaped = substitution[i];
      if (escaped === '0') out += '$&';
      else if (escaped >= '1' && escaped <= '9') out += '$' + escaped;
      else if (escaped === '\\') out += '\\';
      else out += ('\\' + escaped).replace(/\$/g, '$$$$');
    } else {
      out += byte === '$' ? '$$' : byte;
    }
  }
  return out;
}
const results = cases.map(value => {
  let pattern;
  try {
    if (value.substitution != null) {
      const replacement = toJsReplacement(value.substitution);
      if (replacement === null) return {err:'InvalidRegex', matches:[], replacements:[]};
      pattern = new RE2(value.pattern, 'ug');
      return {err:null, matches:[], replacements:value.inputs.map(text => pattern.replace(text, replacement))};
    }
    // RE2 full-match syntax, matching grpc-core StringMatcher::Match.
    pattern = new RE2(`^(?:${value.pattern})$`, 'u');
    return {err:null, matches:value.inputs.map(text => pattern.test(text)), replacements:[]};
  } catch(error) { return {err:'InvalidRegex', matches:[], replacements:[]}; }
  finally { pattern?.wrapper.delete(); }
});
console.log(JSON.stringify(results));
