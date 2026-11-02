'use strict';
const assert = require('node:assert/strict');
const path = require('node:path');
const {spawn} = require('node:child_process');
const grpc = require('../grpc_locality/node_modules/@grpc/grpc-js');
const registry = require('../grpc_locality/node_modules/@grpc/grpc-js/build/src/load-balancer');
const {XDS_CONFIG_KEY, XDS_CLIENT_KEY} = require('../grpc_locality/node_modules/@grpc/grpc-js-xds/build/src/resolver-xds');
require('../grpc_locality/node_modules/@grpc/grpc-js-xds/build/src/load-balancer-xds-cluster-impl').setup();
let picker;
class Config {
  getLoadBalancerName() { return 'netz_drop_child'; }
  toJsonObject() { return {netz_drop_child:{}}; }
  static createFromJson() { return new Config(); }
}
class Child {
  constructor(helper) { this.helper = helper; }
  updateAddressList() { this.helper.updateState(grpc.connectivityState.READY, {pick:()=>({pickResultType:0,status:null,subchannel:null,onCallStarted:null,onCallEnded:null})}, null); return true; }
  exitIdle() {} resetBackoff() {} destroy() {}
}
registry.registerLoadBalancerType('netz_drop_child', Child, Config);
const config=registry.parseLoadBalancingConfig({xds_cluster_impl:{cluster:'oracle',child_policy:[{netz_drop_child:{}}]}});
const noop=()=>{};
const oracle=registry.createLoadBalancer(config,{createSubchannel:noop,updateState:(_s,p)=>picker=p,requestReresolution:noop,addChannelzChild:noop,removeChannelzChild:noop});
const dropCategories=[{category:'zero',requests_per_million:0},{category:'first',requests_per_million:200000},{category:'second',requests_per_million:500000}];
assert(oracle.updateAddressList({ok:true,value:[]},config,{[XDS_CONFIG_KEY]:{clusters:new Map([['oracle',{ok:true,value:{cluster:{},children:{type:'eds',endpoints:{dropCategories}}}}]])},[XDS_CLIENT_KEY]:{}},''));
const savedRandom=Math.random;
const oracleResults=[];
try {
  for(const values of [[0,0.199999],[0,0.2,0.499999],[0,0.2,0.5]]) {
    let index=0;Math.random=()=>values[index++];const result=picker.pick({});oracleResults.push({type:result.pickResultType,details:result.status?.details??'',samples:index});
  }
} finally {Math.random=savedRandom;oracle.destroy();}
assert.equal(oracleResults[0].type,3);assert(oracleResults[0].details.endsWith('first'));assert.equal(oracleResults[0].samples,2);
assert.equal(oracleResults[1].type,3);assert(oracleResults[1].details.endsWith('second'));assert.equal(oracleResults[2].type,0);
const loader=require('../grpc_locality/node_modules/@grpc/proto-loader');
const protobuf=require('../grpc_locality/node_modules/protobufjs');
const deps=path.resolve(__dirname,'../grpc_locality/node_modules/@grpc/grpc-js-xds/deps');
const includes=['envoy-api','xds','googleapis','protoc-gen-validate'].map(x=>path.join(deps,x));
const def=loader.loadSync('envoy/service/discovery/v3/ads.proto',{includeDirs:includes,keepCase:true,defaults:true,longs:String,enums:String});
const adsService=grpc.loadPackageDefinition(def).envoy.service.discovery.v3.AggregatedDiscoveryService.service;
const root=new protobuf.Root();root.resolvePath=(_o,t)=>{for(const dir of includes){const file=path.join(dir,t);if(require('node:fs').existsSync(file))return file;}return t;};root.loadSync('envoy/config/endpoint/v3/endpoint.proto',{keepCase:true});root.resolveAll();
const assignmentType=root.lookupType('envoy.config.endpoint.v3.ClusterLoadAssignment');
const typeUrl='type.googleapis.com/envoy.config.endpoint.v3.ClusterLoadAssignment';
function execute(binary,args){return new Promise((resolve,reject)=>{const child=spawn(binary,args);let output='';const timer=setTimeout(()=>{child.kill();reject(new Error('drop client timeout'));},30000);child.stdout.on('data',b=>output+=b);child.stderr.on('data',b=>output+=b);child.on('error',e=>{clearTimeout(timer);reject(e);});child.on('exit',code=>{clearTimeout(timer);if(code!==0)return reject(new Error(output));const line=output.split('\n').find(x=>x.startsWith('DROP_RESULT '));if(!line)return reject(new Error(output));resolve(JSON.parse(line.slice(12)));});});}
async function run(binary,mode){
  const app=new grpc.Server();const control=new grpc.Server();let calls=0;const sessions=new Set();let step=0;
  const method={path:'/fixture.Drop/Unary',requestStream:false,responseStream:false,requestSerialize:x=>x,requestDeserialize:x=>x,responseSerialize:x=>x,responseDeserialize:x=>x};
  app.addService({Unary:method},{Unary(call,cb){assert.equal(call.request.toString(),'request');calls++;sessions.add(call.call.stream.session);cb(null,Buffer.from('reply'));}});
  const appPort=await new Promise((resolve,reject)=>app.bindAsync('127.0.0.1:0',grpc.ServerCredentials.createInsecure(),(e,p)=>e?reject(e):resolve(p)));
  control.addService(adsService,{StreamAggregatedResources(call){call.on('error',noop);const send=(version,numerator,empty=false)=>{const value={cluster_name:'backend',endpoints:empty?[]:[{locality:{region:'local'},load_balancing_weight:{value:1},lb_endpoints:[{endpoint:{address:{socket_address:{address:'127.0.0.1',port_value:appPort}}},health_status:1}]}],policy:{drop_overloads:numerator===0?[]:[{category:'control-plane',drop_percentage:{numerator,denominator:2}}]}};call.write({type_url:typeUrl,version_info:version,nonce:version+'-nonce',resources:[{type_url:typeUrl,value:assignmentType.encode(assignmentType.create(value)).finish()}]});};call.on('data',r=>{
    if(step===0){assert.equal(r.node.id,'netz-eds-drop');send('half',500000);}
    else if(step===1){assert.equal(r.version_info,'half');}
    else if(step===2){assert(r.resource_names.includes('all'));send('all',1000000);}
    else if(step===3){assert.equal(r.version_info,'all');}
    else if(step===4){assert(r.resource_names.includes('off'));send('off',0);}
    else if(step===5){assert.equal(r.version_info,'off');}
    else if(step===6){assert(r.resource_names.includes('empty'));send('empty',1000000,true);}
    else if(step===7){assert.equal(r.version_info,'empty');call.end();}
    else assert.fail('extra ADS message');step++;
  });}});
  const controlPort=await new Promise((resolve,reject)=>control.bindAsync('127.0.0.1:0',grpc.ServerCredentials.createInsecure(),(e,p)=>e?reject(e):resolve(p)));
  try{const result=await execute(binary,[mode,String(appPort),String(controlPort)]);assert.equal(calls,result.accepted);assert.equal(sessions.size,1);if(mode==='shared')assert.equal(step,8);return{...result,wire_calls:calls,sessions:sessions.size,ads_requests:step};}
  finally{app.forceShutdown();control.forceShutdown();}
}
(async()=>{const results=[];for(const mode of ['ordinary','shared'])results.push(await run(process.argv[2],mode));console.log(JSON.stringify({status:'passed',oracle:oracleResults,grpc_js:require('../grpc_locality/node_modules/@grpc/grpc-js/package.json').version,results}));})().catch(e=>{console.error(e);process.exitCode=1;});
