'use strict';
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const {spawn} = require('node:child_process');
const grpc = require('../grpc_locality/node_modules/@grpc/grpc-js');
const loader = require('../grpc_locality/node_modules/@grpc/proto-loader');
const protobuf = require('../grpc_locality/node_modules/protobufjs');
require('../grpc_locality/node_modules/@grpc/grpc-js-xds').register();
const {RouteConfigurationResourceType} = require('../grpc_locality/node_modules/@grpc/grpc-js-xds/build/src/xds-resource-type/route-config-resource-type');
const deps=path.resolve(__dirname,'../grpc_locality/node_modules/@grpc/grpc-js-xds/deps');
const includes=['envoy-api','xds','googleapis','protoc-gen-validate'].map(x=>path.join(deps,x));
const definition=loader.loadSync('envoy/service/discovery/v3/ads.proto',{includeDirs:includes,keepCase:true,defaults:true,longs:String,enums:String});
const service=grpc.loadPackageDefinition(definition).envoy.service.discovery.v3.AggregatedDiscoveryService.service;
const root=new protobuf.Root();root.resolvePath=(_origin,target)=>includes.map(dir=>path.join(dir,target)).find(file=>fs.existsSync(file))??target;
root.loadSync('envoy/config/route/v3/route.proto',{keepCase:true});root.resolveAll();
const routeType=root.lookupType('envoy.config.route.v3.RouteConfiguration');
const typeUrl='type.googleapis.com/envoy.config.route.v3.RouteConfiguration';
const encode=value=>({type_url:typeUrl,value:Buffer.from(routeType.encode(routeType.create(value)).finish())});
const direct=(method,cluster,extra={})=>({match:{path:'/fixture.Rds/'+method},route:{cluster,...extra}});
function routes(after=false){
  if(after)return {name:'routes',virtual_hosts:[{name:'exact',domains:['backend.test'],routes:[{match:{prefix:'/fixture.Rds/'},route:{cluster:'b'}}]}]};
  return {name:'routes',virtual_hosts:[
    {name:'universe',domains:['*'],routes:[{match:{prefix:''},route:{cluster:'a'}}]},
    {name:'suffix',domains:['*.test'],routes:[{match:{prefix:''},route:{cluster:'a'}}]},
    {name:'exact',domains:['backend.test'],routes:[
      direct('Hold','a'),direct('Stream','b'),
      direct('Retry','b',{retry_policy:{retry_on:'unavailable',num_retries:{value:1},retry_back_off:{base_interval:{nanos:1000000},max_interval:{nanos:1000000}}}}),
      direct('Slow','b',{max_stream_duration:{max_stream_duration:{nanos:10000000},grpc_timeout_header_max:{nanos:50000000}}}),
      {match:{prefix:'/fixture.Rds/',headers:[{name:'x-route',exact_match:'b'}]},route:{cluster:'b',hash_policy:[{header:{header_name:'x-key'},terminal:true}]}},
      {match:{safe_regex:{regex:'/fixture\\.Rds/(Weighted|Unary)'}},route:{weighted_clusters:{clusters:[{name:'a',weight:{value:1}},{name:'b',weight:{value:3}}]}}},
    ]},
  ]};
}
assert.equal(RouteConfigurationResourceType.get().allResourcesRequiredInSotW(),false);
const initial=encode(routes()),updated=encode(routes(true));
for(const resource of [initial,updated])assert.equal(RouteConfigurationResourceType.get().decode({server:{},bootstrap:{}},resource).error,undefined);
const counts={};const sessions=[new Set(),new Set()];const transcript=[];const servers=[];
let controlCall;let step=0;let holdCallback;let held=false;let retryAttempts=0;let slowCanceled=false;
const send=(version,resources)=>controlCall.write({type_url:typeUrl,version_info:version,nonce:version,resources});
const unary=name=>({path:'/fixture.Rds/'+name,requestStream:false,responseStream:false,requestSerialize:x=>x,requestDeserialize:x=>x,responseSerialize:x=>x,responseDeserialize:x=>x});
function record(index,name,call){
  assert.equal(call.request.toString(),'request');counts[name]=(counts[name]??0)+1;sessions[index].add(call.call.stream.session);
  for(const key of Object.keys(call.metadata.getMap()))assert(!key.includes('xds')&&!key.includes('cluster'));
}
(async()=>{
  const ports=[];
  for(const [index,label] of ['a','b'].entries()){
    const server=new grpc.Server();servers.push(server);const methods={},handlers={};
    for(const name of ['Weighted','Unary','Retry','Slow','Hold','After','Release']){
      methods[name]=unary(name);handlers[name]=(call,callback)=>{
        record(index,name,call);
        if(name==='Hold'){
          assert.equal(index,0);assert(!held);held=true;holdCallback=callback;
          assert.equal(step,6);send('v2',[updated]);return;
        }
        if(name==='Release'){assert.equal(index,1);assert(holdCallback);holdCallback(null,Buffer.from('a'));holdCallback=null;}
        if(name==='Retry'){
          assert.equal(index,1);retryAttempts++;
          if(retryAttempts===1)return callback({code:grpc.status.UNAVAILABLE,details:'retry fixture'});
          assert.equal(call.metadata.get('grpc-previous-rpc-attempts')[0],'1');
        }
        if(name==='Slow'){
          assert.equal(index,1);const remaining=call.getDeadline()-Date.now();assert(remaining<=70&&remaining>0);
          const timer=setTimeout(()=>callback(null,Buffer.from(label)),250);
          call.on('cancelled',()=>{slowCanceled=true;clearTimeout(timer);});return;
        }
        callback(null,Buffer.from(label));
      };
    }
    methods.Stream={...unary('Stream'),requestStream:true,responseStream:true};
    handlers.Stream=call=>{call.on('data',message=>{assert.equal(message.toString(),'request');sessions[index].add(call.call.stream.session);});call.on('end',()=>{assert.equal(index,1);counts.Stream=(counts.Stream??0)+1;call.write(Buffer.from('b'));call.end();});};
    server.addService(methods,handlers);ports.push(await new Promise((resolve,reject)=>server.bindAsync('127.0.0.1:0',grpc.ServerCredentials.createInsecure(),(e,p)=>e?reject(e):resolve(p))));
  }
  const control=new grpc.Server();servers.push(control);
  control.addService(service,{StreamAggregatedResources(call){controlCall=call;call.on('error',()=>{});call.on('data',request=>{
    transcript.push({version:request.version_info,nonce:request.response_nonce,names:request.resource_names,nack:request.error_detail?.message??''});
    const ack=version=>{assert.equal(request.version_info,version);assert.equal(request.response_nonce,version);assert(!request.error_detail);};
    const nack=(nonce,message)=>{assert.equal(request.version_info,'v1');assert.equal(request.response_nonce,nonce);assert.equal(request.error_detail.code,3);assert.equal(request.error_detail.message,message);};
    switch(step++){
      case 0:assert.equal(request.node.id,'netz-rds-node');send('v1',[initial]);break;
      case 1:ack('v1');break;
      case 2:{assert(request.resource_names.includes('phase-bad'));const bad=routes();bad.virtual_hosts[2].domains=['*bad*'];const resource=encode(bad);assert(RouteConfigurationResourceType.get().decode({server:{},bootstrap:{}},resource).error);send('bad',[resource]);break;}
      case 3:nack('bad','InvalidRdsResource');send('duplicate',[initial,initial]);break;
      case 4:{nack('duplicate','DuplicateRdsResource');const bad=routes();bad.virtual_hosts[2].typed_per_filter_config={router:{type_url:'type.googleapis.com/custom.Filter',value:Buffer.alloc(0)}};send('filter',[encode(bad)]);break;}
      case 5:nack('filter','UnsupportedRdsFeature');break;
      case 6:ack('v2');break;
      case 7:assert(request.resource_names.includes('phase-omit'));send('v3',[]);break;
      case 8:ack('v3');break;
      case 9:assert(request.resource_names.includes('phase-unrelated'));send('v4',[encode({...routes(true),name:'other'})]);break;
      case 10:ack('v4');break;
      case 11:assert(request.resource_names.includes('phase-empty'));send('v5',[encode({name:'routes'})]);break;
      case 12:ack('v5');call.end();break;
      default:assert.fail('unexpected RDS request');
    }
  });}});
  const controlPort=await new Promise((resolve,reject)=>control.bindAsync('127.0.0.1:0',grpc.ServerCredentials.createInsecure(),(e,p)=>e?reject(e):resolve(p)));
  const result=await new Promise((resolve,reject)=>{
    const child=spawn(process.argv[2],[String(controlPort),...ports.map(String)]);let output='';const timer=setTimeout(()=>{child.kill();reject(new Error(output));},30000);
    child.stdout.on('data',b=>output+=b);child.stderr.on('data',b=>output+=b);child.on('error',e=>{clearTimeout(timer);reject(e);});
    child.on('exit',code=>{clearTimeout(timer);if(code!==0)return reject(new Error(output));const line=output.split('\n').find(x=>x.startsWith('RDS_RESULT '));if(!line)return reject(new Error(output));resolve(JSON.parse(line.slice(11)));});
  });
  assert.equal(step,13);assert.equal(retryAttempts,2);assert.equal(result.throttle_tokens,3100);assert(slowCanceled);assert(held&&!holdCallback);
  assert.deepEqual(counts,{Unary:20,Weighted:400,Stream:1,Retry:2,Slow:1,Hold:1,After:22,Release:1});
  assert.deepEqual(sessions.map(x=>x.size),[1,1]);
  console.log(JSON.stringify({...result,sotw_omission_is_deletion:false,wire_counts:counts,sessions:sessions.map(x=>x.size),transcript,retry_attempts:retryAttempts,slow_canceled:slowCanceled,old_route_completed:true,grpc_js:require('../grpc_locality/node_modules/@grpc/grpc-js/package.json').version,grpc_js_xds:require('../grpc_locality/node_modules/@grpc/grpc-js-xds/package.json').version}));
})().catch(error=>{console.error(error);process.exitCode=1;}).finally(()=>servers.forEach(server=>server.forceShutdown()));
