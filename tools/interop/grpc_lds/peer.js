'use strict';
// grpc-js-xds gates RBAC parsing behind this flag; enable it before registration
// so the official Envoy RBAC schema validates the fixture below.
process.env.GRPC_XDS_EXPERIMENTAL_RBAC='true';
const assert=require('node:assert/strict');const fs=require('node:fs');const path=require('node:path');const {spawn}=require('node:child_process');
const grpc=require('../grpc_locality/node_modules/@grpc/grpc-js');const loader=require('../grpc_locality/node_modules/@grpc/proto-loader');const protobuf=require('../grpc_locality/node_modules/protobufjs');
require('../grpc_locality/node_modules/@grpc/grpc-js-xds').register();
const {ListenerResourceType}=require('../grpc_locality/node_modules/@grpc/grpc-js-xds/build/src/xds-resource-type/listener-resource-type');
const deps=path.resolve(__dirname,'../grpc_locality/node_modules/@grpc/grpc-js-xds/deps');const includes=['envoy-api','xds','googleapis','protoc-gen-validate'].map(x=>path.join(deps,x));
// Envoy annotation protos import google/protobuf/descriptor.proto, which the
// xDS dependency trees do not ship. protobufjs bundles the canonical copy.
includes.push(path.dirname(require.resolve('../grpc_locality/node_modules/protobufjs/package.json')));
const definition=loader.loadSync('envoy/service/discovery/v3/ads.proto',{includeDirs:includes,keepCase:true,defaults:true,longs:String,enums:String});
const service=grpc.loadPackageDefinition(definition).envoy.service.discovery.v3.AggregatedDiscoveryService.service;
const root=new protobuf.Root();root.resolvePath=(_origin,target)=>includes.map(dir=>path.join(dir,target)).find(x=>fs.existsSync(x))??target;
root.loadSync(['envoy/config/listener/v3/listener.proto','envoy/extensions/filters/network/http_connection_manager/v3/http_connection_manager.proto','envoy/extensions/filters/http/rbac/v3/rbac.proto','envoy/extensions/filters/http/fault/v3/fault.proto'],{keepCase:true});root.resolveAll();
const ldsUrl='type.googleapis.com/envoy.config.listener.v3.Listener';const rdsUrl='type.googleapis.com/envoy.config.route.v3.RouteConfiguration';
const hcmUrl='type.googleapis.com/envoy.extensions.filters.network.http_connection_manager.v3.HttpConnectionManager';const routerUrl='type.googleapis.com/envoy.extensions.filters.http.router.v3.Router';
const listenerType=root.lookupType('envoy.config.listener.v3.Listener');const hcmType=root.lookupType('envoy.extensions.filters.network.http_connection_manager.v3.HttpConnectionManager');const routeType=root.lookupType('envoy.config.route.v3.RouteConfiguration');
const rbacUrl='type.googleapis.com/envoy.extensions.filters.http.rbac.v3.RBAC';const rbacFilterType=root.lookupType('envoy.extensions.filters.http.rbac.v3.RBAC');
const rbacPerRouteUrl='type.googleapis.com/envoy.extensions.filters.http.rbac.v3.RBACPerRoute';const rbacPerRouteType=root.lookupType('envoy.extensions.filters.http.rbac.v3.RBACPerRoute');
const faultUrl='type.googleapis.com/envoy.extensions.filters.http.fault.v3.HTTPFault';const faultType=root.lookupType('envoy.extensions.filters.http.fault.v3.HTTPFault');
const encode=(type,value)=>Buffer.from(type.encode(type.create(value)).finish());
const router=name=>({name,typed_config:{type_url:routerUrl,value:Buffer.alloc(0)}});
// Official Envoy schema: DENY (action 1) when the x-deny header is present.
// grpc-js-xds registers only a server-side RBAC filter constructor, so its
// client Listener validator requires is_optional here. netz enforces supported
// optional filters rather than skipping them.
const rbacDenyHeader=()=>({name:'rbac',is_optional:true,typed_config:{type_url:rbacUrl,value:encode(rbacFilterType,{rules:{action:1,policies:{p:{permissions:[{header:{name:'x-deny',present_match:true}}],principals:[{any:true}]}}}})}});
// Official Envoy schema: header-driven abort and delay at 100%.
const faultHeader=()=>({
  name:'fault',
  typed_config:{
    type_url:faultUrl,
    value:encode(faultType,{
      abort:{header_abort:{},percentage:{numerator:100,denominator:0}},
      delay:{header_delay:{},percentage:{numerator:100,denominator:0}},
      upstream_cluster:'b',
      headers:[{name:'x-fault',present_match:true}],
    }),
  },
});
const optional={name:'optional',is_optional:true,typed_config:{type_url:'type.googleapis.com/custom.Optional',value:Buffer.from('opaque')}};
const routeMessageType=root.lookupType('envoy.config.route.v3.Route');
// Direct HTTPFault route override: fixed PERMISSION_DENIED replaces the
// listener's header-driven abort for this route.
const faultOverride=()=>({type_url:faultUrl,value:encode(faultType,{
  abort:{grpc_status:7,percentage:{numerator:100,denominator:0}},
})});
// protobufjs create() drops map fields with message values, so build the Route
// message first and assign typed_per_filter_config directly.
function faultOverrideRoute(cluster){
  const route=routeMessageType.create({match:{path:'/fixture.Lds/Fault'},route:{cluster}});
  route.typed_per_filter_config={fault:faultOverride()};
  return route;
}
// Canonical RBACPerRoute uses field 2 for its HTTP RBAC config. ALLOW is
// protobuf's omitted action (zero); absence at either message level disables
// the listener policy, while a present empty rules message denies every call.
const rbacRouteValues={
  RbacAllow:{rbac:{rules:{policies:{p:{permissions:[{header:{name:'x-allow',present_match:true}}],principals:[{any:true}]}}}}},
  RbacDeny:{rbac:{rules:{action:1,policies:{p:{permissions:[{header:{name:'x-block',present_match:true}}],principals:[{any:true}]}}}}},
  RbacAbsent:{},
  RbacEmpty:{rbac:{}},
  RbacEmptyRules:{rbac:{rules:{}}},
};
const rbacRouteOverrides=Object.fromEntries(Object.entries(rbacRouteValues).map(([name,value])=>{
  assert.equal(rbacPerRouteType.verify(value),null);
  return [name,{type_url:rbacPerRouteUrl,value:encode(rbacPerRouteType,value)}];
}));
assert.equal(rbacPerRouteType.fields.rbac.id,2);
const allowRules=rbacPerRouteType.decode(rbacRouteOverrides.RbacAllow.value).rbac.rules;
assert.equal(allowRules.action,0);assert(!Object.hasOwn(allowRules,'action'));
assert.equal(rbacPerRouteType.decode(rbacRouteOverrides.RbacDeny.value).rbac.rules.action,1);
assert.deepEqual(rbacRouteOverrides.RbacAbsent.value,Buffer.alloc(0));
assert.deepEqual(rbacRouteOverrides.RbacEmpty.value,Buffer.from([0x12,0]));
assert.deepEqual(rbacRouteOverrides.RbacEmptyRules.value,Buffer.from([0x12,2,0x0a,0]));
const rbacOverrideRoutes=cluster=>Object.entries(rbacRouteOverrides).map(([name,config])=>{
  const route=routeMessageType.create({name,match:{path:'/fixture.Lds/'+name},route:{cluster}});
  route.typed_per_filter_config={rbac:config};
  return route;
});
const routes=(name,cluster,zero=false,extra=[])=>({name,virtual_hosts:[{name:'host',domains:['backend.test'],routes:[...extra,...(zero?[{match:{path:'/fixture.Lds/NoCap'},route:{cluster,max_stream_duration:{max_stream_duration:{}}}}]:[]),{match:{prefix:'/fixture.Lds/'},route:{cluster}}]}]});
function listener(name,maximum,inline,extra={}){
  const hcm={http_filters:[optional,router('router')],common_http_protocol_options:{max_stream_duration:{nanos:maximum*1000000}},...(inline?{route_config:inline}:{rds:{config_source:{ads:{},resource_api_version:2},route_config_name:name}}),...extra};
  const resource={type_url:ldsUrl,value:encode(listenerType,{name:'frontend',api_listener:{api_listener:{type_url:hcmUrl,value:encode(hcmType,hcm)}}})};
  return resource;
}
const inlineA=listener('inline-a',50,routes('inline-a','a',true,rbacOverrideRoutes('a')),{http_filters:[optional,rbacDenyHeader(),router('router')]});const dynamic=listener('routes-a',300);const capped=listener('routes-a',20);const renamed=listener('routes-b',100);const inlineB=listener('inline-b',0,routes('inline-b','b',false,[faultOverrideRoute('b')]),{http_filters:[faultHeader(),router('router')]});
// grpc-js-xds rejects the two canonical disabling overrides because its RBAC
// parser requires rules. Assert that specific limitation; the official schema
// and wire assertions above cover the messages sent to netz.
const inlineAValidation=ListenerResourceType.get().decode({server:{},bootstrap:{}},inlineA);
assert.equal(inlineAValidation.error,'Listener message validation failed: ['+['RbacAbsent','RbacEmpty'].map(name=>'api_listener.api_listener: route_config: virtual_hosts[host].routes['+name+'].typed_per_filter_config[rbac] validation failed').join(',')+']');
const inlineAForValidation=listenerType.decode(inlineA.value);
const inlineAHcm=hcmType.decode(inlineAForValidation.api_listener.api_listener.value);
const inlineARoutes=inlineAHcm.route_config.virtual_hosts[0].routes;
for(const [name,config] of Object.entries(rbacRouteOverrides)){
  const route=inlineARoutes.find(route=>route.name===name);
  assert.equal(route.typed_per_filter_config.rbac.type_url,rbacPerRouteUrl);
  assert.deepEqual(route.typed_per_filter_config.rbac.value,config.value);
}
// Validate the rest of the identical listener after removing only those two
// routes whose disabling semantics grpc-js-xds cannot parse.
inlineAHcm.route_config.virtual_hosts[0].routes=inlineARoutes.filter(route=>!['RbacAbsent','RbacEmpty'].includes(route.name));
inlineAForValidation.api_listener.api_listener.value=encode(hcmType,inlineAHcm);
const inlineASupported={type_url:ldsUrl,value:encode(listenerType,inlineAForValidation)};
for(const resource of [inlineASupported,dynamic,capped,renamed,inlineB])assert.equal(ListenerResourceType.get().decode({server:{},bootstrap:{}},resource).error,undefined);
const assignment=(name,cluster)=>({type_url:rdsUrl,value:encode(routeType,routes(name,cluster))});
const servers=[],sessions=[new Set(),new Set()],counts={Fast:0,Slow:0,NoCap:0,Stream:0,...Object.fromEntries(Object.keys(rbacRouteOverrides).map(name=>[name,0]))},labels={a:0,b:0},transcript=[];
let controlCall,step=0,oldSlow=null,routeAck=false,capSent=false,initialCanceled=false,shortCanceled=false;
const send=(url,version,resources)=>controlCall.write({type_url:url,version_info:version,nonce:version,resources});
function maybeCap(){if(routeAck&&oldSlow&&!capSent){capSent=true;send(ldsUrl,'l3',[capped]);}}
const method=name=>({path:'/fixture.Lds/'+name,requestStream:false,responseStream:false,requestSerialize:x=>x,requestDeserialize:x=>x,responseSerialize:x=>x,responseDeserialize:x=>x});
(async()=>{
  const ports=[];
  for(const [index,label] of ['a','b'].entries()){
    const server=new grpc.Server();servers.push(server);const methods={},handlers={};
    for(const name of ['Fast','Slow','NoCap',...Object.keys(rbacRouteOverrides)]){methods[name]=method(name);handlers[name]=(call,callback)=>{
      assert.equal(call.request.toString(),'request');counts[name]++;labels[label]++;sessions[index].add(call.call.stream.session);
      if(name==='NoCap'){assert.equal(index,0);assert(call.getDeadline()-Date.now()>500);setTimeout(()=>callback(null,Buffer.from(label)),100);return;}
      if(name==='Slow'){
        const remaining=call.getDeadline()-Date.now();
        if(index===1&&!oldSlow&&!capSent){assert(remaining>150&&remaining<=350);let replied=false;oldSlow={callback:(...args)=>{replied=true;callback(...args);}};call.on('cancelled',()=>{if(!replied)assert.fail('old HCM deadline was changed');});maybeCap();return;}
        if(index===0)assert(remaining<=80);else assert(remaining<=60);
        const timer=setTimeout(()=>callback(null,Buffer.from(label)),250);
        call.on('cancelled',()=>{if(index===0)initialCanceled=true;else shortCanceled=true;clearTimeout(timer);});return;
      }
      callback(null,Buffer.from(label));
    };}
    methods.Stream={...method('Stream'),requestStream:true,responseStream:true};handlers.Stream=call=>{call.on('data',m=>{assert.equal(m.toString(),'request');});call.on('end',()=>{counts.Stream++;labels[label]++;sessions[index].add(call.call.stream.session);call.write(Buffer.from(label));call.end();});};
    server.addService(methods,handlers);ports.push(await new Promise((resolve,reject)=>server.bindAsync('127.0.0.1:0',grpc.ServerCredentials.createInsecure(),(e,p)=>e?reject(e):resolve(p))));
  }
  const control=new grpc.Server();servers.push(control);
  control.addService(service,{StreamAggregatedResources(call){controlCall=call;call.on('error',()=>{});call.on('data',request=>{
    transcript.push({type:request.type_url,version:request.version_info,nonce:request.response_nonce,names:request.resource_names,nack:request.error_detail?.message??''});
    const ack=(url,version)=>{assert.equal(request.type_url,url);assert.equal(request.version_info,version);assert.equal(request.response_nonce,version);assert(!request.error_detail);};
    const nack=(nonce,error)=>{assert.equal(request.type_url,ldsUrl);assert.equal(request.version_info,'l3');assert.equal(request.response_nonce,nonce);assert.equal(request.error_detail.code,3);assert.equal(request.error_detail.message,error);};
    switch(step++){
      case 0:assert.equal(request.node.id,'netz-lds-node');send(ldsUrl,'l1',[inlineA]);break;
      case 1:ack(ldsUrl,'l1');break;
      case 2:assert(request.resource_names.includes('phase-rds'));send(ldsUrl,'l2',[dynamic]);break;
      case 3:ack(ldsUrl,'l2');break;
      case 4:assert.equal(request.type_url,rdsUrl);assert.deepEqual(request.resource_names,['routes-a']);send(rdsUrl,'r1',[assignment('routes-a','b')]);break;
      case 5:ack(rdsUrl,'r1');routeAck=true;maybeCap();break;
      case 6:ack(ldsUrl,'l3');setTimeout(()=>{oldSlow.callback(null,Buffer.from('b'));oldSlow=null;},120);break;
      case 7:{assert(request.resource_names.includes('phase-bad'));const bad=listener('routes-a',20,null,{http_filters:[router('first'),router('second')]});assert(ListenerResourceType.get().decode({server:{},bootstrap:{}},bad).error);send(ldsUrl,'bad-router',[bad]);break;}
      case 8:nack('bad-router','InvalidLdsResource');send(ldsUrl,'bad-filter',[listener('routes-a',20,null,{http_filters:[{...optional,is_optional:false},router('router')]})]);break;
      case 9:{nack('bad-filter','UnsupportedLdsFeature');const bad=routes('bad-inline','a');bad.virtual_hosts[0].domains=['*bad*'];send(ldsUrl,'bad-inline',[listener('bad-inline',20,bad)]);break;}
      case 10:nack('bad-inline','InvalidLdsResource');send(ldsUrl,'l4',[renamed]);break;
      case 11:ack(ldsUrl,'l4');break;
      case 12:assert.equal(request.type_url,rdsUrl);assert.deepEqual(request.resource_names,['routes-b']);assert.equal(request.version_info,'r1');send(rdsUrl,'r2',[assignment('routes-a','a')]);break;
      case 13:ack(rdsUrl,'r2');send(rdsUrl,'r3',[assignment('routes-b','a')]);break;
      case 14:ack(rdsUrl,'r3');break;
      case 15:assert(request.resource_names.includes('phase-inline'));send(ldsUrl,'l5',[inlineB]);break;
      case 16:ack(ldsUrl,'l5');send(rdsUrl,'r4',[assignment('routes-b','a')]);break;
      case 17:ack(rdsUrl,'r4');break;
      case 18:assert(request.resource_names.includes('phase-delete'));send(ldsUrl,'l6',[]);break;
      case 19:ack(ldsUrl,'l6');send(rdsUrl,'r5',[assignment('routes-b','a')]);break;
      case 20:ack(rdsUrl,'r5');call.end();break;
      default:assert.fail('unexpected LDS/RDS request');
    }
  });}});
  const port=await new Promise((resolve,reject)=>control.bindAsync('127.0.0.1:0',grpc.ServerCredentials.createInsecure(),(e,p)=>e?reject(e):resolve(p)));
  const result=await new Promise((resolve,reject)=>{
    const child=spawn(process.argv[2],[String(port),...ports.map(String)]);let output='';const timer=setTimeout(()=>{child.kill();reject(new Error(output));},30000);
    child.stdout.on('data',b=>output+=b);child.stderr.on('data',b=>output+=b);child.on('error',e=>{clearTimeout(timer);reject(e);});child.on('exit',code=>{clearTimeout(timer);if(code!==0)return reject(new Error(output));const line=output.split('\n').find(x=>x.startsWith('LDS_RESULT '));if(!line)return reject(new Error(output));resolve(JSON.parse(line.slice(11)));});
  });
  assert.equal(step,21);assert(initialCanceled&&shortCanceled);assert(capSent&&!oldSlow);
  assert.deepEqual(counts,{Fast:28,Slow:3,NoCap:1,Stream:2,RbacAllow:1,RbacDeny:1,RbacAbsent:1,RbacEmpty:1,RbacEmptyRules:0});assert.deepEqual(labels,{a:17,b:21});assert.deepEqual(sessions.map(x=>x.size),[1,1]);
  console.log(JSON.stringify({...result,wire_counts:counts,labels,sessions:sessions.map(x=>x.size),transcript,initial_canceled:initialCanceled,short_canceled:shortCanceled,grpc_js:require('../grpc_locality/node_modules/@grpc/grpc-js/package.json').version,grpc_js_xds:require('../grpc_locality/node_modules/@grpc/grpc-js-xds/package.json').version}));
})().catch(error=>{console.error(error);process.exitCode=1;}).finally(()=>servers.forEach(server=>server.forceShutdown()));
