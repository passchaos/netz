'use strict';
const assert=require('node:assert/strict');const fs=require('node:fs');const path=require('node:path');const {spawn}=require('node:child_process');
const grpc=require('../grpc_locality/node_modules/@grpc/grpc-js');const loader=require('../grpc_locality/node_modules/@grpc/proto-loader');const protobuf=require('../grpc_locality/node_modules/protobufjs');
const deps=path.resolve(__dirname,'../grpc_locality/node_modules/@grpc/grpc-js-xds/deps');const includes=['envoy-api','xds','googleapis','protoc-gen-validate'].map(x=>path.join(deps,x));
const definition=loader.loadSync('envoy/service/discovery/v3/ads.proto',{includeDirs:includes,keepCase:true,defaults:true,longs:String,enums:String});
const service=grpc.loadPackageDefinition(definition).envoy.service.discovery.v3.AggregatedDiscoveryService.service;
const root=new protobuf.Root();root.resolvePath=(_o,t)=>includes.map(d=>path.join(d,t)).find(p=>fs.existsSync(p))??t;
root.loadSync(['envoy/config/listener/v3/listener.proto','envoy/config/cluster/v3/cluster.proto','envoy/config/endpoint/v3/endpoint.proto','envoy/extensions/filters/network/http_connection_manager/v3/http_connection_manager.proto'],{keepCase:true});root.resolveAll();
const urls={lds:'type.googleapis.com/envoy.config.listener.v3.Listener',rds:'type.googleapis.com/envoy.config.route.v3.RouteConfiguration',cds:'type.googleapis.com/envoy.config.cluster.v3.Cluster',eds:'type.googleapis.com/envoy.config.endpoint.v3.ClusterLoadAssignment'};
const encode=(name,value)=>Buffer.from(root.lookupType(name).encode(root.lookupType(name).create(value)).finish());
function listener(){const hcm={rds:{config_source:{ads:{}},route_config_name:'routes'},http_filters:[{name:'router',typed_config:{type_url:'type.googleapis.com/envoy.extensions.filters.http.router.v3.Router',value:Buffer.alloc(0)}}]};return{type_url:urls.lds,value:encode('envoy.config.listener.v3.Listener',{name:'frontend',api_listener:{api_listener:{type_url:'type.googleapis.com/envoy.extensions.filters.network.http_connection_manager.v3.HttpConnectionManager',value:encode('envoy.extensions.filters.network.http_connection_manager.v3.HttpConnectionManager',hcm)}}})};}
function route(){return{type_url:urls.rds,value:encode('envoy.config.route.v3.RouteConfiguration',{name:'routes',virtual_hosts:[{name:'host',domains:['backend.test'],routes:[{match:{prefix:'/fixture.Runtime/'},route:{cluster:'a'}}]}]})};}
function cluster(){return{type_url:urls.cds,value:encode('envoy.config.cluster.v3.Cluster',{name:'a',type:3,eds_cluster_config:{eds_config:{ads:{}},service_name:'eds-a'}})};}
function assignment(port){return{type_url:urls.eds,value:encode('envoy.config.endpoint.v3.ClusterLoadAssignment',{cluster_name:'eds-a',endpoints:[{locality:{region:'local'},load_balancing_weight:{value:1},lb_endpoints:[{endpoint:{address:{socket_address:{address:'127.0.0.1',port_value:port}}},health_status:1}]}]})};}
const unary=name=>({path:'/fixture.Runtime/'+name,requestStream:false,responseStream:false,requestSerialize:x=>x,requestDeserialize:x=>x,responseSerialize:x=>x,responseDeserialize:x=>x});
const servers=[],calls=[],transcript=[];let control=null,controlCall=null,step=0,ended=false;
function resource(kind,name,version,value){return{name,version,resource:{type_url:urls[kind],value:value.value}};}
function response(kind,nonce,resources,removed){return{type_url:urls[kind],nonce,resources:resources??[],removed_resources:removed??[]};}
(async()=>{
 const backend=new grpc.Server();servers.push(backend);const methods={},handlers={};
 for(const name of ['A','Unavailable']){methods[name]=unary(name);handlers[name]=(call,cb)=>{calls.push(name);if(name==='A')cb(null,Buffer.from('a'));else cb(new grpc.ServerError(grpc.status.UNAVAILABLE,'no route'));};}
 backend.addService(methods,handlers);
 const port=await new Promise((r,j)=>backend.bindAsync('127.0.0.1:0',grpc.ServerCredentials.createInsecure(),(e,p)=>e?j(e):r(p)));
 control=new grpc.Server();servers.push(control);
 control.addService(service,{DeltaAggregatedResources(call){
  controlCall=call;call.on('error',()=>{});
  call.on('data',request=>{
   if(ended)return;
   transcript.push({step,type:request.type_url,subscribe:request.resource_names_subscribe??[],unsubscribe:request.resource_names_unsubscribe??[],nonce:request.response_nonce??'',nack:request.error_detail?.message??''});
   assert(!request.error_detail);
   const ack=(kind,nonce)=>{assert.equal(request.type_url,urls[kind]);assert.equal(request.response_nonce,nonce);};
   switch(step++){
    case 0:
     assert.equal(request.type_url,urls.lds);assert.equal(request.node?.id,'netz-delta-runtime');assert.deepEqual(request.resource_names_subscribe,['frontend']);
     call.write(response('lds','l1',[resource('lds','frontend','l1',listener())]));break;
    case 1:ack('lds','l1');break;
    case 2:
     assert.equal(request.type_url,urls.rds);assert.deepEqual(request.resource_names_subscribe,['routes']);
     call.write(response('rds','r1',[resource('rds','routes','r1',route())]));break;
    case 3:ack('rds','r1');break;
    case 4:
     assert.equal(request.type_url,urls.cds);assert.deepEqual(request.resource_names_subscribe,['a']);
     call.write(response('cds','c1',[resource('cds','a','c1',cluster())]));break;
    case 5:ack('cds','c1');break;
    case 6:
     assert.equal(request.type_url,urls.eds);assert.deepEqual(request.resource_names_subscribe,['eds-a']);
     call.write(response('eds','e1',[resource('eds','eds-a','e1',assignment(port))]));break;
    case 7:ack('eds','e1');call.write(response('eds','e2',[],['eds-a']));break;
    case 8:ack('eds','e2');call.write(response('eds','e3',[resource('eds','eds-a','e3',assignment(port))]));break;
    case 9:ack('eds','e3');call.write(response('lds','l2',[],['frontend']));break;
    case 10:ack('lds','l2');ended=true;call.end();break;
    default:assert.fail('unexpected delta runtime request');
   }
  });
 }});
 const controlPort=await new Promise((r,j)=>control.bindAsync('127.0.0.1:0',grpc.ServerCredentials.createInsecure(),(e,p)=>e?j(e):r(p)));
 const result=await new Promise((r,j)=>{const child=spawn(process.argv[2],[String(port),String(controlPort)]);let out='';const timer=setTimeout(()=>{child.kill();j(new Error(out));},30000);child.stdout.on('data',b=>out+=b);child.stderr.on('data',b=>out+=b);child.on('error',e=>{clearTimeout(timer);j(e);});child.on('exit',code=>{clearTimeout(timer);if(code)return j(new Error(out));const line=out.split('\n').find(x=>x.startsWith('DELTA_RUNTIME_RESULT '));if(!line)return j(new Error(out));r(JSON.parse(line.slice(21)));});});
 assert.equal(step,11);assert.deepEqual(calls,['A','A']);
 console.log(JSON.stringify({...result,calls,transcript,grpc_js:require('../grpc_locality/node_modules/@grpc/grpc-js/package.json').version}));
})().catch(e=>{console.error(e);process.exitCode=1;}).finally(()=>servers.forEach(s=>s.forceShutdown()));
