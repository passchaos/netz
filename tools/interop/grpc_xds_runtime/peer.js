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
const cluster=(name,eds,max=1)=>({type_url:urls.cds,value:encode('envoy.config.cluster.v3.Cluster',{name,type:3,eds_cluster_config:{eds_config:{ads:{}},service_name:eds},circuit_breakers:{thresholds:[{max_requests:{value:max}}]}})});
const route=(name,cluster)=>({name,virtual_hosts:[{name:'host',domains:['backend.test'],routes:[{match:{prefix:'/fixture.Runtime/'},route:{cluster}}]}]});
function listener(){const routes={name:'inline',virtual_hosts:[{name:'host',domains:['backend.test'],routes:[{match:{path:'/fixture.Runtime/B'},route:{cluster:'b'}},{match:{path:'/fixture.Runtime/Release'},route:{cluster:'b'}},{match:{prefix:'/fixture.Runtime/'},route:{cluster:'a'}}]}]};const hcm={rds:{config_source:{ads:{}},route_config_name:'routes'},http_filters:[{name:'router',typed_config:{type_url:'type.googleapis.com/envoy.extensions.filters.http.router.v3.Router',value:Buffer.alloc(0)}}]};return{type_url:urls.lds,value:encode('envoy.config.listener.v3.Listener',{name:'frontend',api_listener:{api_listener:{type_url:'type.googleapis.com/envoy.extensions.filters.network.http_connection_manager.v3.HttpConnectionManager',value:encode('envoy.extensions.filters.network.http_connection_manager.v3.HttpConnectionManager',hcm)}}})};}
function assignment(name,port,drop=false){return{type_url:urls.eds,value:encode('envoy.config.endpoint.v3.ClusterLoadAssignment',{cluster_name:name,endpoints:[{locality:{region:'local'},load_balancing_weight:{value:1},lb_endpoints:[{endpoint:{address:{socket_address:{address:'127.0.0.1',port_value:port}}},health_status:1}]}],policy:drop?{drop_overloads:[{category:'b-drop',drop_percentage:{numerator:1000000,denominator:2}}]}:{}})};}
const unary=name=>({path:'/fixture.Runtime/'+name,requestStream:false,responseStream:false,requestSerialize:x=>x,requestDeserialize:x=>x,responseSerialize:x=>x,responseDeserialize:x=>x});
const servers=[],sessions=[new Set(),new Set()],calls=[],transcript=[];let controlCall,step=0,held,deleted=false;
(async()=>{
 const ports=[];for(const [index,label] of ['a','b'].entries()){const server=new grpc.Server();servers.push(server);const methods={},handlers={};for(const name of ['A','B','Held','Release']){methods[name]=unary(name);handlers[name]=(call,cb)=>{assert.equal(call.request.toString(),'request');calls.push(label+':'+name);sessions[index].add(call.call.stream.session);if(name==='Held'){assert.equal(index,0);held=cb;return;}if(name==='Release'){assert.equal(index,1);assert(held);held(null,Buffer.from('a'));held=null;}cb(null,Buffer.from(label));};}server.addService(methods,handlers);ports.push(await new Promise((r,j)=>server.bindAsync('127.0.0.1:0',grpc.ServerCredentials.createInsecure(),(e,p)=>e?j(e):r(p))));}
 const control=new grpc.Server();servers.push(control);control.addService(service,{StreamAggregatedResources(call){controlCall=call;call.on('error',()=>{});const send=(kind,version,resources)=>call.write({type_url:urls[kind],version_info:version,nonce:version,resources});call.on('data',request=>{
  transcript.push({type:request.type_url,version:request.version_info,nonce:request.response_nonce,names:request.resource_names,nack:request.error_detail?.message??''});
  const ack=(kind,v)=>{assert.equal(request.type_url,urls[kind]);assert.equal(request.version_info,v);assert.equal(request.response_nonce,v);assert(!request.error_detail);};
  if(request.type_url===urls.cds&&request.version_info==='c2'&&request.response_nonce==='bad'&&!request.resource_names.includes('phase-bad')){assert.equal(request.error_detail?.message,'DuplicateCdsResource');assert(request.resource_names.every(x=>x==='a'||x==='b'));return;}
  if(deleted){assert(request.type_url===urls.cds||request.type_url===urls.eds);return;}
  switch(step++){
   case 0:assert.equal(request.node.id,'netz-auto-xds');send('lds','l1',[listener()]);break;
   case 1:ack('lds','l1');break;
   case 2:assert.equal(request.type_url,urls.rds);assert.deepEqual(request.resource_names,['routes']);send('rds','r1',[{type_url:urls.rds,value:encode('envoy.config.route.v3.RouteConfiguration',{name:'routes',virtual_hosts:[{name:'host',domains:['backend.test'],routes:[{match:{path:'/fixture.Runtime/B'},route:{cluster:'b'}},{match:{path:'/fixture.Runtime/Release'},route:{cluster:'b'}},{match:{prefix:'/fixture.Runtime/'},route:{cluster:'a'}}]}]})}]);break;
   case 3:ack('rds','r1');break;
   case 4:assert.equal(request.type_url,urls.cds);assert.deepEqual(request.resource_names,['a','b']);send('cds','c1',[cluster('a','eds-a',1),cluster('b','eds-b',2)]);break;
   case 5:ack('cds','c1');break;
   case 6:assert.equal(request.type_url,urls.eds);assert.deepEqual(request.resource_names,['eds-a','eds-b']);send('eds','e1',[assignment('eds-a',ports[0]),assignment('eds-b',ports[1])]);break;
   case 7:ack('eds','e1');break;
   case 8:assert(request.resource_names.includes('phase-drop'));send('eds','e2',[assignment('eds-a',ports[0]),assignment('eds-b',ports[1],true)]);break;
   case 9:ack('eds','e2');break;
   case 10:assert(request.resource_names.includes('phase-name'));send('cds','c2',[cluster('a','eds-a',1),cluster('b','eds-b2',2)]);break;
   case 11:ack('cds','c2');break;
   case 12:assert.equal(request.type_url,urls.eds);assert.deepEqual(request.resource_names,['eds-a','eds-b2']);send('eds','e3',[assignment('eds-a',ports[0]),assignment('eds-b2',ports[1])]);break;
   case 13:ack('eds','e3');break;
   case 14:assert(request.resource_names.includes('phase-bad'));send('cds','bad',[cluster('a','eds-a',1),cluster('a','eds-a',1)]);break;
   case 15:assert.equal(request.type_url,urls.cds);assert.equal(request.version_info,'c2');assert.equal(request.response_nonce,'bad');assert.equal(request.error_detail.message,'DuplicateCdsResource');send('lds','l2',[{type_url:urls.lds,value:encode('envoy.config.listener.v3.Listener',{name:'frontend',api_listener:{api_listener:{type_url:'type.googleapis.com/envoy.extensions.filters.network.http_connection_manager.v3.HttpConnectionManager',value:encode('envoy.extensions.filters.network.http_connection_manager.v3.HttpConnectionManager',{route_config:route('b-only','b'),http_filters:[{name:'router',typed_config:{type_url:'type.googleapis.com/envoy.extensions.filters.http.router.v3.Router',value:Buffer.alloc(0)}}]})}}})}]);break;
   case 16:ack('lds','l2');break;
   case 17:assert(request.resource_names.includes('phase-delete'));send('lds','l3',[]);break;
   case 18:ack('lds','l3');deleted=true;setTimeout(()=>call.end(),100);break;
   default:assert.fail('unexpected discovery request');
  }
 });}});
 const port=await new Promise((r,j)=>control.bindAsync('127.0.0.1:0',grpc.ServerCredentials.createInsecure(),(e,p)=>e?j(e):r(p)));
 const result=await new Promise((r,j)=>{const child=spawn(process.argv[2],[String(port)]);let out='';const timer=setTimeout(()=>{child.kill();j(new Error(out));},30000);child.stdout.on('data',b=>out+=b);child.stderr.on('data',b=>out+=b);child.on('error',e=>{clearTimeout(timer);j(e);});child.on('exit',code=>{clearTimeout(timer);if(code)return j(new Error(out));const line=out.split('\n').find(x=>x.startsWith('RUNTIME_RESULT '));if(!line)return j(new Error(out));r(JSON.parse(line.slice(15)));});});
 assert.equal(step,19);assert(!held);assert.deepEqual(calls,['a:A','b:B','a:Held','b:B','b:Release','a:A','b:B','a:Held','b:A','b:Release']);assert.deepEqual(sessions.map(x=>x.size),[1,1]);console.log(JSON.stringify({...result,wire_calls:calls,sessions:sessions.map(x=>x.size),transcript,grpc_js:require('../grpc_locality/node_modules/@grpc/grpc-js/package.json').version}));
})().catch(e=>{console.error(e);process.exitCode=1;}).finally(()=>servers.forEach(s=>s.forceShutdown()));
