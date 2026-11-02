'use strict';
const assert = require('node:assert/strict');
const path = require('node:path');
const fs = require('node:fs');
const {spawn} = require('node:child_process');
const grpc = require('../grpc_locality/node_modules/@grpc/grpc-js');
const loader = require('../grpc_locality/node_modules/@grpc/proto-loader');
const protobuf = require('../grpc_locality/node_modules/protobufjs');
require('../grpc_locality/node_modules/@grpc/grpc-js-xds').register();
const {ClusterResourceType} = require('../grpc_locality/node_modules/@grpc/grpc-js-xds/build/src/xds-resource-type/cluster-resource-type');
const deps = path.resolve(__dirname, '../grpc_locality/node_modules/@grpc/grpc-js-xds/deps');
const includes = ['envoy-api', 'xds', 'googleapis', 'protoc-gen-validate'].map(value => path.join(deps, value));
const definition = loader.loadSync('envoy/service/discovery/v3/ads.proto', {includeDirs: includes, keepCase: true, defaults: true, longs: String, enums: String});
const adsService = grpc.loadPackageDefinition(definition).envoy.service.discovery.v3.AggregatedDiscoveryService.service;
const root = new protobuf.Root();
root.resolvePath = (_origin, target) => includes.map(dir=>path.join(dir,target)).find(file=>fs.existsSync(file)) ?? target;
root.loadSync(['envoy/config/cluster/v3/cluster.proto', 'envoy/config/endpoint/v3/endpoint.proto', 'envoy/extensions/load_balancing_policies/wrr_locality/v3/wrr_locality.proto', 'envoy/extensions/load_balancing_policies/round_robin/v3/round_robin.proto'], {keepCase:true});
root.resolveAll();
const cdsUrl = 'type.googleapis.com/envoy.config.cluster.v3.Cluster';
const edsUrl = 'type.googleapis.com/envoy.config.endpoint.v3.ClusterLoadAssignment';
const clusterType = root.lookupType('envoy.config.cluster.v3.Cluster');
const assignmentType = root.lookupType('envoy.config.endpoint.v3.ClusterLoadAssignment');
const typedPrefix = 'type.googleapis.com/envoy.extensions.load_balancing_policies.';
const encode = (type,value)=>Buffer.from(type.encode(type.create(value)).finish());
const oracle = [];
function cluster(service, limit, ring=false, typed=false) {
  const value = {name:'backend', type:3, eds_cluster_config:{eds_config:{ads:{},resource_api_version:2},service_name:service}, circuit_breakers:{thresholds:[{priority:0,max_requests:{value:limit}}]}};
  if(ring) {value.lb_policy=2;value.ring_hash_lb_config={minimum_ring_size:{value:32},maximum_ring_size:{value:64},hash_function:0};}
  if(typed) {
    const wrr = root.lookupType('envoy.extensions.load_balancing_policies.wrr_locality.v3.WrrLocality');
    const policy = (url,payload)=>({typed_extension_config:{typed_config:{type_url:url,value:payload}}});
    value.load_balancing_policy={policies:[policy('type.googleapis.com/custom.Unknown',Buffer.from('opaque')), policy(typedPrefix+'wrr_locality.v3.WrrLocality',encode(wrr,{endpoint_picking_policy:{policies:[policy(typedPrefix+'round_robin.v3.RoundRobin',Buffer.alloc(0))]}}))]};
  }
  const resource={type_url:cdsUrl,value:encode(clusterType,value)};
  const decoded=ClusterResourceType.get().decode({server:{},bootstrap:{certificateProviders:{}}},resource);
  assert.equal(decoded.error,undefined);assert.equal(decoded.value.edsServiceName,service);assert.equal(decoded.value.maxConcurrentRequests,limit);
  const lb=decoded.value.lbPolicyConfig[0];
  if(ring) assert.deepEqual(lb,{ring_hash:{min_ring_size:32,max_ring_size:64}});
  else assert.deepEqual(lb,{xds_wrr_locality:{child_policy:[{round_robin:{}}]}});
  oracle.push({service,limit,lb,typed});return resource;
}
function assignment(name, ports, bad=false) {
  const endpoints=ports.map((port,index)=>({locality:{region:String(name==='service-b'?1:index)},load_balancing_weight:{value:index===0?1:3},lb_endpoints:[{endpoint:{address:{socket_address:{address:'127.0.0.1',port_value:port}}},health_status:1}]}));
  if(bad) endpoints.push({...endpoints[0]});
  return {type_url:edsUrl,value:encode(assignmentType,{cluster_name:name,endpoints})};
}
const counts=[0,0],sessions=[new Set(),new Set()],servers=[],transcript=[];
const unary={path:'/fixture.Cds/Unary',requestStream:false,responseStream:false,requestSerialize:x=>x,requestDeserialize:x=>x,responseSerialize:x=>x,responseDeserialize:x=>x};
(async()=>{
  const ports=[];
  for(const [index,label] of ['a','b'].entries()) {
    const server=new grpc.Server();servers.push(server);
    server.addService({Unary:unary},{Unary(call,callback){assert.equal(call.request.toString(),'request');counts[index]++;sessions[index].add(call.call.stream.session);callback(null,Buffer.from(label));}});
    ports.push(await new Promise((resolve,reject)=>server.bindAsync('127.0.0.1:0',grpc.ServerCredentials.createInsecure(),(e,p)=>e?reject(e):resolve(p))));
  }
  const control=new grpc.Server();servers.push(control);let step=0;
  control.addService(adsService,{StreamAggregatedResources(call){
    const send=(type,version,resources)=>call.write({type_url:type,version_info:version,nonce:version,resources});
    const ack=(request,type,version)=>{assert.equal(request.type_url,type);assert.equal(request.version_info,version);assert.equal(request.response_nonce,version);assert(!request.error_detail);};
    const nack=(request,type,version,nonce,message)=>{assert.equal(request.type_url,type);assert.equal(request.version_info,version);assert.equal(request.response_nonce,nonce);assert.equal(request.error_detail.code,3);assert.equal(request.error_detail.message,message);};
    call.on('error',()=>{});
    call.on('data',request=>{
      transcript.push({type:request.type_url,version:request.version_info,nonce:request.response_nonce,names:request.resource_names,nack:request.error_detail?.message??''});
      switch(step++) {
        case 0: assert.equal(request.node.id,'netz-cds-node');assert.deepEqual(request.resource_names,['backend']);send(cdsUrl,'c1',[cluster('service-a',3)]);break;
        case 1: ack(request,cdsUrl,'c1');break;
        case 2: assert.equal(request.type_url,edsUrl);assert.deepEqual(request.resource_names,['service-a']);send(edsUrl,'e1',[assignment('service-a',ports)]);break;
        case 3: ack(request,edsUrl,'e1');break;
        case 4: assert(request.resource_names.includes('phase-close'));send(cdsUrl,'c2',[cluster('service-a',0,true)]);break;
        case 5: ack(request,cdsUrl,'c2');break;
        case 6: assert(request.resource_names.includes('phase-open'));send(cdsUrl,'c3',[cluster('service-a',3,true)]);break;
        case 7: ack(request,cdsUrl,'c3');break;
        case 8: {
          assert(request.resource_names.includes('phase-bad'));
          const valid=cluster('service-a',3,true);const value=clusterType.toObject(clusterType.decode(valid.value));value.ring_hash_lb_config.minimum_ring_size={value:8388609};
          const invalid={type_url:cdsUrl,value:encode(clusterType,value)};
          assert(ClusterResourceType.get().decode({server:{},bootstrap:{}},invalid).error);
          send(cdsUrl,'bad',[invalid]);break;
        }
        case 9: nack(request,cdsUrl,'c3','bad','InvalidCdsResource');{const c=cluster('service-a',3);send(cdsUrl,'duplicate',[c,c]);}break;
        case 10: nack(request,cdsUrl,'c3','duplicate','DuplicateCdsResource');{const c=clusterType.toObject(clusterType.decode(cluster('service-a',3).value));c.transport_socket={name:'unsupported'};send(cdsUrl,'security',[{type_url:cdsUrl,value:encode(clusterType,c)}]);}break;
        case 11: nack(request,cdsUrl,'c3','security','UnsupportedCdsFeature');send(cdsUrl,'c4',[cluster('service-b',3,false,true)]);break;
        case 12: ack(request,cdsUrl,'c4');break;
        case 13: assert.equal(request.type_url,edsUrl);assert.equal(request.version_info,'e1');assert.deepEqual(request.resource_names,['service-b']);send(edsUrl,'e2',[assignment('service-b',[ports[1]])]);break;
        case 14: ack(request,edsUrl,'e2');break;
        case 15: assert(request.resource_names.includes('phase-eds-bad'));send(edsUrl,'eds-bad',[assignment('service-b',[ports[1]],true)]);break;
        case 16: nack(request,edsUrl,'e2','eds-bad','InvalidEdsResource');send(cdsUrl,'c5',[]);break;
        case 17: ack(request,cdsUrl,'c5');send(edsUrl,'e3',[assignment('service-b',[ports[1]])]);break;
        case 18: ack(request,edsUrl,'e3');call.end();break;
        default: assert.fail('unexpected ADS request');
      }
    });
  }});
  const port=await new Promise((resolve,reject)=>control.bindAsync('127.0.0.1:0',grpc.ServerCredentials.createInsecure(),(e,p)=>e?reject(e):resolve(p)));
  const result=await new Promise((resolve,reject)=>{
    const child=spawn(process.argv[2],[String(port)]);let output='';const timer=setTimeout(()=>{child.kill();reject(new Error('CDS timeout: '+output));},30000);
    child.stdout.on('data',b=>output+=b);child.stderr.on('data',b=>output+=b);child.on('error',e=>{clearTimeout(timer);reject(e);});
    child.on('exit',code=>{clearTimeout(timer);if(code!==0)return reject(new Error(output));const line=output.split('\n').find(x=>x.startsWith('CDS_RESULT '));if(!line)return reject(new Error(output));resolve(JSON.parse(line.slice(11)));});
  });
  assert.equal(step,19);assert.deepEqual(counts,result.locality.map((n,i)=>n+result.ring[i]+result.switched[i]));
  assert.deepEqual(sessions.map(x=>x.size),[1,1]);
  console.log(JSON.stringify({...result,wire_counts:counts,sessions:sessions.map(x=>x.size),transcript,official_cds_oracle:oracle,grpc_js:require('../grpc_locality/node_modules/@grpc/grpc-js/package.json').version,grpc_js_xds:require('../grpc_locality/node_modules/@grpc/grpc-js-xds/package.json').version}));
})().catch(error=>{console.error(error);process.exitCode=1;}).finally(()=>servers.forEach(server=>server.forceShutdown()));
