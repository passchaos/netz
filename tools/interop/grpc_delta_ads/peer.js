'use strict';
const assert=require('node:assert/strict');const path=require('node:path');const {spawn}=require('node:child_process');
const grpc=require('../grpc_locality/node_modules/@grpc/grpc-js');const loader=require('../grpc_locality/node_modules/@grpc/proto-loader');
const deps=path.resolve(__dirname,'../grpc_locality/node_modules/@grpc/grpc-js-xds/deps');const includes=['envoy-api','xds','googleapis','protoc-gen-validate'].map(x=>path.join(deps,x));
const definition=loader.loadSync('envoy/service/discovery/v3/ads.proto',{includeDirs:includes,keepCase:true,defaults:true,longs:String,enums:String});
const service=grpc.loadPackageDefinition(definition).envoy.service.discovery.v3.AggregatedDiscoveryService.service;
const urls={cds:'type.googleapis.com/envoy.config.cluster.v3.Cluster',eds:'type.googleapis.com/envoy.config.endpoint.v3.ClusterLoadAssignment'};
const cluster=(name,version)=>({name,version,resource:{type_url:urls.cds,value:Buffer.from(name)}});
const wrong=(name,version)=>({name,version,resource:{type_url:urls.eds,value:Buffer.from('wrong')}});
const heartbeat=(name,version)=>({name,version,ttl:{seconds:'1'}});
const transcript=[];let streams=0;let control=null;
(async()=>{
 control=new grpc.Server();
 control.addService(service,{DeltaAggregatedResources(call){
  const stream=streams++;let step=0;call.on('error',()=>{});
  call.on('data',request=>{
   transcript.push({stream,step,type:request.type_url,subscribe:request.resource_names_subscribe??[],unsubscribe:request.resource_names_unsubscribe??[],initial:request.initial_resource_versions??{},nonce:request.response_nonce??'',nack:request.error_detail?.message??''});
   assert.equal(request.type_url,urls.cds);
   if(stream===0){
    switch(step++){
     case 0:
      assert.equal(request.node?.id,'netz-delta-xds');assert.deepEqual(request.resource_names_subscribe,['a','b']);assert.deepEqual(request.resource_names_unsubscribe,[]);assert.deepEqual(request.initial_resource_versions,{});assert.equal(request.response_nonce,'');assert(!request.error_detail);
      call.write({type_url:urls.cds,nonce:'n1',resources:[cluster('a','v1'),cluster('b','v2')]});break;
     case 1:
      assert.equal(request.response_nonce,'n1');assert(!request.error_detail);assert.deepEqual(request.resource_names_subscribe,[]);assert.deepEqual(request.resource_names_unsubscribe,[]);
      call.write({type_url:urls.cds,nonce:'n2',resources:[cluster('c','v3')],removed_resources:['b']});break;
     case 2:
      assert.equal(request.response_nonce,'');assert(!request.error_detail);assert.deepEqual(request.resource_names_subscribe,['c']);assert.deepEqual(request.resource_names_unsubscribe,['b']);
      call.write({type_url:urls.cds,nonce:'n3',resources:[wrong('d','bad')]});break;
     case 3:
      assert.equal(request.response_nonce,'n2');assert(!request.error_detail);assert.deepEqual(request.resource_names_subscribe,[]);assert.deepEqual(request.resource_names_unsubscribe,[]);break;
     case 4:
      assert.equal(request.response_nonce,'n3');assert.equal(request.error_detail?.message,'wrong type');assert.deepEqual(request.resource_names_subscribe,[]);assert.deepEqual(request.resource_names_unsubscribe,[]);call.end();break;
     default:assert.fail('unexpected first-stream request');
    }
   }else{
    switch(step++){
     case 0:
      assert.equal(request.node?.id,'netz-delta-xds');assert.deepEqual(request.resource_names_subscribe,['a','c']);assert.deepEqual(request.initial_resource_versions,{a:'v1',c:'v3'});assert.equal(request.response_nonce,'');assert(!request.error_detail);
      call.write({type_url:urls.cds,nonce:'n4',resources:[heartbeat('a','v1')]});break;
     case 1:
      assert.equal(request.response_nonce,'n4');assert(!request.error_detail);assert.deepEqual(request.resource_names_subscribe,[]);assert.deepEqual(request.resource_names_unsubscribe,[]);call.end();break;
     default:assert.fail('unexpected replay request');
    }
   }
  });
 }});
 const port=await new Promise((r,j)=>control.bindAsync('127.0.0.1:0',grpc.ServerCredentials.createInsecure(),(e,p)=>e?j(e):r(p)));
 const result=await new Promise((r,j)=>{const child=spawn(process.argv[2],[String(port)]);let out='';const timer=setTimeout(()=>{child.kill();j(new Error(out));},30000);child.stdout.on('data',b=>out+=b);child.stderr.on('data',b=>out+=b);child.on('error',e=>{clearTimeout(timer);j(e);});child.on('exit',code=>{clearTimeout(timer);if(code)return j(new Error(out));const line=out.split('\n').find(x=>x.startsWith('DELTA_RESULT '));if(!line)return j(new Error(out));r(JSON.parse(line.slice(13)));});});
 assert.equal(streams,2);assert.equal(transcript.length,7);
 console.log(JSON.stringify({...result,transcript,grpc_js:require('../grpc_locality/node_modules/@grpc/grpc-js/package.json').version}));
})().catch(e=>{console.error(e);process.exitCode=1;}).finally(()=>control?.forceShutdown());
