'use strict';
const assert=require('node:assert/strict');const path=require('node:path');const {spawn}=require('node:child_process');
const grpc=require('../grpc_locality/node_modules/@grpc/grpc-js');const loader=require('../grpc_locality/node_modules/@grpc/proto-loader');
const deps=path.resolve(__dirname,'../grpc_locality/node_modules/@grpc/grpc-js-xds/deps');const includes=['envoy-api','xds','googleapis','protoc-gen-validate'].map(x=>path.join(deps,x));
const definition=loader.loadSync('envoy/service/load_stats/v3/lrs.proto',{includeDirs:includes,keepCase:true,defaults:true,longs:String,enums:String});
const service=grpc.loadPackageDefinition(definition).envoy.service.load_stats.v3.LoadReportingService.service;
const transcript=[];let control=null,step=0;
(async()=>{
 control=new grpc.Server();
 control.addService(service,{StreamLoadStats(call){
  call.on('error',()=>{});
  call.on('data',request=>{
   transcript.push({step,node:request.node?request.node.id:'',features:request.node?request.node.client_features??[]:[],clusters:(request.cluster_stats??[]).map(c=>c.cluster_name)});
   if(step===0){
    assert.equal(request.node?.id,'netz-lrs');
    assert((request.node?.client_features??[]).includes('envoy.lrs.supports_send_all_clusters'));
    assert.deepEqual(request.cluster_stats??[],[]);
    call.write({clusters:['a','b'],load_reporting_interval:{seconds:'0',nanos:100000000},report_endpoint_granularity:true});
    step+=1;return;
   }
   if(step===1){
    assert(!request.node);
    assert.equal((request.cluster_stats??[]).length,1);
    const cluster=request.cluster_stats[0];
    assert.equal(cluster.cluster_name,'a');assert.equal(cluster.cluster_service_name,'eds-a');
    assert.equal(cluster.total_dropped_requests,'1');
    assert.equal(cluster.load_report_interval.nanos,100000000);
    assert.equal(cluster.upstream_locality_stats.length,1);
    const local=cluster.upstream_locality_stats[0];
    assert.equal(local.locality.region,'r');assert.equal(local.locality.zone,'z');
    assert.equal(local.total_successful_requests,'1');assert.equal(local.total_error_requests,'1');assert.equal(local.total_issued_requests,'1');
    assert.equal(cluster.dropped_requests.length,1);assert.equal(cluster.dropped_requests[0].category,'throttle');assert.equal(cluster.dropped_requests[0].dropped_count,'1');
    call.write({clusters:[],send_all_clusters:true});call.end();step+=1;return;
   }
   assert.fail('unexpected LRS request');
  });
 }});
 const port=await new Promise((r,j)=>control.bindAsync('127.0.0.1:0',grpc.ServerCredentials.createInsecure(),(e,p)=>e?j(e):r(p)));
 const result=await new Promise((r,j)=>{const child=spawn(process.argv[2],[String(port)]);let out='';const timer=setTimeout(()=>{child.kill();j(new Error(out));},30000);child.stdout.on('data',b=>out+=b);child.stderr.on('data',b=>out+=b);child.on('error',e=>{clearTimeout(timer);j(e);});child.on('exit',code=>{clearTimeout(timer);if(code)return j(new Error(out));const line=out.split('\n').find(x=>x.startsWith('LRS_RESULT '));if(!line)return j(new Error(out));r(JSON.parse(line.slice(11)));});});
 assert.equal(step,2);
 console.log(JSON.stringify({...result,transcript,grpc_js:require('../grpc_locality/node_modules/@grpc/grpc-js/package.json').version}));
})().catch(e=>{console.error(e);process.exitCode=1;}).finally(()=>control?.forceShutdown());
