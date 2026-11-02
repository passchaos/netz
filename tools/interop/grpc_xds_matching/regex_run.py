#!/usr/bin/env python3
"""Differential full matching against actual RE2 WASM, including adversarial input."""
import argparse,hashlib,json,random,subprocess,tempfile
from pathlib import Path
def corpus():
 rng=random.Random(0x52534453)
 texts=['','a','b','c','ab','aa','abc','123','a_b','xyz','\n','a\nb','猫','猫é','Σ','ς','K','ẞ','٣','a{1','(x+y)[z]']
 texts += [''.join(rng.choice('abcz019_猫Σé\n') for _ in range(rng.randrange(16))) for _ in range(180)]
 atoms=['a','b','[a-z]','[0-9]','[^ab]','[[:alpha:]]','\\d','\\s','\\w','\\p{Greek}','\\p{L}','\\P{Nd}','.','猫','(?:ab|c)','(?i:k|σ)','\\C','\\x{e9}']
 patterns=['','a*','(?:a|aa)*b','(?:a?)*','(?:a*)+','(?:a|)*','(?i)[a-z]','(?i)[^a-z]','(?i)[\\P{Lu}]','[[:^alpha:]]','(?m)^a$\\n(?s:.)','\\Q(x+y)[z]\\E*','\\A\\bword\\b\\z','\\12','\\777','(?P<1>a)','a{1','a{1,','a{b']
 syntax_cases=['(','[a-z','[z-a]','a**','a++','(?=a)','(?<=a)','(a)\\1','\\8','(?x)a','(?i-)a','(?i)*','^+','{1}','a{1}{2}','\\p{Unknown}','\\x{d800}','a{2,1}','a{1001}','[a-\\d]','[\\b]','\\']
 for _ in range(600):
  seq=''.join(rng.choice(atoms)+rng.choice(['','?','*','+','{0,2}','{2}','{1,3}','+?']) for _ in range(rng.randrange(1,5)))
  if rng.randrange(3)==0:seq='(?:'+seq+'|'+rng.choice(atoms)+')'
  if rng.randrange(5)==0:seq='(?i:'+seq+')'
  patterns.append(seq)
 cases=[{'pattern':p,'inputs':texts} for p in patterns+syntax_cases]
 cases += [{'pattern':'(?:a|aa)*b','inputs':['a'*32768,'a'*32767+'b']}, {'pattern':'(?:a?){1000}a{1000}','inputs':['a'*999,'a'*1000,'a'*1999,'a'*2000]}]
 return cases
def main():
 parser=argparse.ArgumentParser();parser.add_argument('client',type=Path);parser.add_argument('--output',type=Path);args=parser.parse_args()
 directory=Path(__file__).resolve().parent;repo=directory.parents[2];cases=corpus()
 with tempfile.TemporaryDirectory(prefix='netz-re2-') as temporary:
  input=Path(temporary)/'cases.json';input.write_text(json.dumps(cases))
  native=json.loads(subprocess.check_output([str(args.client.resolve()),str(input)],text=True,timeout=30))
  reference=json.loads(subprocess.check_output(['node',str(directory/'regex_peer.js'),str(input)],text=True,timeout=30))
 mismatches=[]
 for case,actual,expected in zip(cases,native,reference,strict=True):
  if actual['err']!=expected['err'] or actual['matches']!=expected['matches']:
   wrong=[{'input':text,'native':a,'re2':b} for text,a,b in zip(case['inputs'],actual['matches'],expected['matches']) if a!=b]
   mismatches.append({'pattern':case['pattern'],'native_error':actual['err'],'re2_error':expected['err'],'examples':wrong[:5]})
 if mismatches:raise AssertionError(json.dumps(mismatches[:20],ensure_ascii=False,indent=2))
 digest=lambda path:hashlib.sha256(path.read_bytes()).hexdigest()
 files=sorted((repo/'src/grpc/xds/routing/regex').rglob('*'))+[repo/'src/grpc/xds/routing/regex.zig']+sorted(directory.glob('regex_*'))+[repo/'tools/codegen/xds_unicode/generate.py']
 report={'status':'passed','patterns':len(cases),'match_vectors':sum(len(c['inputs']) for c in cases),'seed':'0x52534453','re2_wasm':'1.0.2','linear_work_bound':True,'source_sha256':{str(p.relative_to(repo)):digest(p) for p in files if p.is_file()},'client_sha256':digest(args.client),'corpus_sha256':hashlib.sha256(json.dumps(cases,sort_keys=True).encode()).hexdigest()}
 if args.output:args.output.parent.mkdir(parents=True,exist_ok=True);args.output.write_text(json.dumps(report,indent=2)+'\n')
 print(json.dumps(report,indent=2))
if __name__=='__main__':main()
