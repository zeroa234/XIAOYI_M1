import importlib.util, json, struct, sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'temp/tool-deps'))
spec=importlib.util.spec_from_file_location('ck',ROOT/'scripts/check-exposure-preview-patch.py')
ck=importlib.util.module_from_spec(spec); spec.loader.exec_module(ck)
from unicorn import (Uc,UcError,UC_ARCH_ARM,UC_MODE_ARM,UC_HOOK_MEM_WRITE,UC_HOOK_MEM_INVALID,UC_PROT_READ,UC_PROT_WRITE,UC_PROT_EXEC)
from unicorn.arm_const import *
MANIFEST_PATH=ROOT/'config/patches/demo-exposure-driver.json'
MANIFEST_BYTES=MANIFEST_PATH.read_bytes()
MANIFEST=json.loads(MANIFEST_BYTES)
HOOK=bytes.fromhex(next(p['new_hex'] for p in MANIFEST['patches'] if int(p['va'],0)==0x365684))
WRAP=bytes.fromhex(next(p['new_hex'] for p in MANIFEST['patches'] if int(p['va'],0)==0x369d68))
for patch in MANIFEST['patches']:
    start=int(patch['va'],0)-0x2000
    assert ck.TEXT[start:start+len(bytes.fromhex(patch['orig_hex']))]==bytes.fromhex(patch['orig_hex'])
STATE=0xc14707e0; CTRL=0xc1469694; EV=0xc150f9f4
REGS=[UC_ARM_REG_R0,UC_ARM_REG_R1,UC_ARM_REG_R2,UC_ARM_REG_R3,UC_ARM_REG_R4,UC_ARM_REG_R5,UC_ARM_REG_R6,UC_ARM_REG_R7,UC_ARM_REG_R8,UC_ARM_REG_R9,UC_ARM_REG_R10,UC_ARM_REG_R11,UC_ARM_REG_R12,UC_ARM_REG_SP,UC_ARM_REG_LR,UC_ARM_REG_CPSR]
STABLE=[UC_ARM_REG_R4,UC_ARM_REG_R5,UC_ARM_REG_R6,UC_ARM_REG_R7,UC_ARM_REG_R8,UC_ARM_REG_R9,UC_ARM_REG_R10,UC_ARM_REG_R11,UC_ARM_REG_SP,UC_ARM_REG_LR,UC_ARM_REG_CPSR]
def put(cpu,a,v): cpu.mem_write(a,struct.pack('<I',v&0xffffffff))
def machine(patched,ranges):
    cpu=Uc(UC_ARCH_ARM,UC_MODE_ARM); cpu.ctl_set_cpu_model(UC_CPU_ARM_926)
    cpu.mem_map(0,0x9b0000); cpu.mem_write(0x2000,ck.TEXT); cpu.mem_write(0x43f800,ck.RODATA)
    cpu.mem_protect(0,0x9b0000,UC_PROT_READ|UC_PROT_WRITE|UC_PROT_EXEC)
    if patched:
        cpu.mem_write(0x365684,HOOK); cpu.mem_write(0x369d68,WRAP)
    cpu.mem_protect(0,0x9b0000,UC_PROT_READ|UC_PROT_EXEC)
    cpu.mem_map(0xc09b0000,0x60000); cpu.mem_write(0xc09b0000,ck.DATA)
    cpu.mem_map(0xc1400000,0x200000); cpu.mem_map(0x20000000,0x40000)
    for va,size in ((0x30100000,0x1000),(0x30000000,0x3000),(0x300f0000,0x1000),(0x21c00000,0x1000)): cpu.mem_map(va,size)
    cpu.reg_write(UC_ARM_REG_CPSR,0xa0000013)
    for index,register in enumerate(REGS[:13]): cpu.reg_write(register,0x12000000+index*0x101)
    cpu.reg_write(UC_ARM_REG_SP,ck.SP); cpu.reg_write(UC_ARM_REG_LR,ck.STOP)
    st={'invalid':[],'outsideWrites':[],'patchOutsideReads':[],'finished':False,'writes':0}
    def invalid(c,access,address,size,value,user): st['invalid'].append([access,hex(address),size,hex(c.reg_read(UC_ARM_REG_PC))]); return False
    def wr(c,access,address,size,value,user):
        st['writes']+=1
        if not any(lo<=address and address+size<=hi for lo,hi in ranges): st['outsideWrites'].append([hex(address),size,hex(c.reg_read(UC_ARM_REG_PC))]); c.emu_stop()
    def rd(c,access,address,size,value,user):
        pc=c.reg_read(UC_ARM_REG_PC)
        if 0x369d68<=pc<0x369d68+len(WRAP):
            allowed=[(0x369d68,0x369d68+len(WRAP)),(CTRL+0x4c,CTRL+0x4d),(EV,EV+4),(ck.SP-0x1000,ck.SP)]
            if not any(lo<=address and address+size<=hi for lo,hi in allowed):
                st['patchOutsideReads'].append([hex(address),size,hex(pc)]);c.emu_stop()
    cpu.hook_add(UC_HOOK_MEM_INVALID,invalid); cpu.hook_add(UC_HOOK_MEM_WRITE,wr)
    cpu.hook_add(ck.UC_HOOK_MEM_READ,rd)
    return cpu,st
def run(patched,mode,ev,time):
    ranges=[(0xc1400000,0xc1600000),(0x30000000,0x30003000),(0x30100000,0x30101000),(0x21c00000,0x21c01000),(ck.SP-0x1000,ck.SP+0x100)]
    cpu,st=machine(patched,ranges)
    cpu.mem_write(STATE,b'\x00'*0x100); put(cpu,STATE+0x38,time)
    put(cpu,CTRL+0x4c,mode); put(cpu,EV,ev)
    cpu.reg_write(UC_ARM_REG_R4,STATE); cpu.reg_write(UC_ARM_REG_R5,0xc14708d0)
    put(cpu,0x30100004,1199<<16); put(cpu,0x30100020,1000<<16); put(cpu,0x30100590,0x00070000)
    events=[]
    def rec(c,access,address,size,value,user):
        if address in (0x21c00014,0x21c00018): events.append((address,value&0xffffffff))
    cpu.hook_add(UC_HOOK_MEM_WRITE,rec)
    before={r:cpu.reg_read(r) for r in REGS}
    ck.execute(cpu,st,0x36567c,0x365688,ack=True,count=800000)
    after={r:cpu.reg_read(r) for r in REGS}
    return {'patched':patched,'mode':mode,'ev':ev,'time':time,'events':events,'r0':cpu.reg_read(UC_ARM_REG_R0),'before':before,'after':after,'state_time':struct.unpack('<I',cpu.mem_read(STATE+0x38,4))[0],'st':st}
if __name__=='__main__':
    import hashlib
    expected={r['section'].lstrip('.'):r['mappedSha256'] for r in json.loads((ROOT/'reports/reference-decode-results.json').read_text())['results'] if r['version']=='3.2-cn'}
    assert {n:hashlib.sha256(b).hexdigest() for n,b in [('text',ck.TEXT),('rodata',ck.RODATA),('data',ck.DATA)]}==expected
    rows=[]; failures=[]
    def check(cond,msg):
        if not cond: failures.append(msg); print('FAIL',msg)
    base=run(False,0,0,33333)
    print('BASELINE r0',hex(base['r0']),'cpsr',hex(base['after'][UC_ARM_REG_CPSR]),'events',len(base['events']))
    for mode in (0,2,3,4,5):
        r=run(True,mode,20,33333)
        ok_behavior=(r['r0']==base['r0'] and r['events']==base['events'])
        ok_stable=all(r['after'][x]==base['after'][x] for x in STABLE)
        ok_state=(r['state_time']==33333)
        ok_callers=all(r['after'][x]==r['before'][x] for x in (UC_ARM_REG_R2,UC_ARM_REG_R3,UC_ARM_REG_R12))
        check(ok_behavior and ok_stable and ok_state and ok_callers,f'non-M mode={mode}')
        rows.append({'kind':'non_m','mode':mode,'ev':20,'time':33333,'r0':hex(r['r0']),'behavior_same':ok_behavior,'stable_regs_same':ok_stable,'state_38_same':ok_state,'caller_saved_restored':ok_callers})
    for ev in (0,20,-20,50,-50,0x7fffffff,-0x80000000):
        r=run(True,1,ev,33333)
        ok_state=(r['state_time']==33333)
        ok_callers=all(r['after'][x]==r['before'][x] for x in (UC_ARM_REG_R2,UC_ARM_REG_R3,UC_ARM_REG_R12))
        ok_stable=all(r['after'][x]==base['after'][x] for x in STABLE)
        ok_behavior=(r['r0']==base['r0'] and r['events']==base['events']) if ev==0 else (r['events']!=base['events'])
        check(ok_state and ok_callers and ok_stable and ok_behavior,f'M ev={ev}')
        if ev!=0: print('M',ev,'r0',hex(r['r0']),'events',r['events'])
        rows.append({'kind':'m','mode':1,'ev':ev,'time':33333,'r0':hex(r['r0']),'events_changed':(r['events']!=base['events']),'stable_regs_same':ok_stable,'state_38_same':ok_state,'caller_saved_restored':ok_callers})
    for time in (1,250,33333,1300000,60000000):
        for ev in (20,-20):
            r=run(True,1,ev,time)
            ok_state=(r['state_time']==time)
            ok_callers=all(r['after'][x]==r['before'][x] for x in (UC_ARM_REG_R2,UC_ARM_REG_R3,UC_ARM_REG_R12))
            ok_stable=all(r['after'][x]==base['after'][x] for x in STABLE)
            check(ok_state and ok_callers and ok_stable,f'time={time} ev={ev}')
            rows.append({'kind':'time','mode':1,'ev':ev,'time':time,'r0':hex(r['r0']),'stable_regs_same':ok_stable,'state_38_same':ok_state,'caller_saved_restored':ok_callers})
    print('FAILURES',len(failures))
    result={
      'fixture':'Unicorn ARM926; original driver execution, modeled SPI ack; bounded wrapper reads',
      'patchManifestSha256':hashlib.sha256(MANIFEST_BYTES).hexdigest(),
      'wrapper_sha256':__import__('hashlib').sha256(WRAP).hexdigest(),
      'wrapper_bytes':len(WRAP),
      'hook_hex':HOOK.hex(),
      'baseline':{'r0':hex(base['r0']),'cpsr':hex(base['after'][UC_ARM_REG_CPSR]),'events':base['events'],'state_38':base['state_time']},
      'cases':rows,'failures':failures,
      'note':'Synthetic frame/MMIO; no camera; non-M comparison covers r4-r11/SP/LR/CPSR and r0/MMIO; r1-r3/ip are additionally restored.'
    }
    (ROOT/'reports/demo-exposure-native-validation-2026-10-29.json').write_text(json.dumps(result,ensure_ascii=False,indent=2)+chr(10),encoding='utf-8')
    if failures: raise SystemExit('Native demo validation failed')
