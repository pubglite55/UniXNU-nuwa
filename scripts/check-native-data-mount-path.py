#!/usr/bin/env python3
"""Host-check the actual native Data mount decision path with API fault injection.
The API stand-ins do not execute APFS or qualify hardware integration.
"""
from pathlib import Path
import subprocess,json,hashlib
root=Path(__file__).resolve().parents[1];out=root/'build/cpu-desktop/data-mount-path';out.mkdir(parents=True,exist_ok=True)
s=(root/'.cache/xnu-work/bsd/kern/kern_exec.c').read_text();start=s.index('static int\nnative_owner_data_prepare(');end=s.index('\n#endif',s.index('\ndone:',start))
function=s[start:end]
prelude=r'''
#include <assert.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <sys/types.h>
#include <errno.h>
#define XNU_NATIVE_RAM_BLOCK 1
#define XNU_OWNER_DATA_VOLUME_UUID "18AB5557-DC2D-469B-8758-855E60F5B0DF"
#define NODEV ((dev_t)-1)
#define NULLVP NULL
#define MNT_RDONLY 1
#define strlcpy(d,s,n) ((void)snprintf(d,n,"%s",s))
#include <stdio.h>
typedef void *proc_t;typedef uintptr_t user64_addr_t;
struct statfs {char f_fstypename[16];};struct fake {struct statfs s;};
typedef struct fake *vnode_t;typedef struct fake *mount_t;
struct mount_args {uintptr_t type,path;unsigned flags;uintptr_t data;};
int native_owner_data_status,native_owner_data_stage,native_owner_data_readonly;
dev_t native_owner_data_device;uint64_t native_owner_data_seed_base,native_owner_data_seed_size;
uint8_t native_owner_data_seed_sha256[32];char native_owner_data_device_path[64];
static int scenario,mounts;static struct fake object;
static int native_ram_block_volume_seed(const char *uuid,dev_t *dev,char *path,size_t n,uint64_t *base,uint64_t *bytes,uint8_t *hash){
 assert(!strcmp(uuid,XNU_OWNER_DATA_VOLUME_UUID));
 if(scenario==1)return 0;
 *dev=42;snprintf(path,n,"/dev/disk2s1");*base=0;*bytes=scenario==2?4097:0x80000000;memset(hash,0xa5,32);return 1;
}
static int copyout(const void *p,uintptr_t to,size_t n){if(scenario==8)return EFAULT;memcpy((void*)to,p,n);return 0;}
static int mount(proc_t p,struct mount_args *a,int32_t *result){
 (void)p;(void)result;++mounts;
 assert(!strcmp((char*)a->type,"apfs")&&!strcmp((char*)a->path,"/private/var")&&!a->flags);
 uintptr_t spec;memcpy(&spec,(void*)a->data,8);assert(!strcmp((char*)spec,"/dev/disk2s1"));
 return scenario==3?EACCES:0;
}
static void *vfs_context_current(void){return NULL;}
static int vnode_lookup(const char *p,int flags,vnode_t *v,void *ctx){(void)flags;(void)ctx;assert(!strcmp(p,"/private/var"));*v=&object;return scenario==4?ENOENT:0;}
static mount_t vnode_mount(vnode_t v){return v;}
static vnode_t vfs_devvp(mount_t m){return m;}
static dev_t vnode_specrdev(vnode_t v){(void)v;return scenario==5?43:42;}
static void vnode_put(vnode_t v){(void)v;}
static unsigned vfs_flags(mount_t m){(void)m;return scenario==6?MNT_RDONLY:0;}
static struct statfs *vfs_statfs(mount_t m){snprintf(m->s.f_fstypename,sizeof(m->s.f_fstypename),"%s",scenario==7?"hfs":"apfs");return &m->s;}
'''
main=r'''
int main(void){
 const int expected[]={0,ENOENT,EINVAL,EACCES,ENOENT,EINVAL,EINVAL,EINVAL,EFAULT};
 for(scenario=0;scenario<9;++scenario){
  uint8_t scratch[2048]={0};mounts=0;native_owner_data_stage=0;
  assert(native_owner_data_prepare(NULL,(uintptr_t)scratch)==expected[scenario]);
  assert(native_owner_data_status==expected[scenario]);
  if(scenario==0){assert(native_owner_data_stage==4&&mounts==1&&native_owner_data_device==42&&!native_owner_data_readonly);
   assert(native_owner_data_seed_base==0&&native_owner_data_seed_size==0x80000000);for(unsigned i=0;i<32;++i)assert(native_owner_data_seed_sha256[i]==0xa5);}
  if(scenario==1||scenario==2||scenario==8)assert(mounts==0);
 }
 puts("PASS: actual native mount path without md0; 8 provider/range/mount/copyout/device/readonly/filesystem refusal paths");
}
'''
(out/'test.c').write_text(prelude+function+main)
subprocess.run(['clang','-std=c11','-Wall','-Wextra','-Werror','-O1','-g','-fsanitize=address,undefined',str(out/'test.c'),'-o',str(out/'test')],check=True,timeout=60)
r=subprocess.run([str(out/'test')],check=True,text=True,capture_output=True,timeout=30)
(out/'report.json').write_text(json.dumps({'function_sha256':hashlib.sha256(function.encode()).hexdigest(),'passed':True,'cases':9,'apis_mocked':True,'actual_apfs':False,'hardware_observed':False},indent=2)+'\n');print(r.stdout,end='')
