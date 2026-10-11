/* host-test driver for device_auth.c: argv = seed mode (testrng | norng | default).
 * Builds MSG_1 twice, then processes one MSG_2 (hex) per stdin line. */
#include "device_auth.h"
#include "os/net/security/micro-ecc/uECC.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
static uint64_t s;
static int rng(uint8_t *d, unsigned n){ for(unsigned i=0;i<n;i++){ s=s*6364136223846793005ULL+1442695040888963407ULL; d[i]=(uint8_t)(s>>56);} return 1; }
static void hex(const char*l,const uint8_t*b,size_t n){printf("%s ",l);for(size_t i=0;i<n;i++)printf("%02x",b[i]);printf("\n");fflush(stdout);}
/* argv: seed mode   mode = testrng | norng | default (whatever random_source() picks) */
int main(int argc,char**argv){
  device_auth_state_t st; uint8_t m1[256], m2[512], key[16]; char line[2048];
  s=strtoull(argv[1],0,10);
  if(!strcmp(argv[2],"testrng")) uECC_set_rng(rng);
  if(!strcmp(argv[2],"norng"))   uECC_set_rng(NULL);
  for(int round=0; round<2; round++){
    memset(m1,0xEE,sizeof m1);
    int n=device_auth_build_msg1(&st,m1,sizeof m1);
    if(n<0){ int untouched=1; for(size_t i=0;i<sizeof m1;i++) if(m1[i]!=0xEE) untouched=0;
             printf("ERR1 %d untouched=%d\n",n,untouched); fflush(stdout); return 0; }
    hex(round? "MSG1B":"MSG1",m1,(size_t)n);
  }
  while(fgets(line,sizeof line,stdin)){ size_t L=strlen(line); while(L&&(line[L-1]=='\n'||line[L-1]=='\r'))line[--L]=0;
    size_t k=L/2; for(size_t i=0;i<k;i++){unsigned v;sscanf(line+2*i,"%02x",&v);m2[i]=(uint8_t)v;}
    int r=device_auth_process_msg2(&st,m2,k,key); if(r==0)hex("KEY",key,16); else {printf("ERR2 %d\n",r);fflush(stdout);} }
  return 0; }
