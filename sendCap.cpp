/* send sctp packet for test*/
/* Copyright 2010-2022 . */
/*
modification history
--------------------
2010-12-08,jimx update
2010-08-1,jimx create
*/
#include <sys/socket.h>
#include <stdio.h>
#include <sys/time.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>
#include <iostream.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <pthread.h>

#include <netinet/if_ether.h>
#include <linux/if_packet.h>
#include <linux/if.h>

#include <dirent.h>
#include <string.h>
#include <time.h>



using namespace std;


typedef  unsigned char		UINT1;
typedef  unsigned short		UINT2;
typedef  unsigned int		UINT4;

typedef  unsigned int bpf_u_int32;
typedef  int bpf_int32;
typedef  unsigned short u_short;
/*excerpt the following two struct from internet by jimx*/
struct   pcap_file_header   { 
          bpf_u_int32   magic;         //Libpcap   magic   number. 
          u_short   version_major;   //Libpcap   major   version. 
          u_short   version_minor;   //Libpcap   minor   version.   
          bpf_int32   thiszone;   //Gmt   to   local   correction.   
          bpf_u_int32   sigfigs;     //Accuracy   of   timestamps.       
          bpf_u_int32   snaplen;       //Length   of   the   max   saved   portion   of   each   packet.     
          bpf_u_int32   linktype;     //Data   link   type   (DLT_*).   See   win_bpf.h   for   details.     
}; 

struct   pcap_pkthdr   { 
          struct   timeval   ts;     //time   stamp           
          bpf_u_int32   caplen;   //length   of   portion   present 
          bpf_u_int32   len;         //length   this   packet   (off   wire)   
  };
#define PCAP_FILE_HDR_SIZE sizeof(pcap_file_header)
#define PCAP_PKT_HDR_SIZE  sizeof(pcap_pkthdr)
#define CAPP_FILE_SIZE_LIMIT 5*1024*1024
const char pcap_file_hdr[]={0xd4,0xc3,0xb2,0xa1,0x02,0x00,0x04,0x00,0x00,0x00,0x00,0x00,
					   0x00,0x00,0x00,0x00,0xff,0xff,0x00,0x00,0x01,0x00,0x00,0x00};

/*******************global var area*/
unsigned int capFileCount;
unsigned long pkt_statis;
int sockfd;
unsigned int amount_pt ;


static unsigned long capNum = 0;

/********************code area*/
#define DFLT_NETWORK_DEV	"eth0"
int rawRocketInit(char* nwDev)
{
   struct ifreq ifr;
   int sock;
   memset(&ifr, 0x0, sizeof(struct ifreq));

   if((sock = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) < 0)
   {
       perror(">>fail to creat raw socket");
       exit(0);
   }

   memcpy(ifr.ifr_name, nwDev,sizeof(ifr.ifr_name));//指定网卡 eth1/eth2/...
   if(ioctl(sock,SIOCGIFINDEX,&ifr) !=0)
   {
       perror(">>fail to assign network card");
       exit(0);
   }

 	struct sockaddr_ll addr;
	memset(&addr,0,sizeof(sockaddr_ll));

	addr.sll_family =AF_PACKET;
	addr.sll_ifindex = ifr.ifr_ifindex;
	addr.sll_protocol = htons(ETH_P_IP);

	if(bind(sock,(struct sockaddr *)&addr,sizeof(addr))!=0)
	{
		perror(">>bind fail");
		exit(0);
	}
#if 0
   //set promisc mode,can be used for Rcv
    ifr.ifr_flags |= IFF_PROMISC;
   if(ioctl(sock, SIOCSIFFLAGS, &ifr) == -1)
   {
       perror(">>fail to set sock IFF_PROMISC");
       exit(0);
   }
#endif   
   return sock;
}


//取得当前时间，表示为20100725_0925(精确至分)
char* getTimeString()
{
	static char timeStr[32];
	time_t timep;
	struct tm *ptm;
	
	time(&timep);
	ptm = localtime(&timep);
	sprintf(timeStr,"%.4d%.2d%.2d_%.2d%.2d%.2d%",\
		ptm ->tm_year + 1900, ptm ->tm_mon + 1, ptm ->tm_mday,\
		ptm ->tm_hour, ptm ->tm_min, ptm ->tm_sec);	
	return timeStr;
}

//用于生成pcap格式的文件
static FILE* fpOut=NULL;
void writeCapFile(char* inbuf,int num)
{
	static char sbuf[64];
	static int newf=1;
	int nmemb;
	
	if(newf) {
		sprintf(sbuf,"%s.capp",getTimeString());
		for(nmemb=1;//文件已存在，则添加下标来创建
			!access(sbuf,R_OK);
			nmemb++)
		{
			printf(">>file exist,creat new file with subscript\n");
			sprintf(sbuf,"%s_%d.capp",getTimeString(),nmemb);
		}
		if(!fpOut) fpOut=fopen(sbuf,"a+");
		//write file header when creats it
		fwrite(pcap_file_hdr,PCAP_FILE_HDR_SIZE,1,fpOut);
		newf=0;
	}
	if(!fpOut) fpOut=fopen(sbuf,"a+");
	nmemb=fwrite(inbuf,sizeof(char),num,fpOut);
	printf(">>write %d byte to %s\n",nmemb,sbuf);
	//fseek(fpCapp, 0, SEEK_END);
	if(ftell(fpOut) > CAPP_FILE_SIZE_LIMIT) {
		fclose(fpOut);
		fpOut=NULL;
		newf=1;
	}
	return;
}


void readCapFile(FILE* pFile)
{
//	static unsigned long capNum = 0;
	long offset_t;
	long off_pos;
	char readbuf[2048];
	pcap_pkthdr *p_ih=NULL;
	UINT4 pkt_idx;
	int nbyte;
	int tmp;
	//
 	fseek(pFile, 0, SEEK_END);
	if((offset_t=ftell(pFile)) < PCAP_FILE_HDR_SIZE){
		printf(">>Err:this file is too small to be a cap file\n");
		return;
	}
	//read file header
	fseek(pFile, 0, SEEK_SET);
	off_pos=0;		
    if(1 != fread(readbuf, PCAP_FILE_HDR_SIZE, 1, pFile))
    {
		perror(">>read packet head error");
		return;
	}
	for(int i=0;i<PCAP_FILE_HDR_SIZE;i++) {
		if(readbuf[i]!=pcap_file_hdr[i]){
			printf(">>Err:unknown cap header\n");
			return;
		}
	}
	
	//printf(">>reading packets...from this %d size file\n", offset_t);
	//read data
	for(pkt_idx = 0,off_pos += PCAP_FILE_HDR_SIZE; 
		off_pos<offset_t; 
		pkt_idx++) 
	{	
		pkt_statis++;
		fseek(pFile, off_pos, SEEK_SET);
		fread(readbuf, PCAP_PKT_HDR_SIZE, 1, pFile);
		p_ih=(pcap_pkthdr *)readbuf;
		off_pos += PCAP_PKT_HDR_SIZE;
		fseek(pFile, off_pos, SEEK_SET);
		fread(readbuf+PCAP_PKT_HDR_SIZE, p_ih->caplen, 1, pFile);
		off_pos += p_ih->caplen;
		if (0 == (pkt_idx % amount_pt)) usleep(1);//延时，避免cpu占用太高
		//send packet
#if 1
		nbyte = sendto(sockfd,(char *)(readbuf+PCAP_PKT_HDR_SIZE),p_ih->caplen,0,NULL,0);
#else	//with frequence number
		tmp = PCAP_PKT_HDR_SIZE + p_ih->caplen;
		readbuf[tmp] = (char)(pkt_statis>>24);
		readbuf[tmp+1] = (char)(pkt_statis>>16);
		readbuf[tmp+2] = (char)(pkt_statis>>8);
		readbuf[tmp+3] = (char)(pkt_statis);
		
		nbyte = sendto(sockfd,(char *)(readbuf+PCAP_PKT_HDR_SIZE),p_ih->caplen + 4,0,NULL,0);
#endif
		if (-1 ==nbyte) perror("sendto fail");
		else {
			//printf(">>the pkt idx=%d len=%d,send %d bytes ok\n",pkt_idx,p_ih->caplen,nbyte);
			capNum++;
		}
	}
}


int searchCapFile(char* pFilename)
{
	FILE *pFile=NULL;
	int optIdx;
	int ret=0;
	char* p_ch=NULL;
	if(!(pFile=fopen(pFilename,"r")))
	{
	 printf(">>fail to open file>%s\n\n",pFilename);
	 return -1;
	}
	printf(">> at %s open file>%s\n",getTimeString(),pFilename);
	p_ch = strrchr(pFilename,'.');
	if(NULL==p_ch || strcmp(p_ch,".cap")){
		printf(">>not .cap file,close&skip\n\n");
		if (pFile) fclose(pFile);
		return -1;
	}
	capFileCount++;
	//sleep(1);//added by wangxx 20100907
	readCapFile(pFile);
	if (pFile) fclose(pFile);
	return ret;
}
int searchInDir(char* path)
{
	DIR* dir=NULL;
	struct dirent *pdirent=NULL;
	char path_str[256];
	int ret;
	
	if(!(dir= opendir(path))){
		perror(">>open as a dir fail");
		ret = searchCapFile(path);
		return ret;
	}
	while(pdirent=readdir(dir)){
		if (0 == strcmp(pdirent->d_name, ".") ||0 == strcmp(pdirent->d_name, ".."))
			continue;

		if (DT_REG == pdirent->d_type) {//普通文件
			sprintf(path_str,"%s/%s", path, pdirent->d_name);
			searchCapFile(path_str);
		}
		if (DT_DIR == pdirent->d_type) {//普通目录
			printf(">>find sub dir>%s\n",pdirent->d_name);
			sprintf(path_str,"%s/%s", path, pdirent->d_name);
			searchInDir(path_str);
		}
	}
	if(dir) closedir(dir);
	return 0;
}

//发送数据包,从cap文件读出发送，或(从txt读取asscii)
int main(int argc, char ** argv)
{
	char sbuf[32];
	//init raw socket
	sprintf(sbuf,"%s",DFLT_NETWORK_DEV);
	if(argv[2] && strlen(argv[2])) {
		memcpy(sbuf,argv[2],sizeof(sbuf));
	}
	printf(">>appointed network card>%s\n",sbuf);
	sockfd=rawRocketInit(sbuf);
	amount_pt = 100;
	if (argv[3] && (atoi(argv[3]))) {
		amount_pt = atoi(argv[3]);
	}
	printf(">>set speed:sleep a while per %u packets.\n",amount_pt);
	if (access(argv[1],R_OK)) {
		printf(">>failed to access path>%s,pls check input.\n\n",argv[1]);
		return 0;
	}
	//for(;;)//repeat
	capFileCount=0;
	pkt_statis=0;
	printf(">>Begin time:%s\n",getTimeString());
	if(searchInDir(argv[1])){
		return 0;
	}
	//printf("capNum: %d\n", capNum);
	if (fpOut) fclose(fpOut);
	printf(">>End time:%s\n",getTimeString());
	printf(">>have searched in %u *.cap files,packets amount:%u\n", capFileCount,pkt_statis);
	printf(">>Mission complete!\n");
	return 0;
}


