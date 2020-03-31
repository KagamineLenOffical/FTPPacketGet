#include <pcap/pcap.h>
#include <cstdio>
#include <iostream>
#include <time.h>
#include <cstring>
#include <cstdlib>
#include <map>
#define uchar unsigned char
#define ull unsigned long long
#define uint unsigned int
using namespace std;
char errBuf[PCAP_ERRBUF_SIZE],*devStr;
FILE *out;
bpf_u_int32  netp=0,maskp=0;//本地ip地址和掩码
pcap_t *pcap_handle=NULL;
map<ull,int> shost,dhost;
map<uint,int> sIP,dIP;

uint ip_to_value(uchar* src){
    uint ret=0;
    for(int i=0;i<4;i++){
        ret<<=8;
        ret+=src[i];
    }
    return ret;
}
void value_to_ip(uint src,uchar* dst){
    for(int i=3;i>=0;i--){
        dst[i]=src&(0xff);
        src>>=8;
    }
    return;
}
ull mac_to_value(uchar *src){
    ull ret=0;
    for(int i=0;i<6;i++){
        ret<<=8ll;
        ret+=(ull)src[i];
    }
    return ret;
}
void value_to_mac(ull src,uchar *dst){
    for(int i=5;i>=0;i--){
        dst[i]=src&(ull)(0xff);
        src>>=8ll;
    }
    return;
}
struct ether_header{
    uchar ether_dhost[6]; //目的mac
    uchar ether_shost[6];//源mac
    unsigned short ether_type;//以太网类型
};
struct ip_header{
    int head_len:4;
    int version:4;
    uchar tos:8;
    int tot_len:16;
    int ident:16;
    int flags:16;
    uchar ttl:8;
    uchar proto:8;
    int checksum:16;
    uchar sourceIP[4];
    uchar destIP[4];
};
struct tcp_header{
    unsigned short srcPort;
    unsigned short desPort;
    int seq_num;
    int ack_num;
    uchar head_len:8;//长度4位加上保留位4位
    uchar flags:8;//保留位和标记位
    unsigned short win_size;//窗口大小
    unsigned short checksum;
    unsigned short urgent_pointer;
};
time_t time_s,time_e;

int now_process;  //0代表还未建立连接 1 表示建立三次握手成功 2 代表用户名已认证 101代表密码认证成功 100代表密码认证失败
int src_ip,dst_ip;
char *resp[]={"220","331","230","530"}; //220 代表建立连接成功 331 代表用户名识别 230代表密码正确 530代表密码错误
char *cmd[]={"USER","PASS"};
char pass[100],user[100];
//检查头部命令或参数
bool check_info_head(char *info,char *code){
    while((*code)!='\0'){
        if((*info)!=(*code))return 0;
        info++;code++;
    }
    return 1;
}

//回调函数
void callback(uchar *argument,const pcap_pkthdr *packet_header,
        const uchar *packet_content){

    out=fopen("1.csv","a");
    int ether_len=sizeof(ether_header);
    if(out==NULL){
        exit(-1);
    }
    ether_header *Ether_header;
    //printf("\n");
    //printf("%s",ctime((time_t *)&(packet_header->ts.tv_sec)));


    //将时间转换为字符串 读取长度和捕获长度
    Ether_header=(ether_header *)packet_content;//获取包头
    if(packet_header->len>=14){
        ip_header *Ip_header=(ip_header*)(packet_content+ether_len);
        int ip_len=Ip_header->head_len<<2;
        if(Ip_header->proto==6){
            tcp_header *Tcp_header=(tcp_header*)(packet_content+ether_len+ip_len);
            int tcp_len=Tcp_header->head_len>>2;
//            printf("%d %d %d\n",ether_len,ip_len,tcp_len);
//            printf("SrcPort:%d->DestPort:%d\n",Tcp_header->srcPort,Tcp_header->desPort);

            char info[1500];
            int len=0;
            memset(info,0,sizeof(info));
            if(packet_header->len>1500)return;
            for(int i=ether_len+ip_len+tcp_len;i<packet_header->len-2;i++){ //获取报文内容 -2为了去除\r\n
                info[len++]=*(packet_content+i);
            }
            info[len]='\0';
            //输出包内信息
            printf("%s\n",info);
            if(check_info_head(info,resp[0])){  //resp=220
                now_process=1;
                src_ip=ip_to_value(Ip_header->sourceIP); //服务器地址
                dst_ip=ip_to_value(Ip_header->destIP);//客户端地址         //只检测最后一次成功建立的连接
                memset(pass,0,sizeof(pass));
                memset(user,0,sizeof(user));
            }
            else if(check_info_head(info,cmd[0])&&now_process==1){ //cmd=USER
                int n_src_ip=ip_to_value(Ip_header->destIP);
                int n_dst_ip=ip_to_value(Ip_header->sourceIP);
                if(src_ip==n_src_ip&&dst_ip==n_dst_ip){   //检验是最后一次连接的ip
                    for(int i=5;i<len;i++){
                        user[i-5]=info[i];
                    }
                }
            }
            else if(check_info_head(info,resp[1])){ //resp=331
                int n_dst_ip=ip_to_value(Ip_header->destIP);
                int n_src_ip=ip_to_value(Ip_header->sourceIP);
                if(src_ip==n_src_ip&&dst_ip==n_dst_ip){
                    now_process=2;
                }
            }
            else if(check_info_head(info,cmd[1])&&now_process==2){ //cmd=PASS
                int n_src_ip=ip_to_value(Ip_header->destIP);
                int n_dst_ip=ip_to_value(Ip_header->sourceIP);
                if(src_ip==n_src_ip&&dst_ip==n_dst_ip){

                    for(int i=5;i<len;i++){
                        pass[i-5]=info[i];
                    }
                }
            }
            else if(check_info_head(info,resp[2])){  //resp=230
                int n_dst_ip=ip_to_value(Ip_header->destIP);
                int n_src_ip=ip_to_value(Ip_header->sourceIP);
                if(src_ip==n_src_ip&&dst_ip==n_dst_ip){
                    now_process=5;
                }
            }
            else if(check_info_head(info,resp[3])){  //resp=530
                int n_dst_ip=ip_to_value(Ip_header->destIP);
                int n_src_ip=ip_to_value(Ip_header->sourceIP);
                if(src_ip==n_src_ip&&dst_ip==n_dst_ip){
                    now_process=4;
                }
            }
            if(now_process&4){
                time_t t=packet_header->ts.tv_sec;
                tm *_time=localtime(&t);
                char timeStr[128];
                strftime(timeStr,128,"%F %T,",_time);
                fprintf(out,"%s",timeStr);
                //客户端信息
                fprintf(out,"%02X-%02X-%02X-%02X-%02X-%02X,",Ether_header->ether_dhost[0],
                       Ether_header->ether_dhost[1],Ether_header->ether_dhost[2],Ether_header->ether_dhost[3],
                       Ether_header->ether_dhost[4],Ether_header->ether_dhost[5]);
                fprintf(out,"%d.%d.%d.%d,",Ip_header->destIP[0],Ip_header->destIP[1],
                       Ip_header->destIP[2],Ip_header->destIP[3]);
                //服务器信息
                fprintf(out,"%02X-%02X-%02X-%02X-%02X-%02X,",Ether_header->ether_shost[0],
                       Ether_header->ether_shost[1],Ether_header->ether_shost[2],Ether_header->ether_shost[3],
                       Ether_header->ether_shost[4],Ether_header->ether_shost[5]);
                fprintf(out,"%d.%d.%d.%d,",Ip_header->sourceIP[0],Ip_header->sourceIP[1],
                        Ip_header->sourceIP[2],Ip_header->sourceIP[3]);
                fprintf(out,"%s,",user);
                fprintf(out,"%s,",pass);
                if(now_process&1){
                    fprintf(out,"SUCCEED\n");
                }
                else fprintf(out,"FAILED\n");
                now_process=0;
            }

//            printf("\n");
//            printf("%s\n",packet_content+ip_len+tcp_len+ether_len);
        }
/*

        fprintf(out,"%d.%d.%d.%d,",Ip_header->sourceIP[0],Ip_header->sourceIP[1],
               Ip_header->sourceIP[2],Ip_header->sourceIP[3]);


        fprintf(out,"%d.%d.%d.%d,",Ip_header->destIP[0],Ip_header->destIP[1],
               Ip_header->destIP[2],Ip_header->destIP[3]);


        uint sip_v=ip_to_value(Ip_header->sourceIP),dip_v=ip_to_value(Ip_header->destIP);
        ull shost_v=mac_to_value(Ether_header->ether_shost);
        ull dhost_v=mac_to_value(Ether_header->ether_dhost);
        if(sIP.find(sip_v)==sIP.end()){
            sIP[sip_v]=packet_header->len;
        }
        else sIP[sip_v]+=packet_header->len;
        if(dIP.find(dip_v)==dIP.end()){
            dIP[dip_v]=packet_header->len;
        }
        else dIP[dip_v]+=packet_header->len;
        if(shost.find(shost_v)==shost.end()){
            shost[shost_v]=packet_header->len;
        }
        else shost[shost_v]+=packet_header->len;
        if(dhost.find(dhost_v)==dhost.end()){
            dhost[dhost_v]=packet_header->len;
        }
        else dhost[dhost_v]+=packet_header->len;
//        printf("%lld %lld\n",shost_v,dhost_v);
*/
    }
    //原流量统计部分
    /*
    fprintf(out,"%d\n",packet_header->len);
    if(packet_header->len>1024)printf("流量过大！\n");
    time(&time_e);
    int ptime=(int)((time_e-time_s));
    printf("%d\n",ptime);
    if(ptime>=10){
        time(&time_s);
        fprintf(out,"src mac:\n");
        for(map<ull,int>::iterator iter=shost.begin();iter!=shost.end();iter++){
            uchar mac[6];
            memset(mac,0,sizeof(mac));
            value_to_mac(iter->first,mac);
            fprintf(out,"%02X-%02X-%02X-%02X-%02X-%02X,",mac[0],mac[1],mac[2],
                mac[3],mac[4],mac[5]);
            fprintf(out,"%d\n",iter->second);
        }
        fprintf(out,"dst mac:\n");
        for(map<ull,int>::iterator iter=dhost.begin();iter!=dhost.end();iter++){
            uchar mac[6];
            memset(mac,0,sizeof(mac));
            value_to_mac(iter->first,mac);
            fprintf(out,"%02X-%02X-%02X-%02X-%02X-%02X,",mac[0],mac[1],mac[2],
                    mac[3],mac[4],mac[5]);
            fprintf(out,"%d\n",iter->second);
        }
        fprintf(out,"src ip:\n");
        for(map<uint,int>::iterator iter=sIP.begin();iter!=sIP.end();iter++){
            uchar ip[4];
            memset(ip,0,sizeof(ip));
            value_to_ip(iter->first,ip);
            fprintf(out,"%d.%d.%d.%d,",ip[0],ip[1],ip[2],ip[3]);
            fprintf(out,"%d\n",iter->second);
        }
        fprintf(out,"dst ip:\n");
        for(map<uint,int>::iterator iter=dIP.begin();iter!=dIP.end();iter++){
            uchar ip[4];
            memset(ip,0,sizeof(ip));
            value_to_ip(iter->first,ip);
            fprintf(out,"%d.%d.%d.%d,",ip[0],ip[1],ip[2],ip[3]);
            fprintf(out,"%d\n",iter->second);
        }
    }
     */
    fclose(out);
}
int main(){

    //获取设备
    devStr=pcap_lookupdev(errBuf);
    if(devStr==NULL){
        printf("error to find device:%s\n",errBuf);
        exit(-1);
    }


    //获取第一个设备的信息
    int ret=0;
    ret=pcap_lookupnet(devStr,&netp,&maskp,errBuf);
    if(ret==-1){
        printf("error:%s",errBuf);
        exit(-1);
    }

    time(&time_s);
    //打开网络接口
    pcap_handle=pcap_open_live(devStr,65535,1,0,errBuf);
    //获取设备Devstr[0] 包最长长度 开启混杂模式 一直等待包到来

    //创建文件



    if(pcap_loop(pcap_handle,-1,callback,NULL)<0){
        //-1指循环到发生错误 callback为回调函数
        printf("transmission error\n");
    }
    pcap_close(pcap_handle);
    return 0;
}
