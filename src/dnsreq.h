/*
struct dns_header {
  unsigned id :16;
  unsigned qr: 1;
  unsigned opcode: 4;
  unsigned aa: 1;
  unsigned tc: 1;
  unsigned rd: 1;
  unsigned ra: 1;
  unsigned unused :1;
  unsigned ad: 1;
  unsigned cd: 1;
  unsigned rcode :4;
  unsigned qdcount :16;
  unsigned ancount :16;
  unsigned nscount :16;
  unsigned arcount :16;
};

*/

struct dns_header
{ 
    unsigned short id;       // identification number 
    unsigned char rd :1;     // recursion desired 
    unsigned char tc :1;     // truncated message 
    unsigned char aa :1;     // authoritive answer 
    unsigned char opcode :4; // purpose of message 
    unsigned char qr :1;     // query/response flag 
    unsigned char rcode :4;  // response code 
    unsigned char cd :1;     // checking disabled 
    unsigned char ad :1;     // authenticated data 
    unsigned char z :1;      // its z! reserved 
    unsigned char ra :1;     // recursion available 
    unsigned short qdcount;  // number of question entries
    unsigned short ancount; // number of answer entries 
    unsigned short authcount; // number of authority entries 
    unsigned short addcount; // number of resource entries

};
