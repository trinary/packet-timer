
struct dns_header {
  unsigned id :16;
  unsigned qr: 1;
  unsigned opcode: 4;
  unsigned aa: 1;
  unsigned tc: 1;
  unsigned rd: 1;
  /* byte boundry */
  unsigned ra: 1;
  unsigned unused :1;
  unsigned ad: 1;
  unsigned cd: 1;
  unsigned rcode :4;
  /* byte boundry */
  unsigned qdcount :16;
  unsigned ancount :16;
  unsigned nscount :16;
  unsigned arcount :16;
};
