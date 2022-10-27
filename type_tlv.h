     // ***** // ***** //       // ***** // ***** //
// ***** // ***** //                 // ***** // ***** //
    // ***** // ***** //       // ***** // ***** //

     // ***** // ***** //       // ***** // ***** //
// ***** // ***** // les jolies TLV // ***** // ***** //
    // ***** // ***** //       // ***** // ***** //

     // ***** // ***** //       // ***** // ***** //
// ***** // ***** //                 // ***** // ***** //
    // ***** // ***** //       // ***** // ***** //

struct neighbour_request { 
  unsigned char type;
  unsigned char len;
} neighbour_request;


struct neighbour { 
  unsigned char type;
  unsigned char len;
  unsigned char ip[IP_SIZE];//aussi des char
  unsigned char port[PORT_SIZE];
} neighbour;


struct network_hash {
  unsigned char type;
  unsigned char len;
  unsigned char network_hash[NETWORK_HASH_SIZE];
} network_hash;


struct network_state_request {
  unsigned char type;
  unsigned char len;
} network_state_request;


struct node_hash {
  unsigned char type;
  unsigned char len;
  unsigned char node_id[NODE_ID_SIZE];
  unsigned char seqno[SEQNO_SIZE];
  unsigned char node_hash[NODE_HASH_SIZE];
} node_hash;


struct node_state_request {
  unsigned char type;
  unsigned char len;
  unsigned char node_id[NODE_ID_SIZE];
} node_state_request;


struct node_state {
  unsigned char type;
  unsigned char len;
  unsigned char node_id[NODE_ID_SIZE];
  unsigned char seqno[SEQNO_SIZE];
  unsigned char node_hash[NODE_HASH_SIZE];
  char data[DATA_MAX_SIZE];
  unsigned char datalen;//SEULEMENT POUR NOUS, NE PAS ENVOYER CECI (aussi pour sizeof())
} node_state;


ssize_t sizeof_node_state(){
  //Quand sizeof(struct node_state) ne compte pas [unsigned char datalen]
  //return sizeof(struct node_state) - sizeof(unsigned char);//normalement

  //comme c'est une bizarrerie: on ne compte pas sur sizeof()
  //meme si sizeof donne la valeur que l'on veut

  return TLV_HEADER_SIZE+NODE_ID_SIZE+SEQNO_SIZE+NODE_HASH_SIZE+DATA_MAX_SIZE;//ok
}

struct warning {
  unsigned char type;
  unsigned char len;
  unsigned char message[WARNING_MSG_SIZE];//c'est notre limitation
} warning;

