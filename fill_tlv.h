     // ***** // ***** // // ***** // ***** //
// ***** // ***** //          // ***** // ***** //
    // ***** // ***** // // ***** // ***** //

     // ***** // ***** // // ***** // ***** //
// ***** // ***** // TLV fill // ***** // ***** //
    // ***** // ***** // // ***** // ***** //

     // ***** // ***** // // ***** // ***** //
// ***** // ***** //          // ***** // ***** //
    // ***** // ***** // // ***** // ***** //

void fill_network_hash(struct network_hash * s_n_h,
                       unsigned char * network_hash){
  s_n_h-> type = TLV_TYPE_NET_HASH;
  s_n_h-> len = sizeof(struct network_hash) - TLV_HEADER_SIZE;
  memmove(s_n_h-> network_hash, network_hash, NETWORK_HASH_SIZE);
}

void fill_network_state_request(struct network_state_request * nsr){
  nsr-> type = TLV_TYPE_NET_STA_REQ;
  nsr-> len = 0;
}

void fill_node_state_request(struct node_state_request * nsr,
                                unsigned char * node_id){
  nsr-> type = TLV_TYPE_NODE_STA_REQ;
  nsr-> len = NODE_ID_SIZE;
  memmove(nsr-> node_id, node_id, NODE_ID_SIZE);
}












     // ***** // ***** //                  // ***** // ***** //
// ***** // ***** //                           // ***** // ***** //
    // ***** // ***** //                 // ***** // ***** //

     // ***** // ***** //                  // ***** // ***** //
// ***** // ***** // ajouter un TLV au message // ***** // ***** //
    // ***** // ***** //                 // ***** // ***** //

     // ***** // ***** //                  // ***** // ***** //
// ***** // ***** //                           // ***** // ***** //
    // ***** // ***** //                 // ***** // ***** //


//choses utiles?
unsigned char * fill_pad1(unsigned char * body){
  body[0] = 0;
  return body + 1;
}

unsigned char * fill_padN(unsigned char * body, unsigned char n){
  body[0] = 1;
  body[1] = n;
  return body + n + TLV_HEADER_SIZE;
}


//cela sont au moins utiles


//[size] en octets avec TLV_HEADER_SIZE
unsigned char * fill_TLV_in_body(unsigned char * body, void * tlv, ssize_t size){
  memmove(body, tlv, size);//generique
  return body + size;
}


unsigned char * fill_network_hash_in_body(unsigned char * body, 
                struct network_hash * n_hash){
  return fill_TLV_in_body(body, (void *) n_hash, sizeof(struct network_hash));
}

unsigned char * fill_network_state_request_in_body(unsigned char * body,
                            struct network_state_request * nsr){
  return fill_TLV_in_body(body, nsr, sizeof(struct network_state_request));
}


unsigned char * fill_node_hash_in_body(unsigned char * body, unsigned char * node_id,
       uint16_t seqno, unsigned char * node_hash){
  body[0] = TLV_TYPE_NODE_HASH;
  body[1] = sizeof(struct node_hash) - TLV_HEADER_SIZE;

  ssize_t tmp = 2;
  memmove(body + tmp, node_id, NODE_ID_SIZE); tmp += NODE_ID_SIZE;
  put_uint16_in_char(body + tmp, seqno); tmp += SEQNO_SIZE;
  memmove(body + tmp, node_hash, NODE_HASH_SIZE); tmp += NODE_HASH_SIZE;

  return body + sizeof(struct node_hash);
}



//ignore le [seqno] dans [node]
//et utilise a la place [use_seqno]
unsigned char * fill_node_state_in_body(unsigned char * body, struct node_state * node,
                             uint16_t use_seqno){

  unsigned char * data_place = fill_node_hash_in_body
                                       (body, node-> node_id, use_seqno, node-> node_hash);

  //Il faut le faire apres: fill_node_hash_in_body() change aussi!
  body[0] = TLV_TYPE_NODE_STA;
  body[1] = sizeof_node_state() - DATA_MAX_SIZE + node-> datalen - TLV_HEADER_SIZE;

  memmove(data_place, node-> data, node-> datalen);

  return data_place + node-> datalen;
}



unsigned char * fill_node_state_request_in_body
                   (unsigned char * body, struct node_state_request * nsr){
  return fill_TLV_in_body(body, nsr, sizeof(struct node_state_request));
}


unsigned char * fill_neighbour_in_body(unsigned char * body,
                                       unsigned char *nei_ip, uint16_t nei_port){

  body[0] = TLV_TYPE_NEI;
  body[1] = sizeof(struct neighbour) - TLV_HEADER_SIZE;

  int tmp = TLV_HEADER_SIZE;
  memmove(body + tmp, nei_ip, IP_SIZE); tmp += IP_SIZE;
  put_uint16_in_char(body + tmp, nei_port); tmp += PORT_SIZE;

  return body + tmp;
}

unsigned char * fill_neighbour_request_in_body(unsigned char * body){
  body[0] = TLV_TYPE_NEI_REQ;
  body[1] = 0;
  return body + sizeof(struct neighbour_request);
}

