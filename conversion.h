     // ***** // ***** //               // ***** // ***** //
// ***** // ***** //                        // ***** // ***** //
    // ***** // ***** //              // ***** // ***** //

     // ***** // ***** //               // ***** // ***** //
// ***** // ***** // conversion des donnees // ***** // ***** //
    // ***** // ***** //              // ***** // ***** //

     // ***** // ***** //               // ***** // ***** //
// ***** // ***** //                        // ***** // ***** //
    // ***** // ***** //              // ***** // ***** //

//body length du head, port, seqno
//il faut reflechir un peu ...
//soit char: 2 1
//tmp 00000000 00000000:   00000000 00000010 -> 
//    00000010 00000000 -> 00000010 00000001 ok

#define OCTET 8
uint16_t char_to_int16(unsigned char * buf){
  uint16_t tmp;
  tmp = buf[0];
  tmp = (uint16_t) (tmp << OCTET);
  tmp += buf[1];
  if(DEBUG_SMALL_DETAIL) printf("%u %u %u\n", buf[0], buf[1], tmp);
  return tmp;
}


//il faut reflechir un peu ...
//[0][1] pour 00000010 00000001: [00000010][00000001]
//[0]: 00000010 00000001 -> 00000000 00000010 ok
//[1]: 00000010 00000001 -> 00000001 00000000 -> 00000000 000000001 ok

//il ajoute exactement la valeur u dans char*
void put_uint16_in_char(unsigned char * s, uint16_t u){

  s[0] = (unsigned char) (u >> OCTET);
  s[1] = (unsigned char) (((uint16_t) u << OCTET) >> OCTET);
}





void fill_struct_addr(struct sockaddr_in6 * to_fill, unsigned char * ip, uint16_t port){
  memmove(to_fill-> sin6_addr.s6_addr, ip, IP_SIZE);
  to_fill-> sin6_port = htons(port);
}


unsigned char get_tlv_type(unsigned char * tlv){
  return tlv[0];
}

unsigned char get_tlv_len(unsigned char * tlv){
  return tlv[1];
}

//"in" pour la valeur dans le champs [len] du tlv
//retourne le minimum du len pour le tlv
unsigned char tlv_minimum_len_in_expected(unsigned char tlv_type){
  //0 a 9
  unsigned char tlv_size[10] = {0, 0, 0, IP_SIZE + PORT_SIZE, NETWORK_HASH_SIZE,
        0, NODE_ID_SIZE + SEQNO_SIZE + NODE_HASH_SIZE, NODE_ID_SIZE,
           NODE_ID_SIZE + SEQNO_SIZE + NODE_HASH_SIZE, 0};

  if(tlv_type > 10)
    return tlv_size[tlv_type];

  return 0;
}

//"in" pour la valeur dans le champs [len] du tlv
int is_bad_tlv_len_in(unsigned char tlv_type, unsigned char tlv_len_in){
  return tlv_minimum_len_in_expected(tlv_type) > tlv_len_in;
}





//si [a] < [b] : -1
//si [a] > [b] : 1
//si [a] == [b] : 0
int compare_node_id(unsigned char * a, unsigned char * b){
  for(int i = 0; i < NODE_ID_SIZE; i++){
    if(a[i] < b[i])
      return -1;

    if(a[i] > b[i])
      return 1;
  }
  return 0;
}


//si [c1] == [c2] : retourne 0
//sinon 1
int is_same_aux(unsigned char * c1, unsigned char * c2, ssize_t len){
  for(int i = 0; i < len; i++)
    if(c1[i] != c2[i]){
      return 0;
    }
  return 1;
}


//si [nh1] == [nh2] : retourne 0
//sinon 1
int is_different_network_hash(unsigned char * nh1, unsigned char * nh2){
  return is_same_aux(nh1, nh2, NETWORK_HASH_SIZE) == 0;
}


//comparaison
#define MOD_SEQNO 65536
int compare_seqno(uint16_t a, uint16_t b){
  if(a == b){
    return 0;
  }
  
  uint32_t Paul = (MOD_SEQNO + b - a) % MOD_SEQNO;
  uint32_t Gudule = (MOD_SEQNO + a - b) % MOD_SEQNO;
  if(DEBUG_SMALL_DETAIL) printf("********** Compare P G dist: %u %u\n", Paul ,Gudule);
  if(Paul < Gudule) return -1;
  if(Paul > Gudule) return 1;
  return 0;
}

int is_same_node_id(unsigned char * n1, unsigned char * n2){
  return is_same_aux(n1, n2, NODE_ID_SIZE);
}


int is_same_node_hash(unsigned char * n1, unsigned char * n2){
  return is_same_aux(n1, n2, NODE_HASH_SIZE);
}





//etre perdu:
uint16_t predict_next_loss(uint16_t current){
  uint16_t tmp = current;

  for(int i = 1; i <= 65536; i++){

    for(int j = 0; j < 6; j++)//comparer avec les 5 suivant
      if(compare_seqno(current + j, htons(tmp)) == -1 && htons(tmp) > current) break;

    tmp += 1;
  }
  return tmp + 1;
}

