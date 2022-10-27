#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <netdb.h>
#include <err.h>
#include <errno.h>
#include <time.h>
#include <sys/time.h>

#include "sha.h"

//si il faut debug
int debug = 1;//generique

//boucle du main
#define DEBUG_BIG_WHILE_BOUCLE 0

#define DEBUG_MAGIC_TREATMENT 0
#define DEBUG_MAGIC_TREATMENT_VERBOSE 0
#define DEBUG_MAGIC_TREATMENT_NET_HASH 0
#define DEBUG_MAGIC_TREATMENT_BAD_ONLY 0



#define DEBUG_MESSAGE_RECEVED 0
#define DEBUG_MESSAGE_RECEVED_ONLY 0
#define DEBUG_MESSAGE_SEND 0
#define DEBUG_MESSAGE_SEND_ONLY 0
#define DEBUG_MESSAGE_SEND_NODE_STATE_ONLY 0

#define DEBUG_MAGIC_TREATMENT_BUF_SEND 0

#define DEBUG_ALL_GOOD_SIZE 0

#define DEBUG_RECEVED_SIZE 0

#define DEBUG_PRINT_MEMORY 0

#define DEBUG_PRINT_VOISIN 0
#define DEBUG_PRINT_VOISIN_VERBOSE 0
#define DEBUG_PRINT_VOISIN_VERBOSE_PLUS 0

#define DEBUG_SMALL_DETAIL 0

#define DEBUG_IMPOSTEUR 0

#define DEBUG_SEARCH_MEMORY 0
#define DEBUG_ADD_MEMORY 0

#define DEBUG_MY_NODE_ID 0

#define DEBUG_PERROR 0

//les tests actives ou desactive des choses
//sa doit etre par defaut a 0
#define TEST_FOR_ALL_TLV 0
#define TEST_NO_TREATMENT 0

//faire rapidement les choses:
//et ajoute les ip des neighbour directement
#define TEST_FAST_MODE 1



//INFORMATION: SEQNO:
//seulement les structures avec seqno sont au format htons() (big)
//Tout les autres: [uint16_t seqno] sont au format ntohs() (little) (parametre/retour)



     // ***** // ***** //                   // ***** // ***** //
// ***** // ***** //                            // ***** // ***** //
    // ***** // ***** //                   // ***** // ***** //

     // ***** // ***** //                   // ***** // ***** //
// ***** // ***** // choses simples auxiliaires // ***** // ***** //
    // ***** // ***** //                   // ***** // ***** //

     // ***** // ***** //                   // ***** // ***** //
// ***** // ***** //                            // ***** // ***** //
    // ***** // ***** //                   // ***** // ***** //



//le temps
time_t get_current_time(){
  struct timeval tv;
  gettimeofday(&tv, NULL);
  return tv.tv_sec;
}

// *** // les define // *** //
//pas tous sont ici: ils sont mieux dans leurs propres places

#define MIN_VOISIN 15

// *** head
#define MAGIC 95
#define VERSION 1
#define HEAD_SIZE 4


// *** tlv
//sauf pour Pad1 ...
#define TLV_HEADER_SIZE 2


#define TLV_TYPE_PAD1 0
#define TLV_TYPE_PADN 1

#define TLV_TYPE_NEI_REQ 2
#define TLV_TYPE_NEI 3

#define TLV_TYPE_NET_HASH 4
#define TLV_TYPE_NET_STA_REQ 5

#define TLV_TYPE_NODE_HASH 6
#define TLV_TYPE_NODE_STA_REQ 7
#define TLV_TYPE_NODE_STA 8

#define TLV_TYPE_WARNING 9


// *** infos des tlv
#define NODE_HASH_SIZE 16
#define NODE_ID_SIZE 8
#define NETWORK_HASH_SIZE 16
#define IP_SIZE 16
#define PORT_SIZE 2
#define DATA_MAX_SIZE 192
#define SEQNO_SIZE 2

//on limite la taille max du message:
#define WARNING_MSG_SIZE 800

// *** auxiliaire pour lire facilement
#define PAS_DEDANS 0
#define DEDANS 1
#define PAS_DE_POSITION -1
#define DEDANS_PAS_PAREIL -2




















     // ***** // ***** //                   // ***** // ***** //
// ***** // ***** //                            // ***** // ***** //
    // ***** // ***** //                   // ***** // ***** //

     // ***** // ***** //                   // ***** // ***** //
// ***** // ***** // informations courantes     // ***** // ***** //
    // ***** // ***** //                   // ***** // ***** //

     // ***** // ***** //                   // ***** // ***** //
// ***** // ***** //                            // ***** // ***** //
    // ***** // ***** //                   // ***** // ***** //




uint16_t my_seqno = 0;//le courant (c'est le numero pour le prochain message)
unsigned char my_node_id[NODE_ID_SIZE];
char my_data[DATA_MAX_SIZE];
unsigned char my_data_len = 0;

//debug
uint16_t my_synchronized_number = 0;
uint16_t my_now_synchronized = 0;//ce qui devrait etre

























     // ***** // ***** //// ***** // ***** //
// ***** // ***** //         // ***** // ***** //
    // ***** // ***** //// ***** // ***** //

     // ***** // ***** //// ***** // ***** //
// ***** // ***** // hashage // ***** // ***** //
    // ***** // ***** //// ***** // ***** //

     // ***** // ***** //// ***** // ***** //
// ***** // ***** //         // ***** // ***** //
    // ***** // ***** //// ***** // ***** //

//WARNING: code de prof par mail (beaucoup de chance de ressemblance avec les autres!)
//Les donnees ne doivent PAS etre traiter (htons), soit seqno.
//Sa fonctionne
int calc_node_hash(unsigned char * res, 
                   unsigned char * node_id, uint16_t seqno, 
                   char * data, int datalen){
  int rc;
  SHA256Context ctx;
  unsigned char hash[32];

  rc = SHA256Reset(&ctx);
  if(rc < 0){
    if(DEBUG_PERROR) perror("reset hash");
    return -1;
  }

  rc = SHA256Input(&ctx, node_id, 8);
  if(rc < 0){
    if(DEBUG_PERROR) perror("input hash");
    return -1;
  }
  uint16_t seqno_htons = htons(seqno);
  rc = SHA256Input(&ctx,(unsigned char *) &seqno_htons, sizeof(seqno));
  if(rc < 0){
    if(DEBUG_PERROR) perror("input hash");
    return -1;
  }
  
  rc = SHA256Input(&ctx, (unsigned char *) data, datalen);
  if(rc < 0){
    if(DEBUG_PERROR) perror("input hash");
    return -1;
  }

  rc = SHA256Result(&ctx, hash);
  if(rc != 0){
    if(DEBUG_PERROR) perror("result hash");
    return -1;
  }
  memmove(res, hash, NODE_HASH_SIZE);//16 premiers
  return 0;
}





//recalculer sistematiquement tout les nodes hash
// sauf qu'ils sont sauvergarder dans [Memory memory]


// ***** get_network_hash() doit etre ici, mais il faut Memory (plus loin derriere)
typedef struct memory memory, *Memory;
void * fold_sens_tri_memory(Memory m,
       void * (*pf)(Memory, unsigned char * id, uint16_t seqno, 
                    char * data, ssize_t datalen, unsigned char * node_hash,
                    void * resultat, void * info),
       void * resultat, void * info);


// ***** // DEBUT Version (de nom): calculer_tout_network_hash
//c'est un [pf]: pour get_network_hash()
//ajoute le node hash courant dan res
//[void * null]: il ne sert a rien dans notre cas
void * fold_left_tmp_state_hash(Memory m, unsigned char * node_id, uint16_t seqno, 
                    char * data, ssize_t datalen, unsigned char * node_hash,
                    void * sha256context, void * null){
  SHA256Context * total_res = (SHA256Context *) sha256context;

  //et on l'ajoute
  int rc = SHA256Input(total_res, node_hash, NODE_HASH_SIZE);
  if(rc < 0){
    if(DEBUG_PERROR) perror("input hash: fold_left_tmp_hash_state()");//ne pas fermer
  }
  return sha256context;//comme il ne change pas (l'ajout est directement dans le pointer)
}


//[res]: met le network hash dedans
void get_network_hash(unsigned char * res, Memory m){

  int rc;
  SHA256Context ctx;
  unsigned char hash[32];

  rc = SHA256Reset(&ctx);

  if(rc < 0)
    if(DEBUG_PERROR) perror("reset hash");//on ne peut rien faire: tant pis

  fold_sens_tri_memory(m, fold_left_tmp_state_hash, &ctx, NULL);

  rc = SHA256Result(&ctx, hash);
  if(rc != 0)
    if(DEBUG_PERROR) perror("result hash");//on ne peut rien faire: tant pis

  memmove(res, hash, NETWORK_HASH_SIZE);//16 premiers
}












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






     // ***** // ***** //               // ***** // ***** //
// ***** // ***** //                        // ***** // ***** //
    // ***** // ***** //              // ***** // ***** //

     // ***** // ***** //               // ***** // ***** //
// ***** // ***** // affichage des messages // ***** // ***** //
    // ***** // ***** //              // ***** // ***** //

     // ***** // ***** //               // ***** // ***** //
// ***** // ***** //                        // ***** // ***** //
    // ***** // ***** //              // ***** // ***** //

//Afficher le message complet (avec des saut pour que ce soit "lisible")
void print_message(unsigned char * buf, ssize_t buflen){
  printf("    Message dans print_message() (len : %lu):\n", buflen);
  int saut = 0;
  if(buflen != 0){
    printf("      ");
    saut = 4;//prochain saut

    //cas pas afficher un head
    //WARNING: un probleme viendra pour un tlv == MAGIC
    if(buf[0] != MAGIC && buflen > 1){
      saut = buf[1] + 2 ;
    }
  }

  for(int i = 0; i < buflen; i++){
    if(i != 0 && saut == i){//maj prochain saut
      printf("\n      ");
      if(buf[i] == 0)
        saut = saut + 1;
      else if(i + TLV_HEADER_SIZE < buflen) saut += get_tlv_len(buf + i) + TLV_HEADER_SIZE;
    }

    printf("%d ", buf[i]);
  }
  printf("\n    Fin de message dans print_message():\n");
}



// ***** // print tmp

char convert_4_bit_to_char(unsigned char i){
  if(i > 16){//un tres gros probleme
    printf("// ERROR convert_4_bit_to_char(): %d\n", i);
    exit(1);
  }
  char tab[6] = {'a', 'b', 'c', 'd', 'e', 'f'};
  if(i < 10)
    return '0' + i;
  return tab[i - 10];
}

#define WITH_DOT 1
#define NO_DOT 0
void print_hexa_aux(unsigned char * s, ssize_t len, int dot){
  for(int i = 0; i < len; i++){
    if(i != 0 && i % 2 == 0)
      if(dot == WITH_DOT) printf(":");

    //remarque: les conversions avec << ou >> les transforment 
    //et ne sont ainsi plus des unsigned char!
    printf("%c%c", convert_4_bit_to_char(s[i] >> 4),
                    convert_4_bit_to_char(( (unsigned char)(s[i] << 4)) >> 4) );
  }
}

void print_hexa_ip(unsigned char * ip){
  print_hexa_aux(ip, IP_SIZE, WITH_DOT);
}

void print_node_id(unsigned char * node_id){
  print_hexa_aux(node_id, NODE_ID_SIZE, NO_DOT);
}

void print_node_hash(unsigned char * node_hash){
  print_hexa_aux(node_hash, NODE_HASH_SIZE, NO_DOT);
}

void print_network_hash(unsigned char * nh){
  print_hexa_aux(nh, NETWORK_HASH_SIZE, NO_DOT);
}









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














     // ***** // ***** //            // ***** // ***** //
// ***** // ***** //                      // ***** // ***** //
    // ***** // ***** //            // ***** // ***** //

     // ***** // ***** //            // ***** // ***** //
// ***** // ***** // remplissage du head // ***** // ***** //
    // ***** // ***** //            // ***** // ***** //

     // ***** // ***** //            // ***** // ***** //
// ***** // ***** //                      // ***** // ***** //
    // ***** // ***** //            // ***** // ***** //




unsigned char * get_body(unsigned char * head){
  return head + HEAD_SIZE;
}

unsigned char * fill_head(unsigned char * head, uint16_t length){
  head[0] = MAGIC;
  head[1] = VERSION;

  put_uint16_in_char(head + 2, length);

  return get_body(head);
}


//CAS SPECIAL: WARNING
void fill_fast_head_with_warning(unsigned char * head, char * msg){
  struct warning * w = (struct warning *) get_body(head);
  w-> type = TLV_TYPE_WARNING;
  w-> len = strlen(msg);
  //pas besoin de memset: bloquer par w-> len. le reste c'est pas notre probleme ...
  memmove(w-> message, msg, w-> len);

  fill_head(head, w-> len + TLV_HEADER_SIZE);
}

void fill_fast_head_with_network_state_request(unsigned char * head){
  ssize_t buflen = sizeof(struct network_state_request) + HEAD_SIZE;


  //ajouter au buffer
  unsigned char * tmp_buf = fill_head(head, buflen - HEAD_SIZE);

  struct network_state_request n_s_r;
  fill_network_state_request(&n_s_r);
  tmp_buf = fill_network_state_request_in_body(tmp_buf, &n_s_r);
}


void fill_fast_head_with_node_state_request(unsigned char * head,
                                            struct node_state_request * n_s_r){
  ssize_t buflen = sizeof(struct node_state_request) + HEAD_SIZE;
  
  //ajouter au buffer
  unsigned char * tmp_buf = fill_head(head, buflen - HEAD_SIZE);

  tmp_buf = fill_node_state_request_in_body(tmp_buf, n_s_r);
}


void fill_fast_head_with_neighbour_request(unsigned char * head){
  fill_head(head, sizeof(struct neighbour_request));
  fill_neighbour_request_in_body(get_body(head));
}











     // ***** // ***** //       // ***** // ***** //
// ***** // ***** //                // ***** // ***** //
    // ***** // ***** //       // ***** // ***** //

     // ***** // ***** //       // ***** // ***** //
// ***** // ***** // head treatment // ***** // ***** //
    // ***** // ***** //       // ***** // ***** //

     // ***** // ***** //       // ***** // ***** //
// ***** // ***** //                // ***** // ***** //
    // ***** // ***** //       // ***** // ***** //


//[size] : taille total (de recvfrom) en octets
int has_head(int size){
  //remarque: si 4 octets sa ne sert a rien (pas de body).
  //on peut donc aussi l'ignorer.
  //prevision: si un message sans TLV est envoyer 
  //et pour nous il faut faire une action:
  //on ne trouvera jamais le bug!
  //et preferable d'envoyer un warning!
  //d'ou la fonction: has_body()
  return size >= HEAD_SIZE;
}

//[size] : taille total (de recvfrom) en octets
int has_body(int size){
  return size > HEAD_SIZE;
}

//[head] : debut du buffer depuis recvfrom
int do_not_ignore(unsigned char * head){
  return head[0] == 95 && head[1] == 1;
}

ssize_t get_head_len(unsigned char * head){
  return char_to_int16(head + 2);
}

//[head] : debut du buffer depuis recvfrom
//[size] : taille total (de recvfrom) en octets
int do_not_ignore_with_size(unsigned char * head, int size){
  //evaluation paresseuse
  return has_head(size) && do_not_ignore(head) && (size - HEAD_SIZE > get_head_len(head));
}










     // ***** // ***** //           // ***** // ***** //
// ***** // ***** //                   // ***** // ***** //
    // ***** // ***** //           // ***** // ***** //

     // ***** // ***** //           // ***** // ***** //
// ***** // ***** // traitement des TLV // ***** // ***** //
    // ***** // ***** //           // ***** // ***** //

     // ***** // ***** //           // ***** // ***** //
// ***** // ***** //                   // ***** // ***** //
    // ***** // ***** //           // ***** // ***** //


unsigned char * print_warning(unsigned char * tlv){
  struct warning * war = (struct warning *) tlv;
  
  char msg[WARNING_MSG_SIZE];
  memset(msg, 0, WARNING_MSG_SIZE);
  int size = war-> len;

  char * msg_info = "";//il faut init

  //securite sur la taille du message: 
  //si le dernier octet de [msg] n'est pas 0 = mort
  if(size >= WARNING_MSG_SIZE){
    size = WARNING_MSG_SIZE - 1;
    msg_info = "MSG too long! [cut]";//pour dire que le message est couper
                                     //car on considere que plus long est nuisible
  }
  memmove(msg, war-> message, size);
  
  printf("// ************* // (%s) WARNING MSG: %s\n", msg_info, msg);
  return tlv + size + TLV_HEADER_SIZE; 
}









     // ***** // ***** //         // ***** // ***** //
// ***** // ***** //                  // ***** // ***** //
    // ***** // ***** //         // ***** // ***** //

     // ***** // ***** //         // ***** // ***** //
// ***** // ***** // stockage donnees // ***** // ***** //
    // ***** // ***** //         // ***** // ***** //

     // ***** // ***** //         // ***** // ***** //
// ***** // ***** //                  // ***** // ***** //
    // ***** // ***** //         // ***** // ***** //


//WARNING: memory.c du projet de: conduite de projet, adapter dans notre memoire

typedef struct memory{
  //data
  unsigned char * node_id;
  uint16_t * seqno;
  char * data;

  unsigned char * node_hash;


  //info pour nous
  unsigned char * datalen;//taille de chaque data
  ssize_t * sens_tri;
  ssize_t open;

  int size;//nombre de place

}memory, *Memory;

#define MEMORY_SIZE 256
Memory init_memory(){
  Memory m = malloc(sizeof(memory));

  unsigned char * node_id = malloc(NODE_ID_SIZE * MEMORY_SIZE);
  uint16_t * seqno = malloc(sizeof(uint16_t) * MEMORY_SIZE);
  char * data = malloc(DATA_MAX_SIZE * MEMORY_SIZE);
  unsigned char * datalen = malloc(MEMORY_SIZE);
  ssize_t * sens_tri = malloc(sizeof(ssize_t) * MEMORY_SIZE);
  unsigned char * node_hash = malloc(NODE_HASH_SIZE * MEMORY_SIZE);

  //si on ajoute directement dans [m], il faut tester son [malloc] avant (mais pas le cas ici)
  if(m == NULL || seqno == NULL || datalen == NULL || node_id == NULL 
     || data == NULL || sens_tri == NULL || node_hash == NULL){
    perror("malloc");//on exit() autant afficher
    exit(1);//RIEN A FAIRE: FIN
  }
  
  memset(datalen, 0, MEMORY_SIZE);
  memset(node_id, 0, NODE_ID_SIZE * MEMORY_SIZE);
  memset(data, 0, DATA_MAX_SIZE * MEMORY_SIZE);
  memset(seqno, 0, sizeof(uint16_t) * MEMORY_SIZE);
  memset(node_hash, 0, NODE_HASH_SIZE * MEMORY_SIZE);
  //sens_tri: on s'en fiche du sens de tri

  m-> node_id = node_id;
  m-> seqno = seqno;
  m-> data = data;

  m-> node_hash = node_hash;

  m-> datalen = datalen;
  m-> sens_tri = sens_tri;
  m-> open = 0;

  m-> size = MEMORY_SIZE;
  
  return m;
}

void memory_put_node_id_at(Memory m, unsigned char * id, ssize_t i){
  memmove(m-> node_id + i * NODE_ID_SIZE, id, NODE_ID_SIZE);
}

void memory_put_data_and_len_at(Memory m, char * data,
                        unsigned char datalen, ssize_t i){
  memmove(m-> data + i * DATA_MAX_SIZE, data, datalen);
  m-> datalen[i] = datalen;
}

void memory_put_node_hash_at(Memory m, unsigned char * hash, ssize_t i){
  memmove(m-> node_hash + i * NODE_HASH_SIZE, hash, NODE_HASH_SIZE);
}

unsigned char * node_id_at(unsigned char * node_id, ssize_t i){
  return node_id + i * NODE_ID_SIZE;
}

char * data_at(char * data, ssize_t i){
  return data + i * DATA_MAX_SIZE;
}

unsigned char * node_hash_at(unsigned char * node_hash, ssize_t i){
  return node_hash + i * NODE_HASH_SIZE;
}



//[pf]: pointeur de fonction, il y a les details
//[resultat]: donner a [pf] et pf retourne un [resultat]
//[info]: des informations necessaires (que la fonction ne va pas modifier)
void * fold_left_memory(Memory m,
       void * (*pf)(Memory, unsigned char * id, uint16_t seqno, 
                    char * data, ssize_t datalen, unsigned char * node_hash,
                    void * resultat, void * info),
       void * resultat, void * info){

  void * tmp_res = resultat;
  for(int i = 0; i < m-> open; i++){
    tmp_res = pf(m, node_id_at(m-> node_id, i), m-> seqno[i],
                 data_at(m-> data, i), m-> datalen[i], node_hash_at(m-> node_hash, i),
                 tmp_res, info);
  }
  return tmp_res;
}

//pour plusieurs lignes en plus, les gains sont minime
//(c'est changer une ligne de code en plus, rapide a debug)
void * fold_sens_tri_memory(Memory m,
       void * (*pf)(Memory, unsigned char * id, uint16_t seqno, 
                    char * data, ssize_t datalen, unsigned char * node_hash,
                    void * resultat, void * info),
       void * resultat, void * info){
  void * tmp_res = resultat;
  for(int i2 = 0; i2 < m-> open; i2++){
    int i = m-> sens_tri[i2];
    tmp_res = pf(m, node_id_at(m-> node_id, i), m-> seqno[i],
                 data_at(m-> data, i), m-> datalen[i], node_hash_at(m-> node_hash, i),
                 tmp_res, info);
  }

  return tmp_res;
}


struct struct_tmp_remplir_node_state{
  int curr_i;//emplacement courant (dans la boucle)
  int next_i;//emplacement de celui dont je dois commencer

  ssize_t rest_space_in_octet;//l'espace restant en octet
  ssize_t put_in_body_in_octet;//combien on ete ajouter (en octets)

  unsigned char * curr_body;//l'endroit qui faut mettre le node state sans data
};

void * tmp_fold_remplir_avec_node_state(Memory m, unsigned char * id, uint16_t seqno, 
                    char * data_ingnored, ssize_t datalen_ignored, unsigned char * node_hash,
                    void * ignored, void * info){
  struct struct_tmp_remplir_node_state * inf =
             (struct struct_tmp_remplir_node_state *) info;

  //on etait a ici
  if(inf-> curr_i == inf-> next_i){
    ssize_t node_hash_size = sizeof(struct node_hash);

    //on a assez de place
    if(inf-> rest_space_in_octet > node_hash_size){

      //ajouter les donnees
      inf-> curr_body = fill_node_hash_in_body(inf-> curr_body, id, seqno, node_hash);

      //le suivant
      inf-> next_i += 1; 

      //maj dese autres infos
      inf-> rest_space_in_octet -= node_hash_size;
      inf-> put_in_body_in_octet += node_hash_size;
    }
  }

  //on a fait un tour
  inf-> curr_i += 1;
  
  return ignored;
}


//retourne emplacement du node_id
//-1 si pas dedans
int search_node_id_position_in_memory(Memory m, unsigned char * node_id){
  int start = 0;
  int end = m-> open -1;

  while(start < end){
    int mid = (start + end) / 2;
    int comp_val = compare_node_id(node_id_at(m-> node_id, m-> sens_tri[mid]), node_id);
    if(comp_val == 0){
      return mid;
    } else if(comp_val == -1){
      end = mid - 1;
    } else if(comp_val == 1){
      start = mid + 1;
    }
  }
  return -1;
}


//ajouter comme nouvelle valeur
void add_new_value_memory(Memory m, unsigned char * id, uint16_t seqno,
                         char * data, ssize_t datalen, unsigned char * hash){
  
  //cas ok
  if(m-> open < m-> size){

    //faire normalement
    memory_put_node_id_at(m, id, m-> open);
    m-> seqno[m-> open] = seqno;

    memory_put_data_and_len_at(m, data, datalen, m-> open);
    memory_put_node_hash_at(m, hash, m-> open);


    //si c'est nous
    if(is_same_node_id(id, my_node_id)){//le cas ou on n'est pas encore dans la memoire
      my_data_len = datalen;
      memmove(my_data, data, datalen);
      my_synchronized_number = seqno;
      my_now_synchronized = seqno;//ce qui devrait etre

      if(seqno != my_seqno){
        my_seqno += seqno + 1;
      }
    }



    //gerer le sens de tri
    m-> sens_tri[m-> open] = m-> open;
    //avec un tri par insertion avec i < open deja trier!
    
    for(int i = m-> open; i > 0; i--){
      unsigned char * tmp_id = node_id_at(m-> node_id, (m-> sens_tri[i - 1]));

      if(compare_node_id(id, tmp_id) == 1)//A VOIR LE SENS
        break;
      unsigned int place_tmp = m-> sens_tri[i];
      m-> sens_tri[i] = m-> sens_tri[i - 1];
      m-> sens_tri[i - 1] = place_tmp;//il y a deux cas a faire si on veut optimiser sa!
                                      //1) quand c'est premier, 2) ou au milieu (pas envie)
                                      //en plus: + compliquer a comprendre! (et debug sa!)
    }
    
    m-> open += 1;//A FAIRE A LA FIN: DES CALCULS SONT FAIT AVEC!
    return;
  }


  //cas pas assez de place
  m-> size = m-> size * 2;//changement de la taille

  //sinon depassement
  m-> node_id = realloc(m-> node_id, NODE_ID_SIZE * m-> size);
  m-> seqno = realloc(m-> seqno, sizeof(uint16_t) * m-> size);
  m-> data = realloc(m-> data, DATA_MAX_SIZE * m-> size);
  m-> node_hash = realloc(m-> node_hash, NODE_HASH_SIZE * m-> size);
  m-> datalen = realloc(m-> datalen, m-> size);
  m-> sens_tri = realloc(m-> sens_tri, sizeof(ssize_t) * m-> size);

  if(m-> seqno == NULL || m-> datalen == NULL || m-> node_id== NULL 
     || m-> data == NULL || m-> sens_tri == NULL || m-> node_hash == NULL){
    perror("realloc");//exit(): autant afficher
    exit(1);//RIEN A FAIRE: FIN
  }

  //et recommence! (impossible de loop: assez de place, sauf erreur programmeur)
  add_new_value_memory(m, id, seqno, data, datalen, hash);
  
}

//ajouter avec comparaisons
void add_value_memory(Memory m, unsigned char * id, uint16_t seqno,
                         char * data, ssize_t datalen, unsigned char * hash){
  if(DEBUG_ADD_MEMORY){
    printf("// ************** // %u\n", seqno);
    print_node_id(id);
    printf("\n");
  }

  //pour mieux comprendre:
  //1) la memoire est vide, donc rien a faire
  //2) la memoire contient my_node_id avec my_seqno:
  //    seqno_dans_memoire(id) < my_seqno : obligatoire (et seqno == my_seqno)
  //                                (quand on arrive dans cette fonction avec notre id)
  //3) sinon c'est une inposture: maj du seqno


  for(int i = 0; i < m-> open; i++){

    if(compare_node_id(node_id_at(m-> node_id, i), id) == 0){//c'est celui-ci!


      //CEST MOOOOOOOOI
      if(compare_node_id(my_node_id, id) == 0){
        if(DEBUG_IMPOSTEUR) printf("// ******* //MOI:  (memory: %u)"
                                   " (seqno: %u) (my_seqno: %u)\n",
                                   m-> seqno[i], seqno, my_seqno);

        //sa peut etre justement moi :)
        if(my_seqno != seqno && compare_seqno(m-> seqno[i], seqno) == -1){
          if(DEBUG_IMPOSTEUR)
            printf("// ********** // INPOSTEUR! (stock: %u) (moi: %u) (ennemie: %u)\n",
                                                m-> seqno[i], my_seqno, seqno);
          m-> seqno[i] = seqno + 1;
          my_seqno = m-> seqno[i];//1) maj du seqno (le courant)

          if(my_synchronized_number == 0) my_synchronized_number = my_seqno;

          if(DEBUG_IMPOSTEUR)
            printf("// ********** // APRES (moi: %u) (enemie: %u)\n", my_seqno, seqno);

          //recalculer avec le nouveau seqno
          calc_node_hash(node_hash_at(m-> node_hash, i),
                         my_node_id, my_seqno, my_data, my_data_len);
          my_seqno++; //2) maj du seqno (le suivant)
          return;//on ne l'ajoute pas: inposteur
        }
        
        if(my_seqno == seqno){
          //si c'est pareil alors il faut l'ajouter
          m-> seqno[i] = seqno;
          memory_put_data_and_len_at(m, data, datalen, i);
          memory_put_node_hash_at(m, hash, i);
          m-> datalen[i] = datalen;
        }
      }



      //compare seqno
      if(compare_seqno(m-> seqno[i], seqno) == -1){
        //on ajoute les valeurs:
        m-> seqno[i] = seqno;
        memory_put_data_and_len_at(m, data, datalen, i);
        memory_put_node_hash_at(m, hash, i);
        m-> datalen[i] = datalen;
      }








      return;//juste pour sa: ne pas utiliser fold_left_memory (optimisation)
             //on pourait dans fold_left_memory dire que si pf retourne NULL on arrete
             //mais c'est generique: ne pas faire de cas particulier
             //sa revient a faire une deuxieme fonction (ou par des moyens complexes en C)
             //qui rendra le code moins comprehensible!
    }
  }

  //ici: c'est pas connu, alors on l'ajoute comme nouveau.
  add_new_value_memory(m, id, seqno, data, datalen, hash);
}


//info pour un fold
struct struct_fold_node_state{

  unsigned char * node_id;

  uint16_t * found_seqno;
  char * found_data;
  unsigned char * found_datalen;
  unsigned char * found_hash;
};

//fonction de fold
void * fold_node_state_in_memory_tmp(Memory m, unsigned char * id, uint16_t seqno, 
                    char * data, ssize_t datalen,
                    unsigned char * tmp_node_hash,
                    void * found , void * struct_tmp_fold_node_state){

  struct struct_fold_node_state * st = 
              (struct struct_fold_node_state *) struct_tmp_fold_node_state;

  if(is_same_node_id(id, st-> node_id)){

    *(st-> found_seqno) = seqno;
    memmove(st-> found_data, data, datalen);
    memmove(st-> found_hash, tmp_node_hash, NODE_HASH_SIZE);
    *(st-> found_datalen) = datalen;
    *((int*)found) = DEDANS;
    if(DEBUG_SEARCH_MEMORY){
      printf("      hash found: ");
      for(int i = 0; i < NODE_HASH_SIZE; i++)
        printf("%u ", tmp_node_hash[i]);
      printf(" with found: %d (%d)\n", *((int*)found), DEDANS);
    }
  }

  return found;
}


//prend les donnees du node [node_id]
//et remplit les champs [seqno], [data], [datalen], [hash]
//retourne [DEDANS] si [node_id] est dedans
//sinon [PAS_DEDANS]
int get_node_state_with_id_from_memory(Memory m, unsigned char * node_id,
        uint16_t * seqno, char * data, unsigned char * datalen, unsigned char * hash){

  struct struct_fold_node_state st = {node_id, seqno, data, datalen, hash};

  int found = PAS_DEDANS;
  fold_left_memory(m, fold_node_state_in_memory_tmp, &found, &st);
  return found;
}

//retourne [DEDANS] ou [PAS_DEDANS]
int is_node_id_in_memory(Memory m, unsigned char * node_id){

  struct node_state tmp;
  uint16_t tmp_seqno;
  return get_node_state_with_id_from_memory(m, node_id, &tmp_seqno, tmp.data,
                                            &tmp.datalen, tmp.node_hash);
}


//retourne NEED si besoin de l'avoir,
//SAME si c'est pareil,
//BETTER si dans notre [memory], le seqno est meilleur (et donc le pair est a la ramasse)
#define SAME 0
#define NEED -1
#define BETTER 1
int node_id_status_in_memory(Memory m, unsigned char * node_id, uint16_t seqno, unsigned char * hash){
  struct node_state node;
  uint16_t seqno_in_memory;

  if(get_node_state_with_id_from_memory(m, node_id, &seqno_in_memory,
                node.data, &node.datalen, node.node_hash) != DEDANS){
    return NEED;//pas dedans
  }

  int seqno_compared = compare_seqno(seqno_in_memory, seqno);

  //remarque: on ne compare plus les hashs

  if(seqno_compared == 0){//souvent le cas
    //if(is_same_node_hash(node.node_hash, hash))
      return SAME;//on va dire que c'est correcte (car si cest egaux mais celui qui envoie est faux ...)
    //return NEED;
  }

  if(seqno_compared == -1)
    return NEED;

  return BETTER;
}


unsigned char * fill_node_state_in_body_from_id_in_memory(
              unsigned char * body, unsigned char * node_id, Memory memory){

  uint16_t seqno;
  struct node_state ns;
  memmove(ns.node_id, node_id, NODE_ID_SIZE);

  if(get_node_state_with_id_from_memory(memory, node_id, &seqno, 
                                ns.data, &ns.datalen, ns.node_hash) != DEDANS){
    return body;
  }
  return fill_node_state_in_body(body, &ns, seqno);
}


int fill_fast_node_state_from_id_in_memory(unsigned char * head, unsigned char * node_id,
                           uint16_t * buflen_usefull, Memory memory){

  unsigned char * next = fill_node_state_in_body_from_id_in_memory
                              (get_body(head), node_id, memory);

  if(next == get_body(head)){
    if(DEBUG_MESSAGE_SEND){ 
      printf("    Node id not found: ");
      print_node_id(node_id);
      printf("\n");
    }
    return 0;
  }

  //reel taille
  *buflen_usefull = next - head;
  if(DEBUG_MESSAGE_SEND) printf("    Total buflen: %u\n", *buflen_usefull);

  fill_head(head, *buflen_usefull - HEAD_SIZE);
  return 1;
}


//print dans tout les cas
void print_memory(Memory m){
  char msg[DATA_MAX_SIZE + 1];
  if(DEBUG_PRINT_MEMORY) printf("// ***** // START print_memory()");
  printf("\n");//on veut un saut de ligne de base

  for(int i2 = 0; i2 < m-> open; i2++){
    int i = m-> sens_tri[i2];
    printf("// ***** //");

    if(DEBUG_PRINT_MEMORY) printf("place: %u-> %u\n", i2, i);//on afficher ceci sur // ***** //
                                                       //juste "esthetique"

    printf("\n   id     ");
    print_node_id(node_id_at(m-> node_id, i));
    printf("\n   seqno  %u", m-> seqno[i]);
    printf("\n   hash   ");
    print_node_hash(node_hash_at(m-> node_hash, i));
    memset(msg, 0, DATA_MAX_SIZE + 1);
    memmove(msg, data_at(m->data, i), m-> datalen[i]);
    printf("\n   msg    %s\n\n", msg);
  }

  if(DEBUG_PRINT_MEMORY) printf("// ***** // END print_memory(). total: %lu", m-> open);
  printf("\n");//meme remarque
}



     // ***** // ***** //         // ***** // ***** //
// ***** // ***** //                  // ***** // ***** //
    // ***** // ***** //         // ***** // ***** //

     // ***** // ***** //         // ***** // ***** //
// ***** // ***** // stockage voisins // ***** // ***** //
    // ***** // ***** //         // ***** // ***** //

     // ***** // ***** //         // ***** // ***** //
// ***** // ***** //                  // ***** // ***** //
    // ***** // ***** //         // ***** // ***** //

//Les voisins
struct voisins{
  #define NB_VOISIN 15
  int occupe[NB_VOISIN];
  unsigned char ip[IP_SIZE * NB_VOISIN];
  uint16_t port[NB_VOISIN];//WARNING: FORMAT MACHINE (LITTLE ENDIAN)
  int transitoire[NB_VOISIN];
  ssize_t last_time[NB_VOISIN];
} voisins;

unsigned char * get_voisin_char_ip_at(unsigned char * ip, ssize_t i){
  if(i >= NB_VOISIN){//erreur programmeur
    printf("get_voisin_char_ip_at(): i >= NB_VOISIN\n");
  }
  return ip + i * IP_SIZE;
}

unsigned char * get_voisin_ip_at(struct voisins * v, ssize_t i){
  return get_voisin_char_ip_at(v-> ip, i);
}


void init_voisins(struct voisins * v){
  memset(v-> occupe, 0, sizeof(int) * NB_VOISIN);
  memset(v-> ip, 0, IP_SIZE * NB_VOISIN);
  memset(v-> port, 0, sizeof(uint16_t) * NB_VOISIN);
  memset(v-> transitoire, 0, sizeof(int) * NB_VOISIN);
  memset(v-> last_time, 0, sizeof(ssize_t) * NB_VOISIN);
}


void print_voisins(struct voisins * v){
  unsigned int time = get_current_time();
  
  if(DEBUG_PRINT_VOISIN) printf("// **** // START voisin_add_aux()");
  printf("\nNEIGHBORS:\n");//on veut un saut quand on affiche les voisins de base! (sans debug)

  for(int i = 0; i < NB_VOISIN; i++){
    if(v-> occupe[i] != 0){
      unsigned char tmp_ip[IP_SIZE];
      memset(tmp_ip, 0, IP_SIZE);
      memmove(tmp_ip, get_voisin_ip_at(v, i), IP_SIZE);
      printf("  place %d:\n    ip: ", i);
      print_hexa_ip(tmp_ip);
      printf("\n    port: %u\n", v-> port[i]);
      printf("    last time: %ld\n", time - v-> last_time[i]);
    }
  }

  if(DEBUG_PRINT_VOISIN) printf("// **** // END voisin_add_aux()");
  printf("\n");//meme remarque
}

//retourne 1 si [ip1] == [ip2] et [port1] == [port2]
//0 sinon
int ip_port_equals(unsigned char * ip1, uint16_t port1,
                   unsigned char * ip2, uint16_t port2){

  if(port1 != port2)
    return 0;

  for(int i = 0; i < IP_SIZE; i++)
    if(ip1[i] != ip2[i])
      return 0;
  
  return 1;
}

//retourne 1 si un chose est fait, 0 sinon
int voisin_add_aux(struct voisins * v, unsigned char * ip, 
                    uint16_t port_16_t, int transit){

  //sa fait plein de choses en meme temps :(
  

  //les valeurs de base
  int nouvelle_emplacement = PAS_DE_POSITION;
  int deja_dedans = PAS_DEDANS;

  for(int i = 0; i < NB_VOISIN; i++){
    //emplacement possible
    if(v-> occupe[i] == 0 && nouvelle_emplacement == PAS_DE_POSITION)
      nouvelle_emplacement = i;//ne pas break, on ne sait pas s'il est deja dedans!

    //mais pas besoin d'ajouter si deja dedans
    if(v-> occupe[i] == 1 &&
        ip_port_equals(ip, port_16_t, get_voisin_ip_at(v, i), v-> port[i])){
      deja_dedans = DEDANS;

      //mettre a jour le temps
      v-> last_time[i] = get_current_time();

      if(DEBUG_PRINT_VOISIN_VERBOSE) printf("// ** // voisin deja dedans: maj temps\n");
      return 1;  //on sort: imaginons (mais impossible) qu'il y a un doublon: 1 degagera
              //pas return? -> cest pour: print_voisins() //obsolete: mais pour le retour
    }
  }

  if(deja_dedans == PAS_DEDANS && nouvelle_emplacement != PAS_DE_POSITION){

    int i = nouvelle_emplacement;//pas envie de changer le code

    v-> occupe[i] = 1;
    memmove(get_voisin_ip_at(v, i), ip, IP_SIZE);

    //EN LITTLE ENDIAN
    v-> port[i] = port_16_t;

    v-> transitoire[i] = transit;

    //mettre a jour le temps
    v-> last_time[i] = get_current_time();

    if(DEBUG_PRINT_VOISIN_VERBOSE) printf("// ** // nouveau voisin ajouter!\n");
    return 1;
  }
  //print_voisins(v);//obsolete: rester en commantaire

  return 0;
}

//retourne 1 si un chose est fait, 0 sinon
int voisin_add(struct voisins * v,
                unsigned char * ip, uint16_t port){
  return voisin_add_aux(v, ip, port, 0);
}

//retourne 1 si un chose est fait, 0 sinon
int voisin_add_permament(struct voisins * v, 
                          unsigned char * ip, uint16_t port){
  return voisin_add_aux(v, ip, port, 1);
}

void voisin_clean(struct voisins * v){
  #define MAX_TIME 70
  unsigned int t = get_current_time();
  for(int i = 0; i < NB_VOISIN; i++){
    if(v-> transitoire[i] == 0 && v-> occupe[i] && t - v-> last_time[i] > MAX_TIME)
      v-> occupe[i] = 0;
  }
}

int voisin_nombre(struct voisins * v){
  int nb = 0;
  for(int i = 0; i < NB_VOISIN; i++){
    if(v-> occupe[i])
      nb++;
  }

  //un probleme doit etre regler!
  if(nb == 0){
    if(DEBUG_SMALL_DETAIL) printf("// ************* // PAS DE VOISIN D:\n");
    return 0;
  }
  return nb;
}



void voisin_for_all(struct voisins * v, 
                    void(*pf)(unsigned char * ip, uint16_t port, void * info), void * info){
  for(int i = 0; i < NB_VOISIN; i++)
    if(v-> occupe[i])
      pf(get_voisin_ip_at(v, i), v-> port[i], info);
}


struct struct_fold_random_voisins{
  int num;
  unsigned char * res_ip;
  uint16_t * res_port;
};

void fold_tmp_get_random_voisins(unsigned char * ip, uint16_t port, void * info){
  struct struct_fold_random_voisins * inf = (struct struct_fold_random_voisins *) info;

  if(inf-> num < 0) return;//rien a faire

  if(inf-> num == 0){
    memmove(inf-> res_ip, ip, IP_SIZE);
    *(inf-> res_port) = port;
  }

  inf-> num -= 1;
}


void get_random_voisins(struct voisins * v, unsigned char * res_ip, uint16_t * res_port){
  srandom(time(0) * getpid());
  int r = random() % voisin_nombre(v);//si c'est 0 on est mal, mais on a au moins 1 voisin
  struct struct_fold_random_voisins stru = {r, res_ip, res_port};
  voisin_for_all(v, fold_tmp_get_random_voisins, &stru);
}




void fold_tmp_is_already_in_voisins(unsigned char * ip, uint16_t port, void * info){
  struct struct_fold_random_voisins * inf = (struct struct_fold_random_voisins *) info;
  if(port == *(inf-> res_port) && is_same_aux(ip, inf-> res_ip, IP_SIZE))
    inf-> num = 1;
}

int is_already_in_voisins(struct voisins * voisins, unsigned char * ip, uint16_t port){
  struct struct_fold_random_voisins stru = {0, ip, &port};
  voisin_for_all(voisins, fold_tmp_is_already_in_voisins, &stru);
  return stru.num;
}


//une structure temporaire pour avoir des infos
struct struct_fold_show_to_others{
  struct sockaddr_in6 * addr;
  ssize_t addrlen;
  int socket;
  unsigned char * buf_msg;
  ssize_t buf_size;
};


//envoye un message a [ip] [port]
//avec les informations dans [info]
void fold_tmp_voisin_show_to_others(unsigned char * ip, uint16_t port, void * info){
  struct struct_fold_show_to_others * inf = (struct struct_fold_show_to_others *) info;
  memmove(inf-> addr-> sin6_addr.s6_addr, ip, IP_SIZE);
  inf-> addr-> sin6_port = htons(port);
  int rc = sendto(inf-> socket, inf-> buf_msg, inf-> buf_size, 0,
                 (struct sockaddr *) inf-> addr, inf-> addrlen);

  if(DEBUG_MESSAGE_SEND || DEBUG_PRINT_VOISIN_VERBOSE){
    printf("  show try for ip: ");
    print_hexa_ip(ip);
    printf("\n  show try for port: %u", port);
    if(DEBUG_MESSAGE_SEND) {
      printf("  with message (len %lu): ", inf-> buf_size);
      print_message(inf-> buf_msg, inf-> buf_size);
    } else printf("\n");
  }

  if(DEBUG_MESSAGE_SEND_ONLY) print_message(inf-> buf_msg, inf-> buf_size);

  if(rc == -1){
    if(DEBUG_PERROR) perror("sendto");//PAS exit(1): juste afficher un probleme
  }
}


void show_to_others(struct voisins * v, struct sockaddr_in6 * addr, ssize_t addrlen,
                    int socket, unsigned char * buf, ssize_t buflen){
  if(DEBUG_MESSAGE_SEND || DEBUG_PRINT_VOISIN_VERBOSE)
    printf("// **** // START show_to_others()\n");
  

  //structure des informations pour fold
  struct struct_fold_show_to_others info;
  info.addr = addr;
  info.socket = socket;
  info.addrlen = addrlen;
  info.buf_msg = buf;
  info.buf_size = buflen;

  voisin_for_all(v, fold_tmp_voisin_show_to_others, &info);
  if(DEBUG_MESSAGE_SEND || DEBUG_PRINT_VOISIN_VERBOSE)
    printf("// **** // END show_to_others()\n");
}

void show_to_others_my_network_hash(struct voisins * v, struct sockaddr_in6 * addr, 
                    ssize_t addrlen, int socket, Memory memory){
  if(DEBUG_MESSAGE_SEND || DEBUG_PRINT_VOISIN_VERBOSE)
    printf("// ***** // START show_to_others_my_network_hash()\n");

  ssize_t buflen = sizeof(network_hash) + HEAD_SIZE;//on va envoyer (que) des network hash!
  unsigned char buf[buflen];
  memset(buf, 0, buflen);

  //calcul network hash
  unsigned char * tmp_buf = fill_head(buf, buflen - HEAD_SIZE);
  unsigned char network_hash[NETWORK_HASH_SIZE];
  get_network_hash(network_hash, memory);

  //ajouter au buffer
  tmp_buf = fill_head(buf, buflen - HEAD_SIZE);

  struct network_hash n_hash;
  fill_network_hash(&n_hash, network_hash);

  tmp_buf = fill_network_hash_in_body(tmp_buf, &n_hash);
  //et avec tmp_buf, on peut ajouter d'autres choses: ne pas oublier [buflen]!

  show_to_others(v, addr, addrlen, socket, buf, buflen);

  if(DEBUG_MESSAGE_SEND || DEBUG_PRINT_VOISIN_VERBOSE)
    printf("// ***** // END show_to_others_my_network_hash()\n");
}


void send_for_all_neighbour_request(struct voisins * v, 
             struct sockaddr_in6 * addr, ssize_t addrlen, int socket){

  if(DEBUG_MESSAGE_SEND || DEBUG_PRINT_VOISIN_VERBOSE)
    printf("// ***** // START send_for_all_neighbour_request()\n");

  ssize_t buflen = sizeof(struct neighbour_request) + HEAD_SIZE;
  unsigned char buf[buflen];

  fill_fast_head_with_neighbour_request(buf);

  show_to_others(v, addr, addrlen, socket, buf, buflen);

  if(DEBUG_MESSAGE_SEND || DEBUG_PRINT_VOISIN_VERBOSE)
    printf("// ***** // END send_for_all_neighbour_request()\n");
}


//demander aux voisins de donner un network hash
//pourquoi steal?, la question c'est plutot: pourquoi pas?
//REMARQUE: utiliser une seul fois: au dedbut du programme
//sa va etre rapide pour avoir toutes les donnees!
void steal_others_network_hash(struct voisins * v, struct sockaddr_in6 * addr,
                    ssize_t addrlen, int socket, Memory memory){
  if(DEBUG_MESSAGE_SEND || DEBUG_PRINT_VOISIN_VERBOSE)
    printf("// ***** // START steal_others_network_hash()\n");

  ssize_t buflen = sizeof(struct network_state_request) + HEAD_SIZE;
  unsigned char buf[buflen];

  fill_fast_head_with_network_state_request(buf);

  show_to_others(v, addr, addrlen, socket, buf, buflen);

  if(DEBUG_MESSAGE_SEND || DEBUG_PRINT_VOISIN_VERBOSE)
    printf("// ***** // END steal_others_network_hash()\n");
}


void send_for_all_node_id_information(struct voisins * v, unsigned char * node_id,
                    struct sockaddr_in6 * addr, ssize_t addrlen,
                    int socket, Memory memory){
  if(DEBUG_MESSAGE_SEND || DEBUG_PRINT_VOISIN_VERBOSE)
    printf("// ***** // START send_for_all_node_id_information()\n");
  unsigned char head[sizeof_node_state() + HEAD_SIZE];//clairement assez

  uint16_t buflen_usefull;

  if(fill_fast_node_state_from_id_in_memory(head, node_id, &buflen_usefull, memory) == 0){
    if(DEBUG_MESSAGE_SEND || DEBUG_MESSAGE_SEND_NODE_STATE_ONLY)
      printf("    // *** // STATE NOT FOUND\n");
    return;
  }

  if(DEBUG_MESSAGE_SEND || DEBUG_MESSAGE_SEND_NODE_STATE_ONLY){
    if(compare_node_id(node_id, my_node_id) == 0) printf("    // *** // SEND MY STATE\n");
    print_message(head, buflen_usefull);
  }

  show_to_others(v, addr, addrlen, socket, head, buflen_usefull);
  if(DEBUG_MESSAGE_SEND || DEBUG_PRINT_VOISIN_VERBOSE)
    printf("// ***** // END send_for_all_node_id_information()\n");
}


//ces fonctions sont derrieres, mais utiles pour afficher ici
void magic_send_fast_node_state_request(struct sockaddr_in6 * addr,
                      ssize_t addrlen, int socket, unsigned char * node_id);

void magic_send_all_node_hash(struct sockaddr_in6 * addr,
                      ssize_t addrlen, int socket, Memory memory);


void send_for_all_every_tlv_type(struct voisins * v, unsigned char * node_id,
                    struct sockaddr_in6 * addr, ssize_t addrlen,
                    int socket, Memory memory){

  if(TEST_FOR_ALL_TLV == 0) return;//double protection

  unsigned char head[1024];
  unsigned char * tmp_body;
  ssize_t buflen_usefull;



  //Pad1
  tmp_body = fill_head(head, 1);// 1 == Pad1 len
  tmp_body[0] = 0;
  buflen_usefull = HEAD_SIZE + 1;
  show_to_others(v, addr, addrlen, socket, head, buflen_usefull);




  //PadN
  int n = 10;
  tmp_body = fill_head(head, n + TLV_HEADER_SIZE);// 1 == Pad1 len
  tmp_body[0] = 1;
  tmp_body[1] = n;
  buflen_usefull = HEAD_SIZE + n + TLV_HEADER_SIZE;
  show_to_others(v, addr, addrlen, socket, head, buflen_usefull);




  //Neighbour request
  send_for_all_neighbour_request(v, addr, addrlen, socket);

  //Neighbour
  buflen_usefull = sizeof(struct neighbour) + HEAD_SIZE;

  unsigned char nei_ip[IP_SIZE];
  uint16_t nei_port;

  get_random_voisins(v, nei_ip, &nei_port);
  fill_neighbour_in_body(get_body(head), nei_ip, nei_port);
  fill_head(head, buflen_usefull - HEAD_SIZE);

  show_to_others(v, addr, addrlen, socket, head, buflen_usefull);



  //Network hash
  show_to_others_my_network_hash(v, addr, addrlen, socket, memory);

  //Network state request
  steal_others_network_hash(v, addr, addrlen, socket, memory);

  //Node hash
  magic_send_all_node_hash(addr, addrlen, socket, memory);

  //Node state request
  magic_send_fast_node_state_request(addr, addrlen, socket, node_id);

  //Node state
  send_for_all_node_id_information(v, node_id, addr, addrlen, socket, memory);

  //Warning
  char * msg = "dans le cadre d'un test de tout les tlv ceci est un test d'envoye de warning";
  buflen_usefull = strlen(msg) + TLV_HEADER_SIZE + HEAD_SIZE;
  
  fill_fast_head_with_warning(head, msg);
  show_to_others(v, addr, addrlen, socket, head, buflen_usefull);

  //fini
}


     // ***** // ***** //          // ***** // ***** //
// ***** // ***** //                   // ***** // ***** //
    // ***** // ***** //         // ***** // ***** //

     // ***** // ***** //          // ***** // ***** //
// ***** // ***** // treatment handler // ***** // ***** //
    // ***** // ***** //         // ***** // ***** //

     // ***** // ***** //          // ***** // ***** //
// ***** // ***** //                   // ***** // ***** //
    // ***** // ***** //         // ***** // ***** //

#define ALL_GOOD_SIZE_OK 1
#define ALL_GOOD_SIZE_ERR 0

int is_all_good_size_message_setter(
                  char * errmsg, const char * message, const char * debugmsg, int resultat){


  if(DEBUG_ALL_GOOD_SIZE && debugmsg != NULL)
    printf("      %s\n// ***** // END is_all_good_size()\n", debugmsg);

  if(errmsg != NULL && message != NULL)
    sprintf(errmsg, "%s", message);

  return resultat;
}

//Verifications des packets
//si tout est bon: retourne ALL_GOOD_SIZE_OK
//sinon retourne ALL_GOOD_SIZE_ERR et [errmsg] est le message d'erreur
//[errmsg] est pour personnaliser les messages ici (aussi avec des infos utiles)
int is_all_good_size(unsigned char * head, int bufsize, char * errmsg){

  if(DEBUG_ALL_GOOD_SIZE) printf("// ***** // START is_all_good_size()\n");

  //les messages
  char errtmp[WARNING_MSG_SIZE];
  char debugtmp[WARNING_MSG_SIZE];
  memset(errtmp, 0, WARNING_MSG_SIZE);
  memset(debugtmp, 0, WARNING_MSG_SIZE);


  if(has_head(bufsize) == 0){

    sprintf(errtmp, "the packet receved is too small, size: %u", bufsize);
    sprintf(debugtmp, "NO HEADER: size %u", bufsize);

    return is_all_good_size_message_setter(errmsg, errtmp, debugtmp, ALL_GOOD_SIZE_ERR);;
  }

  //c'est la taille annoncer par le buffer
  uint16_t rest_len = get_head_len(head);

  unsigned char * tmp_body = get_body(head);

  if(bufsize - HEAD_SIZE < rest_len){

    sprintf(errtmp, "the header announced size: %u (all size: %u)"
                    " > (%u) than the packet receved", rest_len, rest_len + HEAD_SIZE, bufsize);

    sprintf(debugtmp, "HEADER SAY %u (%u) > (%u) PACKET END",
                      rest_len, rest_len + HEAD_SIZE, bufsize);

    return is_all_good_size_message_setter(errmsg, errtmp, debugtmp, ALL_GOOD_SIZE_ERR);
  }





  //invariant de boucle:
  //a chaque debut du tour de boucle, rest_len >= 0

  while(1){//source de blocage possible

    //cas 0:
    //soit tout est lu
    //soit il reste des choses dans le buffer (mais ignorer)
    if(rest_len == 0)
      break;

    //cas 1:
    //il n'y a pas assez de place dans le buffer pour un tlv normal
    if(rest_len == 1){
      if(tmp_body[0] != TLV_TYPE_PAD1){//Pad1

        sprintf(errtmp, "expected Pad1 but found %u", tmp_body[0]);
        sprintf(debugtmp, "EXPECTED Pad1, FOUND %u", tmp_body[0]);

        return is_all_good_size_message_setter(errmsg, errtmp, debugtmp, ALL_GOOD_SIZE_ERR);
      }
      break;
    }

    rest_len -= TLV_HEADER_SIZE; //toujours positif!

    //il y a assez de place: testons!
    unsigned char tmp_tlv_len = get_tlv_len(tmp_body);

    if(DEBUG_ALL_GOOD_SIZE) print_message(tmp_body, get_tlv_len(tmp_body) + TLV_HEADER_SIZE);

    //cas 2:
    //sa dit n'importe quoi sur la taille!
    unsigned char tmp_tlv_type = get_tlv_type(tmp_body);
    if(is_bad_tlv_len_in(tmp_tlv_type, tmp_tlv_len)){

      sprintf(errtmp, "expected for tlv type %u len >= %u but found %u",
                tmp_tlv_type, tlv_minimum_len_in_expected(tmp_tlv_type), tmp_tlv_len);
      sprintf(debugtmp, "EXPECTED TLV %u LEN >= %u, FOUND %u",
                tmp_tlv_type, tlv_minimum_len_in_expected(tmp_tlv_type), tmp_tlv_len);

      return is_all_good_size_message_setter(errmsg, errtmp, debugtmp, ALL_GOOD_SIZE_ERR);
    }

    //cas 3:
    //rest_len est trop petit par rapport au len dans le header!
    if(rest_len < tmp_tlv_len){

      sprintf(errtmp, "TLV type: %u with len (%u) > PACHET END (total: %u) at position: %u",
          tmp_tlv_type, tmp_tlv_len, bufsize,(unsigned int)(get_head_len(head) - rest_len));

      sprintf(debugtmp, "TLV (%u) > PACHET END (total: %u) (free: %u)",
                               tmp_tlv_len, bufsize, rest_len);

      return is_all_good_size_message_setter(errmsg, errtmp, debugtmp, ALL_GOOD_SIZE_ERR);
    }

    //cas 4: ok
    rest_len -= tmp_tlv_len;
    tmp_body = tmp_body + TLV_HEADER_SIZE + tmp_tlv_len;
  }


  sprintf(debugtmp, "OK");
  return is_all_good_size_message_setter(NULL, NULL, debugtmp, ALL_GOOD_SIZE_OK);
}


//envoyer un warning
void magic_send_fast_warning(struct sockaddr_in6 * addr, ssize_t addrlen,
                             int socket, char * msg){
  ssize_t total_size = strlen(msg) + TLV_HEADER_SIZE + HEAD_SIZE;
  unsigned char head[total_size];
  fill_fast_head_with_warning(head, msg);

  if(DEBUG_MESSAGE_SEND_ONLY) print_message(head, total_size);

  if(sendto(socket, head, total_size, 0,
           (struct sockaddr *) addr, addrlen) == -1) 
    if(DEBUG_PERROR) perror("sendto");//pas exit()!
}



void magic_send_fast_random_neighbour(struct sockaddr_in6 * addr,
                               ssize_t addrlen, int socket, struct voisins * voisins){
  ssize_t total_size = sizeof(struct neighbour) + HEAD_SIZE;
  unsigned char head[total_size];

  unsigned char nei_ip[IP_SIZE];
  uint16_t nei_port;

  get_random_voisins(voisins, nei_ip, &nei_port);
  fill_neighbour_in_body(get_body(head), nei_ip, nei_port);
  fill_head(head, total_size - HEAD_SIZE);

  if(DEBUG_MESSAGE_SEND_ONLY) print_message(head, total_size);

  if(sendto(socket, head, total_size, 0,
           (struct sockaddr *) addr, addrlen) == -1) 
    if(DEBUG_PERROR) perror("sendto");//pas exit()!
}

//envoyer une network state request
void magic_send_fast_network_state_request(struct sockaddr_in6 * addr,
                      ssize_t addrlen, int socket){
  ssize_t buflen = sizeof(struct network_state_request) + HEAD_SIZE;
  unsigned char buf[buflen];
  fill_fast_head_with_network_state_request(buf);

  if(DEBUG_MESSAGE_SEND_ONLY) print_message(buf, buflen);

  if(sendto(socket, buf, buflen, 0,
           (struct sockaddr *) addr, addrlen) == -1) 
    if(DEBUG_PERROR) perror("sendto");//pas exit()!
}

void magic_send_all_node_hash(struct sockaddr_in6 * addr,
                      ssize_t addrlen, int socket, Memory memory){
  struct struct_tmp_remplir_node_state st;
  st.next_i = 0;//le suivant de base est 0

  //comme sa: (28 * 20) + 4, donc 20 nodes hash, avec head
  #define TMP_SEND_SIZE 564
  unsigned char head[TMP_SEND_SIZE];

  do {
    
    st.curr_i = 0;//on recommence par 0
    st.rest_space_in_octet = TMP_SEND_SIZE - HEAD_SIZE;
    st.put_in_body_in_octet = 0;
    st.curr_body = get_body(head);

    fold_sens_tri_memory(memory, tmp_fold_remplir_avec_node_state, NULL, &st);

    fill_head(head, st.put_in_body_in_octet);
    //TODO: SEND
    if(st.put_in_body_in_octet != 0){

      ssize_t total_size = st.put_in_body_in_octet + HEAD_SIZE;

      if(DEBUG_MESSAGE_SEND_ONLY) print_message(head, total_size);

      if(sendto(socket, head, total_size, 0, 
                              (struct sockaddr *) addr, addrlen) == -1){
        perror("sendto");//pas exit()!
      }
    }

  } while (st.put_in_body_in_octet != 0);
}


//envoyer un node state request
void magic_send_fast_node_state_request(struct sockaddr_in6 * addr,
                      ssize_t addrlen, int socket, unsigned char * node_id){
  ssize_t buflen = sizeof(struct node_state_request) + HEAD_SIZE;
  unsigned char buf[buflen];
  struct node_state_request nsr;
  fill_node_state_request(&nsr, node_id);
  fill_fast_head_with_node_state_request(buf, &nsr);

  if(DEBUG_MESSAGE_SEND_ONLY) print_message(buf, buflen);

  if(sendto(socket, buf, buflen, 0,
           (struct sockaddr *) addr, addrlen) == -1) 
    if(DEBUG_PERROR) perror("sendto");//pas exit()!
}

//envoyer apres un node state request
unsigned char * magic_fill_node_state(unsigned char * body, unsigned char * node_id, Memory memory){
  uint16_t buflen_usefull;
  //si le node_id est dans la table ou non
  if(fill_fast_node_state_from_id_in_memory(body, node_id, &buflen_usefull, memory)){
    return body + buflen_usefull;
  }
  return body;
}

//envoyer apres un node state request
void magic_send_fast_node_state(struct sockaddr_in6 * addr,
                      ssize_t addrlen, int socket, unsigned char * node_id,
                      Memory memory){

  unsigned char head[sizeof_node_state() + HEAD_SIZE];//clairement assez

  uint16_t buflen_usefull;

  if(DEBUG_MESSAGE_SEND_ONLY || DEBUG_MESSAGE_SEND) print_message(head, buflen_usefull);

  //si le node_id est dans la table ou non
  if(fill_fast_node_state_from_id_in_memory(head, node_id, &buflen_usefull, memory)){
    if(sendto(socket, head, buflen_usefull, 0,
           (struct sockaddr *) addr, addrlen) == -1) 
      if(DEBUG_PERROR) perror("sendto");//pas exit()!
  }
}


void magic_send(struct sockaddr_in6 * addr,
                      ssize_t addrlen, int socket, unsigned char * buf, ssize_t buflen){
  if(sendto(socket, buf, buflen, 0,
           (struct sockaddr *) addr, addrlen) == -1) 
      if(DEBUG_PERROR) perror("sendto");//pas exit()!
}


//REMARQUE IMPORTANTE: on envoye un seul datagram par information.
//SAUF pour Network state request!
void magic_treatment(unsigned char * head, ssize_t recv_buf_len,
                     struct voisins * voisins, struct sockaddr_in6 * addr,
                     ssize_t addrlen, int socket, Memory memory){

  if(DEBUG_MAGIC_TREATMENT) printf("// ***** // START MAGIC TREATMENT\n");
  char errmsg[WARNING_MSG_SIZE];//sa devrait etre suffisant? (message de warning)
  memset(errmsg, 0, WARNING_MSG_SIZE);
  switch(is_all_good_size(head, recv_buf_len, errmsg)){

    case ALL_GOOD_SIZE_ERR:
      magic_send_fast_warning(addr, addrlen, socket, errmsg);
      if(DEBUG_MAGIC_TREATMENT || DEBUG_MAGIC_TREATMENT_BAD_ONLY){
        printf("    BAD RECEVED MESSAGE:\n");
        print_message(head, recv_buf_len);
      }
      if(DEBUG_MAGIC_TREATMENT) printf("// ***** // END MAGIC TREATMENT\n");
      return;

    case ALL_GOOD_SIZE_OK: break;//bien, on continue

    default: //erreur du programmeur
      printf("magic_treatment(): QUI A CODER SA !!!\n"); exit(1);
  }



  //verification du nombre de voisins
  unsigned char tmp_voisin_ip[IP_SIZE];
  memmove(tmp_voisin_ip, addr-> sin6_addr.s6_addr, IP_SIZE);
  //ntohs: voisin_add prend la vrai valeur!

  if(voisin_add(voisins, tmp_voisin_ip, ntohs(addr-> sin6_port)) == 0){
    if(DEBUG_MAGIC_TREATMENT) printf("      TOO MUCH NEIGHBOUR\n"
                                     "// ***** // END MAGIC TREATMENT\n");
    return;
  }

  


  //connaitre le hash courant
  unsigned char network_hash[NETWORK_HASH_SIZE];//hash du network courant (avant de venir ici)
  int need_calc_network_hash = 1;//ne le calculer qu'une seul fois
  //ATTENTION: cela signifie que si le calcul, 
  //puis on change une donnee -> pas le meme que courant! 

  unsigned char node_hash_tmp[NODE_HASH_SIZE];//un tmp pour sotcker un node hash

  //d'autres choses
  ssize_t tmp_len = get_head_len(head);//taille courant du body
  if(DEBUG_MAGIC_TREATMENT) printf("  total for all tlv size: %ld\n", tmp_len);

  if(DEBUG_MESSAGE_RECEVED_ONLY || DEBUG_MESSAGE_RECEVED){
    printf("MESSAGE RECEVED from : "); print_hexa_ip(addr-> sin6_addr.s6_addr);
    printf("\n");
    print_message(head, tmp_len + HEAD_SIZE);
  }

  unsigned char * tmp_tlv_body = get_body(head);//emplacement courant dans body

  unsigned char send_buf[1024];
  unsigned char * send_buf_body = get_body(send_buf);
  struct node_state_request nsr;

  while(tmp_len > 0){
    if(DEBUG_MAGIC_TREATMENT) printf("  magic while\n");
    switch(get_tlv_type(tmp_tlv_body)){

      case TLV_TYPE_PAD1: //Pad1
        if(DEBUG_MAGIC_TREATMENT) printf("    case Pad1\n");
        tmp_len -= 1; tmp_tlv_body = tmp_tlv_body + 1;
        continue;//faire break == la mort



      case TLV_TYPE_PADN: //PadN (tout est fait dans la ligne suivante)
        if(DEBUG_MAGIC_TREATMENT) printf("    case PadN\n");
        //rien a faire
        break;



      case TLV_TYPE_NEI_REQ: //Neighbour request
        
        //sendto();
        if(DEBUG_MAGIC_TREATMENT) printf("    case Neighbour request\n");
        magic_send_fast_random_neighbour(addr, addrlen, socket, voisins);
        break;



      case TLV_TYPE_NEI: //Neighbour
        //envoyer: TODO: a verifier: si c'est nous???
        if(DEBUG_MAGIC_TREATMENT) printf("    case Neighbour\n");

        struct neighbour * nb = (struct neighbour *) tmp_tlv_body;

        if(is_already_in_voisins(voisins, nb-> ip, char_to_int16(nb-> port))){
          break;
        }

        //une fonction fait sa, mais pour tout les voisins ...
        //c'est pas grave, il sera envoyer seul (bricolage)
        struct voisins tmp_voisin;
        init_voisins(&tmp_voisin);
        voisin_add(&tmp_voisin, nb-> ip, char_to_int16(nb-> port));
        
        if(TEST_FAST_MODE){
          struct sockaddr_in6 tmp_addr;
          memmove(&tmp_addr, addr, sizeof(struct sockaddr_in6));
          voisin_add(voisins, nb-> ip, char_to_int16(nb-> port));
          magic_send_fast_node_state_request(&tmp_addr, addrlen, socket, my_node_id);
        }

        //une copie car la fonction:
        //show_to_others_my_network_hash() change les valeurs du [sockaddr_in6]
        struct sockaddr_in6 addr_env;
        memmove(&addr_env, addr, addrlen);

        show_to_others_my_network_hash(&tmp_voisin, &addr_env, sizeof(addr_env), socket, memory);
        break;



      case TLV_TYPE_NET_HASH: //Network Hash
        //comparer avec le courant
        if(DEBUG_MAGIC_TREATMENT || DEBUG_MAGIC_TREATMENT_NET_HASH)
          printf("    case Network Hash\n");
        
        if(need_calc_network_hash)
          get_network_hash(network_hash, memory);

        unsigned char * tmp_recv_network_hash = 
            ((struct network_hash *) tmp_tlv_body)-> network_hash;

        if(DEBUG_MAGIC_TREATMENT_NET_HASH){
          printf("      _my_ network hash: ");
          print_network_hash(network_hash);
          printf("\n      recv network hash: ");
          print_network_hash(tmp_recv_network_hash);
          printf("\n");
        }
        if(is_different_network_hash(network_hash, tmp_recv_network_hash)){
          if(DEBUG_MAGIC_TREATMENT_NET_HASH)
            printf("       not same: send network state request\n");
          //alors envoyer nous les infos!
          magic_send_fast_network_state_request(addr, addrlen, socket);
        }
        break;



      case TLV_TYPE_NET_STA_REQ: //Network State Request
        //plein de TLV node hash
        if(DEBUG_MAGIC_TREATMENT) printf("    case Network State Request\n");

        magic_send_all_node_hash(addr, addrlen, socket, memory);
        break;



      case TLV_TYPE_NODE_HASH: //Node Hash

        //traitement: regarder si on a les meme informations
        //mais pas assez d'information pour calculer le hash!
        if(DEBUG_MAGIC_TREATMENT) printf("    case Node Hash\n");
        struct node_state * tmp_n = (struct node_state *) tmp_tlv_body;

        int res_node_status_in_memory = node_id_status_in_memory(memory, tmp_n-> node_id, 
           char_to_int16(tmp_n-> seqno), tmp_n-> node_hash);

        if(res_node_status_in_memory == NEED){
          fill_node_state_request(&nsr, tmp_n-> node_id);
          send_buf_body = fill_node_state_request_in_body(send_buf_body, &nsr);
          //magic_send_fast_node_state_request(addr, addrlen, socket, tmp_n-> node_id);
          if(DEBUG_MAGIC_TREATMENT) printf("    case Node Hash: send node state request\n");

        } else if(DEBUG_MAGIC_TREATMENT) printf("    case Node Hash: already good\n");

        //on envoie une node state
        if(res_node_status_in_memory == BETTER){
          send_buf_body = fill_node_state_in_body_from_id_in_memory(send_buf_body, tmp_n-> node_id, memory);
          //struct voisins tmp_voisin2;
          //init_voisins(&tmp_voisin2);
          //voisin_add(&tmp_voisin2, addr-> sin6_addr.s6_addr, ntohs(addr-> sin6_port));
          //send_for_all_node_id_information(&tmp_voisin2, tmp_n-> node_id, 
          //                    addr, addrlen, socket, memory);
        }
        break;



      case TLV_TYPE_NODE_STA_REQ: //Node State Request
        //retourner un node state: a verifier
        
        if(DEBUG_MAGIC_TREATMENT)
          printf("    case Node State Request\n");
        if(DEBUG_MESSAGE_SEND_NODE_STATE_ONLY) printf("    // *** // try to sending node state.\n");
        struct node_state_request * tmp_r = 
                 (struct node_state_request *) tmp_tlv_body;

        if(is_node_id_in_memory(memory, tmp_r-> node_id)){
          send_buf_body = fill_node_state_in_body_from_id_in_memory(send_buf_body, tmp_r-> node_id, memory);
          //struct voisins tmp_voisin3;
          //init_voisins(&tmp_voisin3);
          //voisin_add(&tmp_voisin3, addr-> sin6_addr.s6_addr, ntohs(addr-> sin6_port));
          //send_for_all_node_id_information(&tmp_voisin3, tmp_r-> node_id, 
          //                  addr, addrlen, socket, memory);
        }
        break;



      case TLV_TYPE_NODE_STA: //Node State
        //mettre dans les bonnes choses: a verifer
        //avec warning msg si pas meme node hash que l'on calcul

        //info de base
        if(DEBUG_MAGIC_TREATMENT) printf("    case Node State\n");
        struct node_state * tmp_ns = (struct node_state *) tmp_tlv_body;

        //explication du calcul: datalen = max_data_len - (max_size - curr_size)
        ssize_t datalen_tmp = DATA_MAX_SIZE -
                              (sizeof_node_state() - 
                              (get_tlv_len(tmp_tlv_body) + TLV_HEADER_SIZE) );

        //calculer le node hash: on sauvegarde le node hash dans memory,
        //donc il ne doit pas etre faux!
        calc_node_hash(node_hash_tmp, tmp_ns-> node_id, char_to_int16(tmp_ns-> seqno),
                                      tmp_ns-> data, datalen_tmp);

        if(is_same_node_hash(tmp_ns-> node_hash, node_hash_tmp)){

          if(DEBUG_MAGIC_TREATMENT) printf("    case Node State: trying maj\n");

          add_value_memory(memory, tmp_ns-> node_id, 
             char_to_int16(tmp_ns-> seqno), tmp_ns-> data, datalen_tmp, tmp_ns-> node_hash);

        } else {//warning

          if(DEBUG_MAGIC_TREATMENT) printf("    case Node State: error hash!\n");
          printf("MAUVAIS\n");
          magic_send_fast_warning(addr, addrlen, socket, "Not same node hash calculated!");
        }
        break;



      case TLV_TYPE_WARNING://Warning
        printf("    case Warning\n");
        print_warning(tmp_tlv_body);
        break;

      default://Inconnue
        printf("    case Inconnue: %d\n", get_tlv_type(tmp_tlv_body));
        break;
    }


    //vider send_buffer
    uint32_t tmp_size = send_buf_body - send_buf;
    if(tmp_size > 700){
      fill_head(send_buf, tmp_size - HEAD_SIZE);
      if(DEBUG_MAGIC_TREATMENT_BUF_SEND) print_message(send_buf, tmp_size);
      magic_send(addr, addrlen, socket, send_buf, tmp_size);
      send_buf_body = get_body(send_buf);//reset
    }

    //chose de base

    tmp_len -= get_tlv_len(tmp_tlv_body) + TLV_HEADER_SIZE;

    if(DEBUG_MAGIC_TREATMENT) printf("  magic tmp_len: %ld\n", tmp_len);

    tmp_tlv_body = tmp_tlv_body + get_tlv_len(tmp_tlv_body) + TLV_HEADER_SIZE;
  }

  
  if(send_buf_body != get_body(send_buf)){//il faut envoyer
    uint32_t tmp_size = send_buf_body - send_buf;
    
    fill_head(send_buf, tmp_size - HEAD_SIZE);
    if(DEBUG_MAGIC_TREATMENT_BUF_SEND) print_message(send_buf, tmp_size);
    magic_send(addr, addrlen, socket, send_buf, tmp_size);
  }

  if(DEBUG_MAGIC_TREATMENT) printf("// ***** // MAGIC TREATMENT END\n");
}



     // ***** // ***** //                    // ***** // ***** //
// ***** // ***** //                             // ***** // ***** //
    // ***** // ***** //                    // ***** // ***** //

     // ***** // ***** //                  // ***** // ***** //
// ***** // ***** // traitement du node courant // ***** // ***** //
    // ***** // ***** //                  // ***** // ***** //

     // ***** // ***** //                    // ***** // ***** //
// ***** // ***** //                             // ***** // ***** //
    // ***** // ***** //                    // ***** // ***** //


#define MY_DATA_FILE ".my_node_id.data"

void create_new_node_id(){
  if(DEBUG_MY_NODE_ID) printf("Creation d'un nouveau identifiant dans %s.\n", MY_DATA_FILE);

  char buf[40];//40: pourquoi pas?
  memset(buf, 0, 40);

  for(int i = 0; i < NODE_ID_SIZE; i++){
    my_node_id[i] = random() % 256;
    char tmp[5];
    sprintf(tmp, "%d ", my_node_id[i]);
    strcat(buf, tmp);
  }

  FILE * f = fopen(MY_DATA_FILE, "w");
  fwrite(buf, sizeof(unsigned char), strlen(buf), f);
  fclose(f);
  my_seqno = 0;
  my_data_len = 0;
}

//global
int information_charged = 0;

void charge_my_information(){
  
  if(information_charged) return;

  information_charged = 1;

  FILE * f = fopen(MY_DATA_FILE, "r");
  if(f == NULL){//pas creer
    create_new_node_id();
    return;
  }

  //tester
  int rc;
  for(int i = 0; i < NODE_ID_SIZE; i++){
    int c;
    rc = fscanf(f, "%d ", &c);

    if(rc == -1 || c < 0 || c > 255){//corrompu
      printf("%d, %d \n", rc, c);
      fclose(f);
      if(DEBUG_MY_NODE_ID) printf("Le fichier %s est corrompu.\n", MY_DATA_FILE);
      create_new_node_id();
      return;
    }

    my_node_id[i] = (unsigned char) c;
  }

  if(DEBUG_MY_NODE_ID) printf("L'identifiant est recuperer.\n");
  fclose(f);

  my_seqno = 0;
  my_data_len = 0;
}

//on ecrase
void add_my_value_in_memory(Memory m){
  unsigned char hash[NODE_HASH_SIZE];
  calc_node_hash(hash, my_node_id, my_seqno, my_data, my_data_len);
  add_value_memory(m, my_node_id, my_seqno, my_data, my_data_len, hash);
}

void add_my_info_to_memory(Memory memory, char * my_data2, ssize_t my_data_len2){
  memmove(my_data, my_data2, my_data_len2);
  my_data_len = my_data_len2;

  add_my_value_in_memory(memory);

  my_seqno += 1;


  //debug
  if(my_synchronized_number != 0 && my_now_synchronized == 0)
    my_now_synchronized = my_synchronized_number;

  if(my_now_synchronized != 0) my_now_synchronized += 1;

  

}


void change_my_information_test(Memory memory){
  memset(my_data, 0, DATA_MAX_SIZE);
  
  sprintf(my_data, "test first synchronized: %u, should now: %u, predict next loss: %u",
           my_synchronized_number, my_now_synchronized, predict_next_loss((uint16_t)(my_seqno - 1)));
  my_data_len = strlen(my_data);
}


void print_help_aux(char * option_type, char * description){
  printf("        -%s,\n"
         "             %s\n", option_type, description);
}

void print_help(){
  printf("\nHELP\n  USAGE: [OPTION] [...]\n  OPTIONS:\n");
  print_help_aux("h", "show this text");
  print_help_aux("p", "show the current memory table");
  print_help_aux("v", "show the current neighbour table");
  print_help_aux("n", "show the current node id");
  print_help_aux("c", "change the current node id (not advised)");
  print_help_aux("k", "show the current message");
  print_help_aux("e", "show the next seqno");
  print_help_aux("l", "predict the next lost seqno");
  print_help_aux("m [MSG]", "add [MSG] to the memory for the current node");
  print_help_aux("s [FILE]", "save the current memory in the file [FILE]");
  printf("\n");
}


void super_handler(Memory memory, struct voisins * voisins, 
                  struct sockaddr_in6 * addr, ssize_t addrlen, int socket,
                  char * args, ssize_t args_len){
  if(args_len <= 2){
    print_help();
    return;
  }

  char option;
  int rc = sscanf(args, "-%c", &option);

  if(rc == 0){
    print_help();
    return;
  }

  char * default_memory_file_name = "memory.out";

  char * msg = args + 3;
  ssize_t msglen = args_len - 4;//a cause du \n
  msg[msglen] = 0;

  ssize_t tmp_len = DATA_MAX_SIZE+1;
  char tmp[tmp_len];

  switch(option){

    case 'h' :
      print_help();
      return;

    case 'p' :
      print_memory(memory);
      return;

    case 'v' :
      print_voisins(voisins);
      return;

    case 'n' :
      printf("\n");
      print_node_id(my_node_id);
      printf("\n\n");
      return;

    case 'c' :
      create_new_node_id();
      printf("\n");
      return;

    case 'k' :
      memset(tmp, 0, tmp_len);
      memmove(tmp, my_data, my_data_len);
      printf("\n%s\n\n", tmp);
      return;

    case 'e' :
      printf("\n%u\n\n", my_seqno);//en avance du prochain
      return;

    case 'l' :
      printf("\n%u\n\n", predict_next_loss((uint16_t)(my_seqno - 1)));//le faire sur le courant!
      return;

    case 'm' :
      if(args_len > 3){
        
        add_my_info_to_memory(memory, msg, msglen);
        send_for_all_node_id_information(voisins, my_node_id, addr, addrlen, socket, memory);
        printf("\n");
      } else {
        printf("Warning: no data found!\n");
        print_help();
      }
      return;

    case 's' ://utiliser en debug mode ne garentie RIEN
      
      if(args_len > 4){
        default_memory_file_name = msg;
      }

      FILE * stdout_tmp = stdout;
      stdout = fopen(default_memory_file_name, "w");
      print_memory(memory);
      fclose(stdout);
      stdout = stdout_tmp;
      return;

    //TODO
    default:
      print_help();
      return;
  }
  
}


     // ***** // ***** //      // ***** // ***** //
// ***** // ***** //               // ***** // ***** //
    // ***** // ***** //      // ***** // ***** //

     // ***** // ***** //     // ***** // ***** //
// ***** // ***** // ___le main___ // ***** // ***** //
    // ***** // ***** //      // ***** // ***** //

     // ***** // ***** //     // ***** // ***** //
// ***** // ***** //               // ***** // ***** //
    // ***** // ***** //      // ***** // ***** //


int main(int argc, char ** argv){

  // ***** INIT

  char * name;
  char * argv_port;


  if(argc % 2 == 0){//impaire pour la pair (addr, port)
    printf("Usage: [[addr] [port]] [...]. Found %d, not even\n", argc -1);
    exit(1);
  }

  int number_of_addr = argc / 2;//sa peut etre 0

  if(number_of_addr == 0){
    name = "jch.irif.fr";
    argv_port = "1212";
    printf("Default use: ip: %s, port: %s\n", name, argv_port);
    number_of_addr = 1;
  } else {
    name = argv[1];
    argv_port = argv[2];
  }






  // * reseau

  int rc;
  int s;//socket


  struct sockaddr_in6 addr_envoyer;
  memset(&addr_envoyer, 0, sizeof(addr_envoyer));
  addr_envoyer.sin6_family = AF_INET6;
  ssize_t addr_envoyerlen = sizeof(addr_envoyer);


  unsigned char tmp_voisin_ip[IP_SIZE];


  // * buffer

  #define MAX_DGRAM_SIZE 65515
  unsigned char recv_buf[MAX_DGRAM_SIZE];



  // * information utile

  struct voisins voisins;
  init_voisins(&voisins);

  Memory memory = init_memory();//memoire pour les voisins

  
  //ajouter sa data de base
  charge_my_information();
  char my_data_starter[DATA_MAX_SIZE + 1];
  memset(my_data_starter, 0, DATA_MAX_SIZE + 1);
  fprintf(stdout, "Premier data: ");
  fflush(stdout);//car pas de \n
  read(STDIN_FILENO, my_data_starter, DATA_MAX_SIZE);//erreur? on s'en fiche! data vaut 0!

  my_data_starter[DATA_MAX_SIZE] = 0;//la fin
  ssize_t my_data_len_starter = strlen(my_data_starter);
  add_my_info_to_memory(memory, my_data_starter, my_data_len_starter);

  if(DEBUG_PRINT_MEMORY) print_memory(memory);




  






  // *** init: ip de depart: le 0 est bien fait, le reste: il faut aller les chercher
  //WARNING: structure de code du prof par mail
  for(int i = 0; i < number_of_addr; i++){
    if(i != 0){//chercher le suivant
      name = argv[i * 2 + 1];
      argv_port = argv[i * 2 + 2];
    }
  
    struct addrinfo hints;
    struct addrinfo *res;
    memset(&hints, 0, sizeof(hints));
    hints.ai_socktype = SOCK_DGRAM;
    hints.ai_flags = AI_V4MAPPED | AI_ALL;//tous ipv6 et ipv4 (mapped)
    hints.ai_family = AF_INET6;//en ipv6
    rc = getaddrinfo(name, argv_port, &hints, &res);
    if(rc < 0) {
    /* be smart : continuer */
      perror("getaddrinfo");
      continue;
    }
    for(struct addrinfo *p = res; p != NULL; p = p->ai_next) {
      memmove(tmp_voisin_ip, ((struct sockaddr_in6 *) p-> ai_addr)-> sin6_addr.s6_addr, IP_SIZE);
      voisin_add_permament(&voisins, tmp_voisin_ip, atoi(argv_port));
    }
    freeaddrinfo(res);
  }
  //fin code prof par mail

  



  // *** init: socket

  s = socket(AF_INET6, SOCK_DGRAM, 0);
  
  
  //setsockopt(s, SOL_SOCKET, IPV6_V6ONLY, &sock_tmp_val, sizeof(sock_tmp_val));
  if(s == -1){
    perror("socket");//exit(): gros probleme
    exit(1);
  }

  int sock_tmp_val = 1;//juste pour setsockopt

  if(setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &sock_tmp_val, sizeof(int)) < 0)
    perror("setsockopt");

  if(setsockopt(s, SOL_SOCKET, SO_REUSEPORT, &sock_tmp_val, sizeof(int)) < 0)
    perror("setsockopt");

  struct sockaddr_in6 sin6;
  memset(&sin6, 0, sizeof(sin6));
  sin6.sin6_family = AF_INET6;
  sin6.sin6_port = htons(1313);
  rc = bind(s, (struct sockaddr *) &sin6, sizeof(struct sockaddr_in6));
  if(rc == -1){
    perror("bind");//exit(): gros probleme
    exit(1);
  }

  //FAST TEST
  /*
  unsigned char tp_ip[16] = {42, 1, 14, 10, 5, 58, 167, 240, 122, 208, 132, 98, 96, 126, 183, 144};
  voisin_add(&voisins, tp_ip, 49153);
  memmove(sin6.sin6_addr.s6_addr, tp_ip, IP_SIZE);
  sin6.sin6_port = htons(49153);

  unsigned char tmp_id[8] = {185,199,37,159,158,10,194,214};
  magic_send_fast_node_state_request(&sin6, sizeof(sin6), s, my_node_id);
  */
  //END FAST TEST


  // *** init: attendre

  fd_set rfds;
  FD_ZERO(&rfds);
  FD_SET(s,&rfds);
  struct timeval wait_ti;
  int ti_limit = 5;
  wait_ti.tv_sec = ti_limit;
  wait_ti.tv_usec = 0;




  // ***** AVOIR LES INFOS DE BASE

  send_for_all_node_id_information(&voisins, my_node_id, &addr_envoyer, addr_envoyerlen, s, memory);

  //envoyer a tout le monde un network state request (pour commencer)
  
  steal_others_network_hash(&voisins, &addr_envoyer, addr_envoyerlen, s, memory);
  






  // ***** C'EST PARTI!

  //temps de depart!
  ssize_t last_time20 = get_current_time();//20 secondes
  ssize_t last_time40 = get_current_time();//40 secondes
  //ssize_t last_time3 = get_current_time();
  //ssize_t last_time4 = get_current_time();
  //ssize_t last_time5 = get_current_time();

  print_help();//afficher aide


  //magic loop!
  while(1){
    if(DEBUG_BIG_WHILE_BOUCLE) printf("// ******* // START while\n");

    // ***** ATTENDRE

    //il faut le refaire a chaque fois!
    FD_ZERO(&rfds);
    FD_SET(s,&rfds);
    FD_SET(STDIN_FILENO, &rfds);
    wait_ti.tv_sec = ti_limit;//il faut le refaire a chaque fois?
    rc = select(s + 1, &rfds, NULL, NULL, &wait_ti);

    if(!rc){
      if(DEBUG_BIG_WHILE_BOUCLE) perror("// ** // select");
      if(DEBUG_BIG_WHILE_BOUCLE)
        printf("  Time limit: %ds, no message. Doing others things ...\n", ti_limit);
    } else if(FD_ISSET(s, &rfds)){

      // ***** RECEVOIR

      struct sockaddr_in6 addr_client;
      memset(&addr_client, 0, sizeof(addr_client));
      addr_client.sin6_family = AF_INET6;
      socklen_t addr_client_len = sizeof(addr_client);

      memset(recv_buf, 0, MAX_DGRAM_SIZE);
      rc = recvfrom(s, recv_buf, MAX_DGRAM_SIZE, 0,
                                 (struct sockaddr *) &addr_client, &addr_client_len);

      if(rc < 0) {
        perror("// *** // recvfrom");
        continue;//ne pas sortir du while!
      }

      if(DEBUG_MESSAGE_RECEVED || DEBUG_BIG_WHILE_BOUCLE) {
        printf("// *** // RECEVED FROM with ip: ");
        print_hexa_ip(addr_client.sin6_addr.s6_addr);
        printf("\n// *** // RECEVED FROM with port: %u\n", ntohs(addr_client.sin6_port));
        print_message(recv_buf, rc);
      }

      //It's magic!
      if(TEST_NO_TREATMENT == 0)
        magic_treatment(recv_buf, rc, &voisins, &addr_client, addr_client_len, s, memory);
    } else if(FD_ISSET(STDIN_FILENO, &rfds)){
      ssize_t max = DATA_MAX_SIZE + 4;//[-][option][espace] ... [\n]
      char msg_buf[max];
      memset(msg_buf, 0, max);
      ssize_t args_len = read(STDIN_FILENO, msg_buf, max);

      super_handler(memory, &voisins, &addr_envoyer, addr_envoyerlen, s, msg_buf, args_len);

    } else {
      printf("%d ?\n",rc);//probleme programmeur.
    }
    
    
    // ***** FAIRE DES CHOSES
    
    // *** envoyer aux autres?
    if(get_current_time() - last_time20 > 20){
      if(DEBUG_BIG_WHILE_BOUCLE) printf("// ******* // SHOW to others my network hash\n");

      //TODO: changer ceci pour changer depuis terminal

      //change_my_information_test(memory);
      //send_for_all_node_id_information(&voisins, my_node_id, 
      //                        &addr_envoyer, addr_envoyerlen, s, memory);


      
      show_to_others_my_network_hash(&voisins, &addr_envoyer, addr_envoyerlen, s, memory);

      voisin_clean(&voisins);
      if(voisin_nombre(&voisins) < MIN_VOISIN){
        send_for_all_neighbour_request(&voisins, &addr_envoyer, addr_envoyerlen, s);
      }

      //test: envoyer tout les type de tlv
      if(TEST_FOR_ALL_TLV){
        send_for_all_every_tlv_type(&voisins, my_node_id,
                                    &addr_envoyer, addr_envoyerlen, s, memory);
      }


      if(DEBUG_PRINT_VOISIN) print_voisins(&voisins);
      last_time20 = get_current_time();
    }

    if(get_current_time() - last_time40 > 40){
      if(DEBUG_PRINT_MEMORY) print_memory(memory);
      last_time40 = get_current_time();
    }



    //c'est tout?
    //TOUT le reste est traiter avec: magic_treatment()?

    if(DEBUG_BIG_WHILE_BOUCLE) printf("// ******* // END while\n");
  }


  return 0;
}

