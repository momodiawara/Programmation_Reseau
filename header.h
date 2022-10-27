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
