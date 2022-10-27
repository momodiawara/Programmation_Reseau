
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
