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

