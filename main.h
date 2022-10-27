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
