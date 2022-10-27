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
