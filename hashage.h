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

