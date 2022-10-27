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

