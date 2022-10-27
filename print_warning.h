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

