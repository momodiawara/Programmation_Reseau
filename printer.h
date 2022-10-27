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
