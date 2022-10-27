
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
