     // ***** // ***** //                   // ***** // ***** //
// ***** // ***** //                            // ***** // ***** //
    // ***** // ***** //                   // ***** // ***** //

     // ***** // ***** //                   // ***** // ***** //
// ***** // ***** // informations courantes     // ***** // ***** //
    // ***** // ***** //                   // ***** // ***** //

     // ***** // ***** //                   // ***** // ***** //
// ***** // ***** //                            // ***** // ***** //
    // ***** // ***** //                   // ***** // ***** //




uint16_t my_seqno = 0;//le courant (c'est le numero pour le prochain message)
unsigned char my_node_id[NODE_ID_SIZE];
char my_data[DATA_MAX_SIZE];
unsigned char my_data_len = 0;

//debug
uint16_t my_synchronized_number = 0;
uint16_t my_now_synchronized = 0;//ce qui devrait etre
