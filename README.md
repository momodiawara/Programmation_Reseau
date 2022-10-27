# Programmation_Reseau


Comment faire fonctionner le code:

make
./fichier
./fichier jch.irif.fr 1212

Comment lire le code:

-voir fichier.c (deconseiller)

-voir les fichiers .h (c'est le fichier .c mais decoupe en morceau) (ils ne fonctionnes pas)
(il y a aussi plus de commentaire que dans fichier.c)
(sha.h et sha-private.h ne compte pas bien evidement)

//les informations de base (pas interessant)
header.h
type_tlv.h

//les informations courante du pair (simple et utile)
informations_courante.h

//des petites fonctions de convertions (simple et utile)
conversion.h

//le remplissage des tlv/head (simple et utile)
fill_tlv.h
head_msg.h

//des affichages et hashages (pas interressant)
printer.h
print_warning.h
hashage.h

//les tables: donnees et voisins (c'est les structures de donnees)
memory.h
voisin.h

//les traitements des paquets recus (tres utiles)
treatment.h

//les traitements du pair courant (avec entree du terminal)
treatment_curr_node.h

//le main qui orchestre tout
main.h
