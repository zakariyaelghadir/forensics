import struct
# Définir le chemin de l'image système de fichiers à analyser
image_path = "C:/Users/Zakariya El ghadir/Desktop/sics4/computer forensics/projet/deviceImageCorrupted.raw"
with open(image_path, "rb") as f:
    # Lire le MBR de l'image système de fichiers
    mbr = f.read(512)
options = ["choix 1:Afficher le type de système de fichiers", "choix 2:Afficher le nombre de secteurs de pudding", "choix 3:Afficher le nombre de partitions", "choix 4:Afficher le début de la première partition", "choix 5:Afficher la taille de la première partition", "choix 6:Afficher les informations du superbloc"]
print("Veuillez choisir parmi les options suivantes : ")
for i, option in enumerate(options):
    print(f"{i+1}. {option}")
choice = int(input("\nEntrez le numéro de votre choix : "))
while choice < 1 or choice > len(options):
    choice = int(input("Choix invalide. Entrez le numéro de votre choix : "))
def get_filesystem(mbr_path):
        # Extraire l'entrée de la 1er partition
        first_partition = mbr[446 :446+16]
        # Analyser l'octet de type de partition
        partition_type = first_partition[4]
        # Déterminer le système de fichiers en fonction du type de partition
        if partition_type == 0x83:
            return "ext2/ext3/ext4"
        elif partition_type == 0x07:
            return "NTFS"
        elif partition_type == 0x0B:
            return "FAT32"
        elif partition_type == 0x72:
            return "FAT32(avec LBA)"
        else:
            return "Unknown"
def pudding(filesystem):
    if filesystem == "ext2/ext3/ext4":
        return 2
    elif filesystem == "NTFS":
        return 8
    elif filesystem == "FAT32(avec LBA)":
        return 4
def count_partitions(mbr_data):
    count = 0
    # On parcourt la table des partitions
    for i in range(4):
        offset = 446 + i * 16
        partition_entry = mbr_data[offset:offset + 16]
        # On extrait le champ "type" de l'entrée de partition
        partition_type = struct.unpack('<B', partition_entry[4:5])[0]
        # Si le champ "type" est différent de zéro, cela signifie que la partition est utilisée
        if partition_type != 0:
            count += 1
    return count
if choice==1:
    filesystem = get_filesystem(image_path)
    print("La partition est formatée avec ", filesystem)
elif choice==2:
    pudding=pudding(get_filesystem(image_path))
    print("secteur de pudding pour système de fichier est ", pudding)
elif choice==3:
    # On compte le nombre de partitions
    partition_count = count_partitions(mbr)
    # On affiche le résultat
    print(f'Le MBR contient {partition_count} partitions.')
elif choice==4:
    first_partition = struct.unpack("<I", mbr[454:454 + 4])[0]
    print("la première partition est commencer par le secteur :",first_partition)
    calcul=(first_partition+pudding(get_filesystem(image_path)))*512
    print("(",first_partition,"+",pudding(get_filesystem(image_path)),") * 512 = ", calcul )
elif choice==5:
    partition_size = struct.unpack("<I", mbr[458:458 + 4])[0]
    print("La taille de la première partition est :", partition_size*512, "octets", )
else :
    with open(image_path,"rb") as f:
        # Lire le superbloc (à l'offset 1024 dans ce cas)
        f.seek(0x8200)
        superbloc = f.read(1024)
        # Extraire les informations du superbloc
        inodes_count = struct.unpack("<I", superbloc[0:4])[0]
        blocks_count = struct.unpack("<I", superbloc[4:8])[0]
        block_size = struct.unpack("<I", superbloc[24:28])[0]

    print("Nombre d'inodes : {} inodes".format(inodes_count))
    print("Nombre de blocs : {} bloc".format(blocks_count))
    print("Taille d'un bloc : {} octets".format(2 ** (10 + block_size)))
    # Vérifier si la taille de bloc est valide
    if block_size % 2 != 0 or block_size < 512 or block_size > 65536:
        print("La taille de bloc n'est pas valide.")

