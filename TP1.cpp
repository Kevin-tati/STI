/**
 *  TP1 : Sécurité et Cryptographie 
 *             SDES
 * 
 * Author: KHRIS Lydia 11709552
 *          TATIBOUET Kevin 11504114
 * */



#include<iostream>
#include<stdio.h>
#include<string.h>
#include<stdlib.h>
#include<assert.h>
void menu_principal(int *);
void menuC();
void menuD();
int DoEnDe(int);
class S_DES
{
private:
    char clef[11],K1[9],K2[9],PIOutput[9],InversionPIOutput[9];
    char F1Output[9],F2Output[9];
    char INPUT_BIT[9],OUTPUT_BIT[9];
public:
    unsigned char INPUT,OUTPUT;
    S_DES(char *clef);
    ~S_DES();
    void generateurDeClef();
    char *RotationGauche(char *,int );
    void char_to_bits(unsigned char );
    void PI(char *);
    void InversionPI(char *);
    void Crypter_Des(unsigned char );
    void Decrypter_Des(unsigned char );
    void Fk(char *,char *,int );
    char *XOR(char *,int );
    char *SBOX0(char *);
    char *SBOX1(char *);
    void GetChar();
};
S_DES::S_DES(char *key)  //Initialisation de la clef
{
    int i;
    printf("%s\n",key);
    if (strlen(key) != 10)  //verification de la taille de la clef
    {
        printf("\ntaille de la clef invalide %s %lu",key,strlen(key));
        getchar();
        printf("%s\n",key);
        exit(1);
    }
    for (i=0;i<10;i++)  //clef privée
    {
        clef[i]=key[i];
    }
    clef[10]='\0';
    generateurDeClef(); //on genere les clef, on obtient en sortie les clef K1 et K2
}
void S_DES::generateurDeClef()
{
    int TdP10[10]={3,5,2,7,4,10,1,9,8,6}; 	 // table de permutation
    char tmp[11];    		//pour stocké TdP10
    int TdP8[8]={6,3,7,4,8,5,10,9}; 		//table de permutation
    char *PG,*rg,*rg1,*PD,*rd,*rd1,*rgrd;
    int i;
    /*Opération sur la clef principal*/
    for (i=0;i<10;i++)
        tmp[i]=clef[TdP10[i]-1];
    tmp[10]='\0';
    /* Division des 10 bits de sortie en 2 parties*/
    PG = new char[11];
    PD = new char[11];
    for (i=0;i<5;i++)
    {
        PG[i]=tmp[i];
        PD[i]=tmp[i+5];
    }
    PG[5]='\0';
    PD[5]='\0';
    rg=new char[6];
    rd=new char[6];
    /* Rotation circulaire gauche de 1 bit sur les 2 parties des 10 bits de sortie*/
    rg=RotationGauche(PG,1);
    rd=RotationGauche(PD,1);
    /*On combine les 2 parties apres avoir effectuez la rotation gauche*/
    rgrd = new char[11];
    for (i=0;i<5;i++)
    {
        rgrd[i]=rg[i];
        rgrd[i+5]=rd[i];
    }
    rgrd[10]='\0';
    /*Operation sur la premiere sous clef K1*/
    for (i=0;i<8;i++)
        K1[i]=rgrd[TdP8[i]-1];
    K1[8]='\0'; //premiere sous-clef K1
    /*nouvelle rotation circulaire gauche de 2 bits*/
    rg1=RotationGauche(rg,2);
    rd1=RotationGauche(rd,2);
    /*Combinaisons de la sortie sur la deuxieme rotation circulaire gauche*/
    for (i=0;i<5;i++)
    {
        rgrd[i]=rg1[i];
        rgrd[i+5]=rd1[i];
    }
    rgrd[10]='\0';
    /*Operation sur la seconde sous-clef K2*/
    for (i=0;i<8;i++)
    {
        K2[i]=rgrd[TdP8[i]-1];
    }
    K2[8]='\0'; //seconde sous-clef K2
}
/*Méthode pour effectuer une rotation circulaire gauche sur une chaîne de bits*/
char *S_DES::RotationGauche(char *bs,int n)
{
    int taille=strlen(bs);
    char *char_ptr,prembit,*str;
    char_ptr = new char[taille +1];
    str=new char[taille+1];
    char_ptr=bs;
    int i,j;
    for (j=0;j<n;j++)
    {
        prembit=char_ptr[0];
        for (i=0;i<taille-1;i++)
        {
            str[i]=char_ptr[i+1];
        }
        str[taille-1]=prembit;
        char_ptr[taille]='\0';
        char_ptr=str;
    }
    char_ptr[taille]='\0';
    return(str);
}
/*Méthode pour convertir un caractère non signé en chaîne de bits*/
void S_DES::char_to_bits(unsigned char chaine)
{
    int i,bit;
    INPUT_BIT[8]='\0';
    for (i=7;i>=0;i--)
    {
        bit=chaine%2;
        chaine=chaine/2;
        if (bit!=0)
            INPUT_BIT[i]='1';
        else
            INPUT_BIT[i]='0';
    }
}
/*Méthode pour effectuer la permutation initiale*/
void S_DES::PI(char *input)
{
    int PIArray[8]={2,6,3,1,4,8,5,7};
    int i;
    PIOutput[8]='\0';
    for (i=0;i<8;i++)
    {
        PIOutput[i]=input[PIArray[i]-1];
    }
}
/*Méthode pour effectuer l'inverse de la permutation initiale*/
void S_DES::InversionPI(char *input)
{
    int InversionPIArray[8]={4,1,3,5,7,2,8,6};
    int i;
    InversionPIOutput[8]='\0';
    for (i=0;i<8;i++)
    {
        InversionPIOutput[i]=input[InversionPIArray[i]-1];
    }
}
/*Méthode pour effectuer le cryptage S-DES sur une entrée 8 bits*/
void S_DES::Crypter_Des(unsigned char input)
{
    char PIG[5],PIR[5],G1[5],D1[5];
    int i;
    INPUT=input;
    char_to_bits(INPUT);  //Convertit l'entrée en chaîne de bits
    PI(INPUT_BIT);        //Permutation initiale
    //gotoxy(1,1);
    printf("\nCryptage.");
    /*Diviser la sortie de la permutation initial en 2 parties*/
    for (i=0;i<4;i++)
    {
        PIG[i]=PIOutput[i];
        PIR[i]=PIOutput[i+4];
    }
    PIG[4]='\0';
    PIR[4]='\0';
    Fk(PIG,PIR,1);
    /*Diviser la sortie de Fk en 2 parties*/
    for (i=0;i<4;i++)
    {
        G1[i]=F1Output[i];
        D1[i]=F1Output[4+i];
    }
    G1[4]='\0';
    D1[4]='\0';
    /*les paramètres de chaîne sont échangés et utilisent la sous-clé K2*/
    Fk(D1,G1,2);
    /*Exécution de la permutation initial inverse sur la sortie de Funtion_F*/
    InversionPI(F1Output);
    /*La chaîne de chiffrement est reconvertie en caractère non signé et stockée
      en sortie de variable privée de cette classe*/
    getchar();
}

/*Méthode pour récupérer un caractère non signé à partir d'une chaîne de bits*/
void S_DES::GetChar()
{
    int i,j,in;
    unsigned char chaine=0;
    char *bs;
    bs=new char[10];
    bs=InversionPIOutput;
    if (strlen(bs)>10)
    {
        printf("\nTaille de la chaine incorrect");
        exit(0);
    }
    for (i=0;i<10;i++)
    {
        if (bs[i]=='1')
        {
            in=1;
            for (j=1;j<10-i;j++)
            {
                in=in*2;
            }
            chaine=chaine+in;
        }
    }
    OUTPUT=chaine;
}


/*Cette méthode XOR sur EP et ses sous-clés
  en fonction du paramètre k avec k = 1: sous-clé K1 k = 2: sous-clé K2*/
char *S_DES::XOR(char *ep,int k)
{
    char *output,*key;
    int i,taille;
    output=new char[strlen(ep)+1];
    key=new char[strlen(K1)+1];
    if (k==1)
    {
        strcpy(key,K1);
    } else
    {
        if (k==2)
        {
            strcpy(key,K2);
        } else
        {
            printf("\n\nmauvais choix pour le parametrage de la clef");
            getchar();
            exit(1);
        }
    }
    taille=strlen(K1);
    if (strlen(ep)!=taille)
    {
        printf("\ninput=%lu est equivalent K=%d",strlen(ep),taille);
        printf("\n\n erreur de sortie (taille incorrect) Entrez une autre clef");
        getchar();
        exit(1);
    }
    for (i=0;i<strlen(ep);i++)
    {
        if (ep[i]==key[i])
            output[i]='0';
        else
            output[i]='1';
    }
    output[strlen(ep)]='\0';
    return(output);
}
/*SBOX0 :definition de l'operation*/
char *S_DES::SBOX0(char *l)
{
    int S0[4][4]={1,0,3,2,  //S0 Matrix
        3,2,1,0,
        0,2,1,3,
        3,1,3,2
    };
    const char *bits[]={"00","01","10","11"};
    char gligne[3],gcolone[3];
    char *SO;
    int i,gl,gc,b;
    SO=new char[3];
    gligne[0]=l[0];
    gligne[1]=l[3];
    gcolone[0]=l[1];
    gcolone[1]=l[2];
    gligne[2]='\0';
    gcolone[2]='\0';
    for (i=0;i<4;i++)
    {
        if (strcmp(gligne,bits[i])==0)
            gl=i;
        if (strcmp(gcolone,bits[i])==0)
            gc=i;
    }
    b=S0[gl][gc];
    for (i=0;i<3;i++)
        SO[i]=bits[b][i];
    SO[3]='\0';
    return(SO);
}
/*SBOX1 : definition de l'operation*/
char *S_DES::SBOX1(char *l)
{
    int S0[4][4]={0,1,2,3,   //S1 Matrix
        2,0,1,3,
        3,0,1,0,
        2,1,0,3
    };
    const char *bits[]={"00","01","10","11"};
    char gligne[3],gcolone[3];
    char *SO;
    int i,gl,gc,b;
    SO=new char[3];
    gligne[0]=l[0];
    gligne[1]=l[3];
    gcolone[0]=l[1];
    gcolone[1]=l[2];
    gligne[2]='\0';
    gcolone[2]='\0';
    for (i=0;i<4;i++)
    {
        if (strcmp(gligne,bits[i])==0)
            gl=i;
        if (strcmp(gcolone,bits[i])==0)
            gc=i;
    }
    b=S0[gl][gc];
    for (i=0;i<3;i++)
        SO[i]=bits[b][i];
    SO[3]='\0';
    return(SO);
}

/*Le déchiffrement est juste l'inverse du chiffrement
  Ici, PI, InversionPI, E / P, SBOX1 et SBOX2 sont identiques
  Mais Fk opère d'abord sur la sous-clef K2 et
  puis sur la sous-clef K1*/
void S_DES::Decrypter_Des(unsigned char input)
{
    char PIG[5],PIR[5],G1[5],D1[5];
    int i;
    INPUT=input;
    char_to_bits(INPUT);
    PI(INPUT_BIT);        //permutation initial
    printf("\nDecryptage");
    for (i=0;i<4;i++)
    {
        PIG[i]=PIOutput[i];
        PIR[i]=PIOutput[i+4];
    }
    PIG[4]='\0';
    PIR[4]='\0';
    Fk(PIG,PIR,2);
    for (i=0;i<4;i++)
    {
        G1[i]=F1Output[i];
        D1[i]=F1Output[4+i];
    }
    G1[4]='\0';
    D1[4]='\0';
    Fk(D1,G1,1);
    InversionPI(F1Output);
    getchar();
}

void S_DES::Fk(char *linput,char *rinput,int key)
{
    int E_P[8]={4,1,2,3,2,3,4,1};
    int P4[4]={2,4,3,1};          //Opération sur le tableau P4
    int i;
    char epOutput[9],*XOR_Output,*GXOR,*DXOR;
    char *SBOX0_Output,*SBOX1_Output;
    char SBOX_Output[5];
    char P4_Output[5];
    char fk_Output[5];
    char Main_Output[9];
    /*Opération sur le tableau EP*/
    for (i=0;i<8;i++)
    {
        epOutput[i]=rinput[E_P[i]-1];
    }
    epOutput[8]='\0';
    /*XOR est appliqué sur la sortie EP et les sous-clé (K1 / K2)*/
    XOR_Output=XOR(epOutput,key);
    /*Divisez la sortie de xor en 2 parties*/
    GXOR=new char[strlen(XOR_Output)/2+1];
    DXOR=new char[strlen(XOR_Output)/2+1];
    for (i=0;i<strlen(XOR_Output)/2;i++)
    {
        GXOR[i]=XOR_Output[i];
        DXOR[i]=XOR_Output[i+4];
    }
    GXOR[4]=DXOR[4]='\0';
    /*opération SBOX0 à gauche 4 bits*/
    SBOX0_Output=SBOX0(GXOR);
    /*opération SBOX1 à gauche 4 bits*/
    SBOX1_Output=SBOX1(DXOR);
    /*Combinaison de la sortie 2 bits des deux SBOXES en une seule chaîne*/
    for (i=0;i<2;i++)
    {
        SBOX_Output[i]=SBOX0_Output[i];
        SBOX_Output[i+2]=SBOX1_Output[i];
    }
    SBOX_Output[4]='\0';
    /*Exécution de l'opération P4 sur la sortie SBOX*/
    for (i=0;i<4;i++)
    {
        P4_Output[i]=SBOX_Output[P4[i]-1];
    }
    P4_Output[4]='\0';
    /*opération XOR sur la sortie P4 4 bits et entrée gauche 4 bits de Funtion_F*/
    for (i=0;i<4;i++)
    {
        if (P4_Output[i]==linput[i])
            fk_Output[i]='0';
        else
            fk_Output[i]='1';
    }
    fk_Output[4]='\0';
    /*Concaténation de la sortie des 4 bits de l'opération XOR et entrée droite 4 bits de Fk*/
    for (i=0;i<4;i++)
    {
        Main_Output[i]=fk_Output[i];
        Main_Output[i+4]=rinput[i];
    }
    Main_Output[8]='\0';
    /*Affectation de cette chaîne concaténé à la variable privée 'F1Output'*/
    strcpy(F1Output,Main_Output);
}


/*Destructeur*/
S_DES::~S_DES(){
}
char *sfname,*tfname;
char key[11];
int main(void)
{
    //clrscr();
    unsigned char chaine,chaine1;
    int i,n=10,choice;
    while (1)
    {
    //    key = new char[11];
        sfname = new char[20];
        tfname = new char[20];
        menu_principal(&choice);
        //fflush(stdin);
        switch (choice)
        {
        case 1:
            menuC();
            DoEnDe(choice);
            break;
        case 2:
            menuD();
            DoEnDe(choice);
            break;
        case 3:
            exit(0);
        default:
            printf("\n Mauvais choix, entrez a nouveau \nAppuyez sur n'importe quelle touche pour revenir au menu principal..");
            getchar();
            break;
        }
    }
}


void menu_principal(int *c)
{
    //clrscr();
    printf("\nQue voulez-vous faire");
    printf("\n1. Crypter");
    printf("\n2. Decrypter");
    printf("\n3. Sortir");
    printf("\n\nEntrez votre choix");
    scanf("%d",c);
}
void menuC()
{
    //clrscr();
    sfname=new char[20];
    tfname=new char[20];
    char* key = new char[11];
    printf("%s\n",key);
    printf("\nMenu de cryptage\n\n");
    printf("\nEntrez le fichier a crypter: ");
    std::cin >> sfname;
    printf("\nEntrez le nom du fichier cible: ");
    std::cin >> tfname;
    printf("\nEntrez la clef de 10 bits: ");
    std::cin >> key;
    printf("\n\nNotez cette clé, car la même clé est utilisée pour le décryptage");
    //getch();
}
void menuD()
{
    //clrscr();
    sfname=new char[20];
    tfname=new char[20];
    char* key =new char[11];
    printf("\nMenu de decryptage\n\n");
    printf("\nEntrez le nom du fichier à déchiffrer: ");
    std::cin >> sfname;;
    printf("\nEntrez le nom du fichier cible: ");
    std::cin >> tfname;
    printf("\nEntrez la clef 10 bits: ");
    std::cin >> key;
}
int DoEnDe(int c)
{
    S_DES S(key);
    int i,n;
    n=10; //Nombre de tours
    unsigned char chaine;
    FILE *fp;
    FILE *ft;
    fp=fopen(tfname,"w");
    ft=fopen(sfname,"r");
    if (fp==NULL)
    {
        printf("\nErreur lors de l'ouverture du fichier cible");
        getchar();
        fclose(fp);
        return(0);
    }
    if (ft==NULL)
    {
        printf("\nErreur lors de l'ouverture du fichier source");
        getchar();
        fclose(ft);
        return(0);
    }
    while (fread(&chaine,1,1,ft)==1)
    {
        S.OUTPUT=chaine;
        for (i=0;i<n;i++)
        {
            if (c==1)
                S.Crypter_Des(S.OUTPUT);
            if (c==2)
                S.Decrypter_Des(S.OUTPUT);
        }
        fwrite(&S.OUTPUT,1,1,fp);
    }
    printf("\nTache accompli !");
    getchar();
    fclose(fp);
    fclose(ft);
    return(1);
}
