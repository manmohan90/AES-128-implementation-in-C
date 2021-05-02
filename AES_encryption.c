//MANMOHAN SINGH 
//AES-128 Encryption IMPLEMENTATION 

#include <stdio.h>
#include <stdint.h>
#define byte uint8_t
#define ull unsigned long long
#define ul unsigned long
byte S_Box[16][16] = {  
    {0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76},  
    {0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0},  
    {0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15},  
    {0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75},  
    {0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84},  
    {0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF},  
    {0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8},  
    {0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2},  
    {0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73},  
    {0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB},  
    {0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79},  
    {0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08},  
    {0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A},  
    {0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E},  
    {0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF},  
    {0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16}  
};  
byte Rcon[11] = {0x00 ,0x01 , 0x02 , 0x04 , 0x08 , 0x10 ,0x20 , 0x40 , 0x80 , 0x1b , 0x36 }; 

byte x[16]; //  array for 128 bit plaintext
byte x_mat[4][4]; //4x4 matrix for 128 bit plaintext
byte key[16]; //  array for 128 bit cipher key
byte key_mat[4][4]; //128 bit cipher key  in 4x4 matrix
byte round_keys[11][4][4]; //to store round keys    
//applying shift rows on x_mat
void shiftRows()
{
    byte x_shift[4][4]; // 4x4 matrix store values after shift rows operation
    for(int i=0;i<4;i++)
    {
        for(int j=0;j<4;j++)
        {
            int k =(i+j)%4;
            x_shift[i][j] = x_mat[i][k]; 
        }
    }
    for(int i=0;i<4;i++) 
   {
       for(int j=0;j<4;j++)
        x_mat[i][j]=x_shift[i][j];
   } 
} 
//multiplication function 
int mulfun(int a) {   
    int b;
    if((a&(0x80))==0) //if MSB is 0
      b = a<<1;
    else               // when MSB is 1
      b = (a<<1)^(0x1b);  
    return b;   
} 
//applying mix columns on x_mat 
void mixColumn()
{
   
    int temp_arr[4];  // temp array 
    byte x_mix[4][4];  //4x4 matrix store values after mix column operation
    for(int i=0; i<4; ++i)  
    {  
        for(int j=0; j<4; ++j)  
            temp_arr[j] = x_mat[j][i]; // taking column values in temp_arr
        x_mix[0][i] = (mulfun(temp_arr[0]))^(mulfun(temp_arr[1]))^temp_arr[1]^temp_arr[2]^temp_arr[3];   
        x_mix[1][i] = temp_arr[0]^(mulfun(temp_arr[1]))^(mulfun(temp_arr[2]))^temp_arr[2]^temp_arr[3];  
        x_mix[2][i] = temp_arr[0]^temp_arr[1]^(mulfun(temp_arr[2]))^(mulfun(temp_arr[3]))^temp_arr[3];  
        x_mix[3][i] = (mulfun(temp_arr[0]))^temp_arr[0]^temp_arr[1]^temp_arr[2]^(mulfun(temp_arr[3]));
    } 
    
   for(int i=0;i<4;i++)
   {
       for(int j=0;j<4;j++)
        x_mat[i][j]=x_mix[i][j];
   } 
}
//applying s-box for subbyte operation
byte s_box(byte value)
{
   int row = value>>4;   // getting row number
   int col = value&(0xf); // getting column number
   return S_Box[row][col];
}   
// applying subbyte operation
void subbytes()
{
   for(int i=0;i<4;i++)
   {
       for(int j=0;j<4;j++)
        x_mat[i][j] = s_box(x_mat[i][j]);
   }
} 
//generating  round key function 
void generateKey(int a)
{
   int temp_key[4][4]; //temp array for storing key bytes
   for(int j=0;j<4;j++)
   {
       if(j==0)
       {
           int temp_arr[4]; // this array contain the previous word
           for(int i=0;i<4;i++)
            temp_arr[i] = key_mat[i][3];
           //applying rotate word operation on temp_arr
           int rotate_arr[4]; //this array  stores after rotation
           for(int i=0;i<4;i++)
            rotate_arr[i] = temp_arr[(i+1)%4];
           //applying sub word opertation on output of rotate word operation
           for(int i=0;i<4;i++)
            rotate_arr[i] =  s_box(rotate_arr[i]);
           //taking XOR with round constant
            rotate_arr[0] ^=Rcon[a];
            
           for(int i=0;i<4;i++)
           {
               temp_key[i][j] = rotate_arr[i]^(key_mat[i][j]);
           }
       }
       else
       {
           for(int i=0;i<4;i++)
           {
               temp_key[i][j] = (temp_key[i][j-1])^(key_mat[i][j]);
           }

       }
   }
   for(int i=0;i<4;i++)
   {
       for(int j=0;j<4;j++)
       {
        key_mat[i][j]=temp_key[i][j];
        }
   }
}

//Add round key operation - AES encryption
void AddRoundKey_enc(int a)
{
    for(int i=0;i<4;i++)
    {
       for(int j=0;j<4;j++)
       {
         x_mat[i][j] = (x_mat[i][j])^(round_keys[a][i][j]);
       }
     }
} 
 
int main()
{
    printf("Input 128 bits plaintext:\n");
    for(int i=0;i<16;i++)
        scanf("%x",&x[i]); 
    int k=0;
    for(int j=0;j<4;j++)
    {
       for(int i=0;i<4;i++)
        { 
         x_mat[i][j] =x[k];
         k++;
        }  
    }
    printf("Input 128 bit cipher key   :\n");
    for(int i=0;i<16;i++)
        scanf("%x",&key[i]);
    k=0;
    for(int j=0;j<4;j++)
    {
       for(int i=0;i<4;i++)
        { 
         key_mat[i][j] =key[k];
         k++;
        }  
    } 
    // this is key expansion to store 11 round keys for encryption by Alice
    for(int rounds=0;rounds<11;rounds++)
    {
      if(rounds!=0)
       generateKey(rounds);  
      for(int i=0;i<4;i++)
      {
       for(int j=0;j<4;j++)
       {
        round_keys[rounds][i][j]=key_mat[i][j];
       }
      }    
    }   
    
    for(int i=0;i<11;i++)
    {
        if(i==0)
          AddRoundKey_enc(i);
        else // 10 round function  
        {
            subbytes();
            shiftRows();
            if(i!=10)
            mixColumn();
            AddRoundKey_enc(i);
        }
    }  
    printf("128-bit Ciphertext generated after 10 round function is :\n");
    for(int j=0;j<4;j++)
    {
        for(int i=0;i<4;i++)
         printf("%0.2x ",x_mat[i][j]);
       // printf(" ");
    }
    printf("\n");
     
}

/*   TEST CASES  
INPUT : 32 43 f6 a8 88 5a 30 8d 31 31 98 a2 e0 37 07 34
KEY   : 2b 7e 15 16 28 ae d2 a6 ab f7 15 88 09 cf 4f 3c
OUTPUT: 39 25 84 1d 02 dc 09 fb dc 11 85 97 19 6a 0b 32

INPUT : 00 11 22 33 44 55 66 77 88 99 aa bb cc dd ee ff
KEY   : 00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f 
OUTPUT: 69 c4 e0 d8 6a 7b 04 30 d8 cd b7 80 70 b4 c5 5a

*/