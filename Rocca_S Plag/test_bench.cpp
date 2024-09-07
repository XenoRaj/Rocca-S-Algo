#include <ap_int.h>
#include <hls_stream.h>
#include <stdlib.h>
#include <cstdio>
#include <cstring>

#include "aes-gcm.h"

typedef uint64_t us64 ;
typedef uint8_t us8;
#define WPA_PUT_BE64(a, val)				\
	do {						\
		(a)[0] = (us8) (((us64) (val)) >> 56);	\
		(a)[1] = (us8) (((us64) (val)) >> 48);	\
		(a)[2] = (us8) (((us64) (val)) >> 40);	\
		(a)[3] = (us8) (((us64) (val)) >> 32);	\
		(a)[4] = (us8) (((us64) (val)) >> 24);	\
		(a)[5] = (us8) (((us64) (val)) >> 16);	\
		(a)[6] = (us8) (((us64) (val)) >> 8);	\
		(a)[7] = (us8) (((us64) (val)) & 0xff);	\
	} while (0)

#define WPA_GET_BE64(a) ((((us64) (a)[0]) << 56) | (((us64) (a)[1]) << 48) | \
			 (((us64) (a)[2]) << 40) | (((us64) (a)[3]) << 32) | \
			 (((us64) (a)[4]) << 24) | (((us64) (a)[5]) << 16) | \
			 (((us64) (a)[6]) << 8) | ((us64) (a)[7]))
typedef uint8_t state_t[4][4];

const uint8_t Rcon[11] = {
  0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36 };

 void KeyExpansion(uint8_t* RoundKey, const uint8_t* Key)
{
  unsigned i, j, k;
  uint8_t tempa[4]; // Used for the column/row operations

  // The first round key is the key itself.
  for (i = 0; i < Nk; ++i)
  {
    RoundKey[(i * 4) + 0] = Key[(i * 4) + 0];
    RoundKey[(i * 4) + 1] = Key[(i * 4) + 1];
    RoundKey[(i * 4) + 2] = Key[(i * 4) + 2];
    RoundKey[(i * 4) + 3] = Key[(i * 4) + 3];
  }

  // All other round keys are found from the previous round keys.
  for (i = Nk; i < Nb * (Nr + 1); ++i)
  {
    {
      k = (i - 1) * 4;
      tempa[0]=RoundKey[k + 0];
      tempa[1]=RoundKey[k + 1];
      tempa[2]=RoundKey[k + 2];
      tempa[3]=RoundKey[k + 3];

    }

    if (i % Nk == 0)
    {
      // This function shifts the 4 bytes in a word to the left once.
      // [a0,a1,a2,a3] becomes [a1,a2,a3,a0]

      // Function RotWord()
      {
        const uint8_t u8tmp = tempa[0];
        tempa[0] = tempa[1];
        tempa[1] = tempa[2];
        tempa[2] = tempa[3];
        tempa[3] = u8tmp;
      }

      // SubWord() is a function that takes a four-byte input word and
      // applies the S-box to each of the four bytes to produce an output word.

      // Function Subword()
      {
        tempa[0] = getSBoxValue(tempa[0]);
        tempa[1] = getSBoxValue(tempa[1]);
        tempa[2] = getSBoxValue(tempa[2]);
        tempa[3] = getSBoxValue(tempa[3]);
      }

      tempa[0] = tempa[0] ^ Rcon[i/Nk];
    }
#if defined(AES256) && (AES256 == 1)
    if (i % Nk == 4)
    {
      // Function Subword()
      {
        tempa[0] = getSBoxValue(tempa[0]);
        tempa[1] = getSBoxValue(tempa[1]);
        tempa[2] = getSBoxValue(tempa[2]);
        tempa[3] = getSBoxValue(tempa[3]);
      }
    }
#endif
    j = i * 4; k=(i - Nk) * 4;
    RoundKey[j + 0] = RoundKey[k + 0] ^ tempa[0];
    RoundKey[j + 1] = RoundKey[k + 1] ^ tempa[1];
    RoundKey[j + 2] = RoundKey[k + 2] ^ tempa[2];
    RoundKey[j + 3] = RoundKey[k + 3] ^ tempa[3];
  }
}



// This function adds the round key to state.
// The round key is added to the state by an XOR function.
void AddRoundKey(uint8_t round, state_t* state, const uint8_t* RoundKey)
{
  uint8_t i,j;
  for (i = 0; i < 4; ++i)
  {
    for (j = 0; j < 4; ++j)
    {
      (*state)[i][j] ^= RoundKey[(round * Nb * 4) + (i * Nb) + j];
    }
  }
}

// The SubBytes Function Substitutes the values in the
// state matrix with values in an S-box.
void SubBytes(state_t* state)
{
  uint8_t i, j;
  for (i = 0; i < 4; ++i)
  {
    for (j = 0; j < 4; ++j)
    {
      (*state)[j][i] = getSBoxValue((*state)[j][i]);
    }
  }
}

// The ShiftRows() function shifts the rows in the state to the left.
// Each row is shifted with different offset.
// Offset = Row number. So the first row is not shifted.
void ShiftRows(state_t* state)
{
  uint8_t temp;

  // Rotate first row 1 columns to left
  temp           = (*state)[0][1];
  (*state)[0][1] = (*state)[1][1];
  (*state)[1][1] = (*state)[2][1];
  (*state)[2][1] = (*state)[3][1];
  (*state)[3][1] = temp;

  // Rotate second row 2 columns to left
  temp           = (*state)[0][2];
  (*state)[0][2] = (*state)[2][2];
  (*state)[2][2] = temp;

  temp           = (*state)[1][2];
  (*state)[1][2] = (*state)[3][2];
  (*state)[3][2] = temp;

  // Rotate third row 3 columns to left
  temp           = (*state)[0][3];
  (*state)[0][3] = (*state)[3][3];
  (*state)[3][3] = (*state)[2][3];
  (*state)[2][3] = (*state)[1][3];
  (*state)[1][3] = temp;
}
uint8_t xtime(uint8_t x)
{
  return ((x<<1) ^ (((x>>7) & 1) * 0x1b));
}

// MixColumns function mixes the columns of the state matrix
void MixColumns(state_t* state)
{
  uint8_t i;
  uint8_t Tmp, Tm, t;
  for (i = 0; i < 4; ++i)
  {
    t   = (*state)[i][0];
    Tmp = (*state)[i][0] ^ (*state)[i][1] ^ (*state)[i][2] ^ (*state)[i][3] ;
    Tm  = (*state)[i][0] ^ (*state)[i][1] ; Tm = xtime(Tm);  (*state)[i][0] ^= Tm ^ Tmp ;
    Tm  = (*state)[i][1] ^ (*state)[i][2] ; Tm = xtime(Tm);  (*state)[i][1] ^= Tm ^ Tmp ;
    Tm  = (*state)[i][2] ^ (*state)[i][3] ; Tm = xtime(Tm);  (*state)[i][2] ^= Tm ^ Tmp ;
    Tm  = (*state)[i][3] ^ t ;              Tm = xtime(Tm);  (*state)[i][3] ^= Tm ^ Tmp ;
  }
}
void rs(uint8_t X[])
{
  bool set=false,carry=false;
  for(int i=0;i<Blocks;i++)
  {
      set=(X[i]&1);//check if 0th bit is set so that instead of falling away it can get carried over to next block
      X[i]>>=1;
      if(carry)// if rightmost bit of previous block fell off during rs, then set leftmost bit of this block
      X[i]|=(1<<7);
      if(set)
      carry=true;
      else
      carry=false;
  }
}


// Cipher is the main function that encrypts the PlainText.
void Cipher(state_t* state, const uint8_t* RoundKey)
{
  uint8_t round = 0;

  // Add the First round key to the state before starting the rounds.
  AddRoundKey(0, state, RoundKey);


  for (round = 1; ; ++round)
  {


	SubBytes(state);



    ShiftRows(state);



    if (round == Nr) {

      break;
    }
    MixColumns(state);


    AddRoundKey(round, state, RoundKey);


  }
  // Ad round key to last round

  AddRoundKey(Nr, state, RoundKey);


}



void print_blocks(uint8_t X[1500],int len)
{ printf("\n");
  for(int i=0;i<len;i++)
  {   if(X[i]==0)
      printf("00");
      else if(X[i]<16)
      printf("0%x",X[i]);
      else
      printf("%x",X[i]);
    if(i!=0&&(i+1)%Blocks==0)
    printf("\n");
  }
}


void AES_cipher(uint8_t in[],uint8_t key[]){
	Cipher((state_t*)in,key);
}

uint8_t* XOR(uint8_t X[],uint8_t Y[],int blocks=16)
{   uint8_t *res=(uint8_t*)malloc(blocks*sizeof(uint8_t));
    for(int i=0;i<blocks;i++)
    res[i] = X[i]^Y[i];
    return res;
}
// replace 16 with Blocks everywhere
uint8_t* dot(uint8_t X[],uint8_t Y[])
{
  uint8_t *V=(uint8_t*)malloc(16*sizeof(uint8_t));
  uint8_t *Z0=(uint8_t*)malloc(16*sizeof(uint8_t));
  for(int i=0;i<16;i++)
  Z0[i]=0x0;
  uint8_t R[16]={0};
  R[0]=0xE1;
  memcpy (V,Y, 16*sizeof(uint8_t));
  for(int i=0;i<=127;i++)
	{   int bid=i/8;
      int off_r=7-(i-bid*8);
      if((X[bid]&(1<<off_r)))//consider X to X[0,1,2.. 127], check if X[i]==0 , where 0<=i<=127
      {
          Z0=XOR(Z0,V);//potential memory leak, old Zi still allocated but now Zi+1 allocated another memory
      }
			  //Z=XOR(Z,V);//potential memory leak, old Zi still allocated but now Zi+1 allocated another memory
		  if(V[Blocks-1]&1)
      {
          rs(V);
          V=XOR(V,R);
      }
      else
      {
          rs(V);
          //potential memory leak, old Vi still allocated but now Vi+1 allocated another memory
      }
	}
	return Z0;

}
//testing offset block access , similar access is reqd in GHASH, to process array starting from X[Blocks*i], we send address X+Blocks*i


uint8_t* GHASH(uint8_t *H,uint8_t *X,int X_lenbits)//,)
{
    int m=X_lenbits/128;
    uint8_t *Y0=(uint8_t*)malloc(16*sizeof(uint8_t));
    for(int i=0;i<16;i++)
    Y0[i]=0x0;
    uint8_t *xpos=X;
    for(int i=0;i<m;i++)
    {

        Y0=XOR(Y0,X+16*i);////potential memory leak, old Vi still allocated but now Vi+1 allocated another memory
        Y0=dot(Y0,H);//leaky implementation , memory Y0 was previously pointing to ,doesn't get deallocated

        xpos += 16;
    }
    return Y0;

}
uint8_t* inc(uint8_t X[],int s)// s mod 8 == 0
{
    int rmostblocks=s/8;
    uint8_t *res=(uint8_t*)malloc(sizeof(uint8_t)*Blocks);
    memcpy(res,X,sizeof(uint8_t)*Blocks);
    bool carry=true;// else won't even run for right most block
    for(int i=Blocks-1;i>=(Blocks-rmostblocks)&&carry;i--)
    {
      res[i]++;
      if(res[i]!=0x00)
      carry=false;
    }
    return res;
}
uint8_t* GCTR(uint8_t key[],uint8_t ICB[],uint8_t X[],int X_lenbits)
{   int comp_blocks=X_lenbits/128;// #comp_blocks of 16 bytes X_lebnits/n complete blocks(128 bit)
    int lo_bytes=(X_lenbits-comp_blocks*128)/8;
    uint8_t *Y=(uint8_t*)malloc(sizeof(uint8_t)*(Blocks*comp_blocks+lo_bytes));
    int CB_blocks=((X_lenbits%128==0)?comp_blocks:(comp_blocks+1));
    uint8_t *CB=(uint8_t*)malloc(sizeof(uint8_t)*(Blocks*CB_blocks));
    memcpy(CB,ICB,sizeof(uint8_t)*Blocks);//copy ICB into CB0

    for(int i=1;i<CB_blocks;i++)// CBi=inc(CBi-1,32) for  1<=i<=n-1
    {
      uint8_t *tmp=inc(CB+16*(i-1),32);// store inc result in res, then copy to CBi
      memcpy(CB+16*i,tmp,sizeof(uint8_t)*Blocks);
      //free(tmp);// to recover memory
    }

    // encrypt CBs with key
    for(int i=0;i<CB_blocks;i++)
      AES_cipher(CB+16*i,key);// CBi=CIPH(CBi,key) where 0<=i<=n-1, here CBi is itself the starting of a 128bit/16B block, hence we do CB+16*i

    for(int i=0;i<comp_blocks;i++)
    {
        uint8_t *tmp=XOR(X+16*i,CB+16*i);// tmp=Xi XOR CIPH(CBi)

        memcpy(Y+16*i,tmp,sizeof(uint8_t)*Blocks);// Yi=tmp = Xi XOR CIPH(CBi)

    }

    memcpy(Y+16*comp_blocks,XOR(X+16*comp_blocks,CB+16*comp_blocks,lo_bytes),sizeof(uint8_t)*lo_bytes);
    return Y;
}

uint8_t * GCM_AE(uint8_t IV[],uint8_t P[],uint8_t A[],uint64_t IV_lenbits,uint64_t P_lenbits,uint64_t A_lenbits, uint8_t key[],uint8_t *Tag,uint8_t T_lenbits)
{   uint8_t ExpKey[AES_keyExpSize]={0};
	KeyExpansion(ExpKey,key);
	uint8_t *H=(uint8_t*)malloc(Blocks*sizeof(uint8_t));

//	  printf(" print here ExpKey\n: ");
//	    for (int i = 0; i < AES_keyExpSize; i++) {
//	        printf("%02x ", ExpKey[i]);
//	    }
	    printf("\n");
    for(int i=0;i<Blocks;i++)
      H[i]=0x00;
//    printf("\n H blocks\n");
//    print_blocks(H,16);
    AES_cipher(H,ExpKey); 
//    printf("\n H blocks\n");
//    print_blocks(H,16);
    uint8_t *J0=(uint8_t*)malloc(Blocks*sizeof(uint8_t));
    for(int i=0;i<Blocks;i++)
        J0[i]=0x00;
    if(IV_lenbits==96)
    {
      memcpy(J0,IV,sizeof(uint8_t)*12);
      J0[15]=0x01;
    }
    else
    {
      uint64_t s=128*((uint64_t)ceil((float)IV_lenbits/128.0))-IV_lenbits;
      uint64_t hblock_len=(IV_lenbits+s+64+64)/8;//how many of 8 bits blocks the payload for hash would be
      uint8_t *hash_payload=(uint8_t*)malloc(hblock_len*sizeof(uint8_t));
      for(int i=0;i<hblock_len;i++)
        hash_payload[i]=0x00;
      memcpy(hash_payload,IV,sizeof(uint8_t)*(IV_lenbits/8));//copying IV to starting of payload, need IV len in blocks of 8 bits, those blocks will be copied
      //divide by 8 after taking sum of IV lenbits+s+64, to avoid loss due to truncation


      WPA_PUT_BE64(hash_payload+sizeof(uint8_t)*(IV_lenbits/8+(s+64)/8),IV_lenbits);

      J0=GHASH(H,hash_payload,hblock_len*8);
    }

    uint8_t *J0_inc=inc(J0,32);

    uint8_t* C=GCTR(ExpKey,J0_inc,P,P_lenbits);

    //step 4
    uint64_t u=128*((uint64_t)ceil(((float)P_lenbits/128.0)))-P_lenbits;//replace with cipher lenbits
    uint64_t v=128*((uint64_t)ceil(((float)A_lenbits/128.0)))-A_lenbits;

    //step 5
    uint64_t hblock_len=(A_lenbits+v+P_lenbits+u+64+64)/8;//replace P_lenbits with C_lenbits
    uint8_t *hash_payload=(uint8_t*)malloc(hblock_len*sizeof(uint8_t));
    for(int i=0;i<hblock_len;i++)
        hash_payload[i]=0x00;
    memcpy(hash_payload,A,sizeof(uint8_t)*(A_lenbits/8));
    memcpy(hash_payload+sizeof(uint8_t)*((A_lenbits+v)/8),C,sizeof(uint8_t)*(P_lenbits/8));//replace P_lenbits with C_lenbits

    WPA_PUT_BE64(hash_payload+sizeof(uint8_t)*((A_lenbits+v+P_lenbits+u)/8),A_lenbits);

    WPA_PUT_BE64(hash_payload+sizeof(uint8_t)*((A_lenbits+v+P_lenbits+u+64)/8),P_lenbits);

    uint8_t *S=GHASH(H,hash_payload,hblock_len*8);


    uint8_t *Tag_tmp=GCTR(ExpKey,J0,S,128);//len of S is 128bits since its output of GHASH
    //try alternate

    // AES_cipher(J0,key);

    memcpy(Tag,Tag_tmp,sizeof(uint8_t)*T_lenbits/8);
    return C;

}
int test_GCM_AE()
{ // 60 B IV, 60 B PT
	  uint8_t key[32]={0xfe,0xff,0xe9,0x92,0x86,0x65,0x73,0x1c,0x6d,0x6a,0x8f,0x94,0x67,0x30,0x83,0x08,
	                  0xfe,0xff,0xe9,0x92,0x86,0x65,0x73,0x1c,0x6d,0x6a,0x8f,0x94,0x67,0x30,0x83,0x08};

	  uint8_t IV[Bytes]={0x93,0x13,0x22,0x5d,0xf8,0x84,0x06,0xe5,0x55,0x90,0x9c,0x5a,0xff,0x52,0x69,0xaa,
	                  0x6a,0x7a,0x95,0x38,0x53,0x4f,0x7d,0xa1,0xe4,0xc3,0x03,0xd2,0xa3,0x18,0xa7,0x28,
	                  0xc3,0xc0,0xc9,0x51,0x56,0x80,0x95,0x39,0xfc,0xf0,0xe2,0x42,0x9a,0x6b,0x52,0x54,
	                  0x16,0xae,0xdb,0xf5,0xa0,0xde,0x6a,0x57,0xa6,0x37,0xb3,0x9b,0x00,0x00,0x00,0x00};

	  uint8_t PT[Bytes]={0xd9,0x31,0x32,0x25,0xf8,0x84,0x06,0xe5,0xa5,0x59,0x09,0xc5,0xaf,0xf5,0x26,0x9a,
	                  0x86,0xa7,0xa9,0x53,0x15,0x34,0xf7,0xda,0x2e,0x4c,0x30,0x3d,0x8a,0x31,0x8a,0x72,
	                  0x1c,0x3c,0x0c,0x95,0x95,0x68,0x09,0x53,0x2f,0xcf,0x0e,0x24,0x49,0xa6,0xb5,0x25,
	                  0xb1,0x6a,0xed,0xf5,0xaa,0x0d,0xe6,0x57,0xba,0x63,0x7b,0x39,0x00,0x00,0x00,0x00};



	  uint8_t AAD[20]={0xfe,0xed,0xfa,0xce,0xde,0xad,0xbe,0xef,0xfe,0xed,0xfa,0xce,0xde,0xad,0xbe,0xef,
	                  0xab,0xad,0xda,0xd2};


//	  uint8_t IV[8]={0xca,0xfe,0xba,0xbe,0xfa,0xce,0xdb,0xad};

  uint8_t tmp[16]={0};
  uint64_t IV_lenbits=(sizeof(IV)/sizeof(uint8_t))*8;
  uint64_t P_lenbits=(sizeof(PT)/sizeof(uint8_t))*8;
  uint64_t A_lenbits=(sizeof(AAD)/sizeof(uint8_t))*8;
  //printf("%d %d %d\n",IV_lenbits,P_lenbits,A_lenbits);
  uint8_t T_lenbits=128;
  hls::stream<axis_data> in_s("input_stream"),out_s("output_stream");
  uint8_t IV_lenarr[8];
  WPA_PUT_BE64(IV_lenarr,IV_lenbits);
  uint8_t P_lenarr[8];
  WPA_PUT_BE64(P_lenarr,P_lenbits);
  uint8_t A_lenarr[8];
  WPA_PUT_BE64(A_lenarr,A_lenbits);


  axis_data local_read,local_write;

  ap_uint<64> iv_len;
  for(int i=0;i<8;i++)
	  iv_len.range((i+1)*8-1,i*8)=(ap_uint<8>)IV_lenarr[i];
  ap_uint<64> p_len;
  for(int i=0;i<8;i++)
	  p_len.range((i+1)*8-1,i*8)=(ap_uint<8>)P_lenarr[i];
  ap_uint<64> a_len;
  for(int i=0;i<8;i++)
	  a_len.range((i+1)*8-1,i*8)=(ap_uint<8>)A_lenarr[i];
  ap_uint<128> blk;
  blk.range(63,0)=(ap_uint<64>)iv_len;
  blk.range(127,64)=(ap_uint<64>)p_len;

  local_read.data=blk;
  local_read.last=0;
  in_s.write(local_read);

  blk.range(63,0)=(ap_uint<64>)a_len;
  blk.range(127,64)=(ap_uint<64>)T_lenbits;

  local_read.data=blk;
  // local_read.last=1;
  local_read.last=0;
  in_s.write(local_read);


  int comp_block=IV_lenbits/128;
  int lo=IV_lenbits/8-comp_block*16;
  for(int i=0;i<comp_block;i++)
  {
    for(int j=0;j<16;j++)
      blk.range((j+1)*8-1,j*8)=(ap_uint<8>)IV[i*16+j];
    local_read.data=blk;
    local_read.last=0;
    //printf("%x ",IV[i]);
    in_s.write(local_read);
  }
  if(lo!=0)
  {
    for(int l=0;l<lo;l++)
      blk.range((l+1)*8-1,l*8)=(ap_uint<8>)IV[comp_block*16+l];
    local_read.data=blk;
    local_read.last=0;
    in_s.write(local_read);
  }

  comp_block=P_lenbits/128;
  lo=P_lenbits/8-comp_block*16;
  for(int i=0;i<comp_block;i++)
  {
    for(int j=0;j<16;j++)
      blk.range((j+1)*8-1,j*8)=(ap_uint<8>)PT[i*16+j];
    local_read.data=blk;
    local_read.last=0;
    in_s.write(local_read);
  }
  if(lo!=0)
  {
    for(int l=0;l<lo;l++)
      blk.range((l+1)*8-1,l*8)=(ap_uint<8>)PT[comp_block*16+l];
    local_read.data=blk;
    local_read.last=0;
    in_s.write(local_read);
  }


  comp_block=A_lenbits/128;
  lo=A_lenbits/8-comp_block*16;
  for(int i=0;i<comp_block;i++)
  {
    for(int j=0;j<16;j++)
      blk.range((j+1)*8-1,j*8)=(ap_uint<8>)AAD[i*16+j];
    local_read.data=blk;
    local_read.last=0;
    in_s.write(local_read);
  }
  if(lo!=0)
  {
    for(int l=0;l<lo;l++)
      blk.range((l+1)*8-1,l*8)=(ap_uint<8>)AAD[comp_block*16+l];
    local_read.data=blk;
    local_read.last=0;
    in_s.write(local_read);
  }

  for(int i=0;i<AES_KEYLEN/16;i++)
  {
    for(int j=0;j<16;j++)
      blk.range((j+1)*8-1,j*8)=key[i*16+j];
    local_read.data=blk;
    if(i==AES_KEYLEN/16-1)
    local_read.last=1;
    else
    local_read.last=0;
    in_s.write(local_read);
  }
  GCM_AE_HW_1x8(in_s,out_s);

//read from output stream of HW

  uint8_t C_hw[Bytes],T_hw[16];
  comp_block=P_lenbits/128;
  lo=P_lenbits/8-comp_block*16;

 for(int i=0;i<comp_block;i++)
 {
	 local_write=out_s.read();
	 blk=local_write.data;
	 for(int j=0;j<16;j++)
		 C_hw[i*16+j]=(uint8_t)blk.range((j+1)*8-1,j*8);
	}
  if(lo!=0)
  {
    local_write=out_s.read();
    blk=local_write.data;
    for(int l=0;l<lo;l++)
    {
      C_hw[comp_block*16+l]=(uint8_t)blk.range((l+1)*8-1,l*8);
    }
  }

  local_write=out_s.read();
  blk=local_write.data;
 for(int i=0;i<T_lenbits/8;i++)
 {
   T_hw[i]=(uint8_t)blk.range((i+1)*8-1,i*8);
 }

   uint8_t *T_sw=(uint8_t*)malloc(sizeof(uint8_t)*16);
   uint8_t *C_sw=GCM_AE(IV,PT,AAD,IV_lenbits,P_lenbits,160,key,T_sw,128);
   printf("SW call made\n");
   printf("\nSoftware Cipher");
   print_blocks(C_sw,P_lenbits/8);
   printf("\nHardware Cipher");
   print_blocks(C_hw,P_lenbits/8);
   printf("\nSoftware Tag");
   print_blocks(T_sw,T_lenbits/8);
   printf("\nHardware Tag");
   print_blocks(T_hw,T_lenbits/8);
   if (0 != memcmp((char*) C_sw, (char*) C_hw, P_lenbits/8))
   			      {
	   printf("CiPhers don't match\n");
   			          //printf("SUCCESS!\n");
   			  	return 1;
   			      }
   if (0 != memcmp((char*) T_sw, (char*) T_hw,T_lenbits/8 ))
      			      {
      			          //printf("SUCCESS!\n");
	   printf("Tags don't match\n");
      			  	return 1;
      			      }
   return 0;
}
int main()
{
	//test_aes_encipher();
	printf("Welcome to main function\n");
	return  test_GCM_AE();
}
