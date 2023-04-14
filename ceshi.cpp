#include <iostream>
#include <string>
#include <unistd.h>
#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/ssl.h>
#include <wolfssl/wolfcrypt/types.h>
#include <wolfssl/wolfcrypt/random.h>
#include <wolfssl/wolfcrypt/ecc.h>
#include <wolfssl/wolfcrypt/sp_int.h>
#include <wolfssl/wolfcrypt/integer.h>
#include <wolfssl/wolfcrypt/wolfmath.h>
#include <wolfssl/wolfcrypt/sha.h>
#include <wolfssl/wolfcrypt/error-crypt.h>
#include <wolfssl/wolfcrypt/hash.h>
#include <wolfssl/wolfcrypt/asn.h>
#include <wolfssl/wolfcrypt/aes.h>
//#include <wolfssl/wolfcrypt/sp.h>
using namespace std;
int ra_mul_G_test(){
	ecc_key key;
    int ret;
    WC_RNG rng;
    wc_ecc_init(&key);
    wc_InitRng(&rng);
    int curveId = ECC_SECP256R1;
    int keySize = wc_ecc_get_curve_size_from_id(curveId);
    ret = wc_ecc_make_key_ex(&rng, keySize, &key, curveId);
    if (ret != MP_OKAY) {
    // error handling
    }
    
    mp_int ra;
	mp_init(&ra);
	mp_int orderG;
	mp_init(&orderG);
	ret = mp_read_radix(&orderG,key.dp->order,16);
	if(ret != 0){
		cout<<"get_order error"<<endl;
		return -1;
		}
	ret = wc_ecc_gen_k(&rng,64,&ra,&orderG);
	if(ret != 0){
		cout<<"gen_ra error"<<endl;
		return -1;
		}
	
	mp_int a;
	mp_init(&a);
	ret = mp_read_radix(&a,key.dp->Af,16);
	
	mp_int b;
	mp_init(&b);
	ret = mp_read_radix(&b,key.dp->Bf,16);
	
	mp_int prime;
	mp_init(&prime);
	mp_read_radix(&prime,key.dp->prime,16);
	
	ecc_point* point_res;
	ecc_point* point_res2;
    ecc_point* point;
    point = wc_ecc_new_point();
    point_res = wc_ecc_new_point();
    point_res2 = wc_ecc_new_point();
    ret = wc_ecc_get_generator(point,curveId);
    cout<<"get generator: "<<ret<<endl;
    ret = wc_ecc_point_is_on_curve(point,ECC_SECP256R1);
    cout<<"point is on curve: "<<ret<<endl;
    //ret = wc_ecc_is_point(point,&a,&b,&prime);
    //cout<<"point is on curve method2: "<<ret<<endl;
    
    ret  = wc_ecc_mulmod(&ra,point,point_res,&a,&prime,1);
    cout<<"ra * point: "<<ret<<endl;
    
    ret = wc_ecc_point_is_on_curve(point_res,ECC_SECP256R1);
    cout<<"point_res is on curve: "<<ret<<endl;
    ret = wc_ecc_is_point(point_res,&a,&b,&prime);
    cout<<"point_res is on curve method2: "<<ret<<endl;
    
    mp_int setnum;
    mp_init(&setnum);
    ret = mp_set_int(&setnum,1);
    cout<<"setnum error: "<<ret<<endl;
    ret  = wc_ecc_mulmod(&setnum,point,point_res2,&a,&prime,1);
    cout<<"setnum * point: "<<ret<<endl;
    ret = wc_ecc_point_is_on_curve(point_res2,ECC_SECP256R1);
    cout<<"point_res2 is on curve: "<<ret<<endl;
    ret = wc_ecc_is_point(point_res2,&a,&b,&prime);
    cout<<"point_res2 is on curve method2: "<<ret<<endl;
    return 0;
	}
int test_eql(){
	ecc_key key;
    int ret;
    WC_RNG rng;
    wc_ecc_init(&key);
    wc_InitRng(&rng);
    int curveId = ECC_SECP256R1;
    int keySize = wc_ecc_get_curve_size_from_id(curveId);
    ret = wc_ecc_make_key_ex(&rng, keySize, &key, curveId);
    if (ret != MP_OKAY) {
    // error handling
    }
	
	mp_int num_radix;
	mp_int num_bin;
	mp_init(&num_radix);
	mp_init(&num_bin);
	const byte* a_byte = reinterpret_cast<const byte*>(key.dp->Af);
	ret = mp_read_radix(&num_radix,key.dp->Af,16);
	cout<<"num_radix: "<<ret<<endl;
	ret = mp_read_unsigned_bin(&num_bin,a_byte,64);
	cout<<"num_bin: "<<ret<<endl;
	ret = mp_cmp(&num_radix,&num_bin);
	cout<<"num_radix is equal to num_bin: "<<ret<<endl;
	return 0;
	
	}
	//ra_mul_G_and_is_on_curve() is ok
int ra_mul_G_and_is_on_curve(){
	ecc_key key;
    int ret;
    WC_RNG rng;
    wc_ecc_init(&key);
    wc_InitRng(&rng);
    int curveId = ECC_SECP256R1;
    int keySize = wc_ecc_get_curve_size_from_id(curveId);
    ret = wc_ecc_make_key_ex(&rng, keySize, &key, curveId);
    if (ret != MP_OKAY) {
    // error handling
    }
    
    mp_int a,b,prime,order,num;
    mp_init_multi(&a,&b,&prime,&order,&num,NULL);
    ret = mp_read_radix(&a,key.dp->Af,16);
    cout<<"get mp_int af: "<<ret<<endl;
    ret = mp_read_radix(&b,key.dp->Bf,16);
    cout<<"get mp_int bf: "<<ret<<endl;
    ret = mp_read_radix(&prime,key.dp->prime,16);
    cout<<"get mp_int prime: "<<ret<<endl;
    ret = mp_read_radix(&order,key.dp->order,16);
    cout<<"get mp_int order: "<<ret<<endl;
    ret = wc_ecc_gen_k(&rng,32,&num,&order);
    cout<<"get mp_int num: "<<ret<<endl;
    
    ecc_point* point = wc_ecc_new_point();
    ecc_point* point_res = wc_ecc_new_point();
    ret = wc_ecc_get_generator(point,wc_ecc_get_curve_idx(ECC_SECP256R1));
    cout<<"get ecc_point point: "<<ret<<endl;
    ret = wc_ecc_is_point(point,&a,&b,&prime);
    cout<<"point is on curve: "<<ret<<endl;
    ret = wc_ecc_mulmod(&num,point,point_res,&a,&prime,1);
    cout<<"get ecc_point point_res: "<<ret<<endl;
    ret = wc_ecc_is_point(point_res,&a,&b,&prime);
    cout<<"point_res is on curve: "<<ret<<endl;
	return 0;
	
	}
int merge_byte(byte* byte1,word32 byte1len,byte* byte2,word32 byte2len,byte* byteres,word32* bytereslen){
	word32 reslen = byte1len + byte2len;
	byte *res = (byte*)XMALLOC(reslen, NULL, DYNAMIC_TYPE_ECC_BUFFER);
	if(res == NULL){
		cout<<"-1"<<endl;
		return -1;
		}
	for(int i = 0;i<byte1len;i++){
		res[i] = byte1[i];
		}
	for(int i = 0;i<byte2len;i++){
		res[i+byte1len] = byte2[i];
		}
	printf("byte1 + byte2 :\n");
	for(int i = 0;i<reslen;i++){
		printf("%02x",res[i]);
		}
	cout<<endl;
	XMEMCPY(byteres, res, reslen);
	/*for(int i = 0;i<reslen;i++){
		byteres[i] = res[i];
		}
	*bytereslen = reslen;
	*/
	*bytereslen = reslen;
	XFREE(res,NULL, DYNAMIC_TYPE_ECC_BUFFER);
	return 0;
	
	
	}
int Aes_Message_Padding(byte* input,word32 inputlen,word32* outlen,byte* output){
	/*
	word32 re = inputlen % 16;
	if(re == 0){
		*outlen = inputlen;
		output = input;
		return 0;
		}
	*/
	word32  out;
	if(inputlen%16 == 0){
		out = inputlen;
		}else{
	    out = ((inputlen/16)+1)*16;
	    }
	byte* outputbuf ;
	outputbuf = (byte*)XMALLOC(out, NULL, DYNAMIC_TYPE_ECC_BUFFER);
	if(outputbuf == NULL){
		cout<<"-1"<<endl;
		return -1;
		}
	for(word32 i = 0;i < inputlen;i++){
		outputbuf[i] = input[i];
		} 
	for(word32 i = inputlen;i<out;i++){
		outputbuf[i] = 0x00;
		}
	//outputbuf[out] = '\0';
	cout<<"after padding"<<endl;
	for(int i = 0;i<out;i++){
		printf("%02x",outputbuf[i]);
		}
	cout<<endl;
	XMEMCPY(output, outputbuf, out);
	/*for(int i = 0;i<out;i++){
		output[i] = outputbuf[i];
		}*/
	cout<<endl;
	*outlen = out;
	XFREE(outputbuf,NULL, DYNAMIC_TYPE_ECC_BUFFER);
	return 0;

	}
//merge_and_pad_test() is ok	
int merge_and_pad_test(){
	ecc_key key;
    int ret;
    WC_RNG rng;
    wc_ecc_init(&key);
    wc_InitRng(&rng);
    int curveId = ECC_SECP256R1;
    int keySize = wc_ecc_get_curve_size_from_id(curveId);
    ret = wc_ecc_make_key_ex(&rng, keySize, &key, curveId);
    if (ret != MP_OKAY) {
    // error handling
    }
    
    byte bufpubkey[256] = {'0'};
    word32 bufpubkeylen = 256;
    ret = wc_ecc_export_point_der(curveId,&key.pubkey,bufpubkey,&bufpubkeylen);
    cout<<"export_pubkey error: "<<ret<<endl;
    cout<<"pubkey len: "<<bufpubkeylen<<endl;
    for(int i = 0;i<bufpubkeylen;i++){
		printf("%02x",bufpubkey[i]);
		}
	cout<<endl;
    
    mp_int privkey;
    mp_init(&privkey);
    mp_copy(&key.k,&privkey);
    
    int privkey_size = mp_unsigned_bin_size(&privkey);
    cout<<"export privkey len: "<<privkey_size<<endl;
    byte bufprivkey[privkey_size] = {'0'};
    ret = mp_to_unsigned_bin(&privkey,bufprivkey);
    cout<<"export privkey error: "<<ret<<endl;
    cout<<"bufprivkey:"<<endl;
    for(int i = 0;i<privkey_size;i++){
		printf("%02x",bufprivkey[i]);
		}
	cout<<endl;
	
	
	word32 buf_pubkey_privkey_len = bufpubkeylen + privkey_size;
	byte buf_pubkey_privkey[buf_pubkey_privkey_len];
	
	ret = merge_byte(bufpubkey,bufpubkeylen,bufprivkey,privkey_size,buf_pubkey_privkey,&buf_pubkey_privkey_len);
	cout<<"buf_pubkey_privkey_len: "<<buf_pubkey_privkey_len<<endl;
	cout<<"merge_byte error: "<<ret<<endl;
	for(int i = 0;i<buf_pubkey_privkey_len;i++){
		printf("%02x",buf_pubkey_privkey[i]);
		}
	cout<<endl;
	
	byte afterpad[128];
	word32 afterpadlen = 0;
	ret = Aes_Message_Padding(buf_pubkey_privkey,buf_pubkey_privkey_len,&afterpadlen,afterpad);
	cout<<"Aes_Message_Padding error: "<<ret<<endl;
	for(int i = 0;i<afterpadlen;i++){
		printf("%02x",afterpad[i]);
		}
	cout<<endl;
	cout<<"afterpadlen: "<<afterpadlen<<endl;
	return 0;
	}
int set_point_test(){
	ecc_key key;
    int ret;
    WC_RNG rng;
    wc_ecc_init(&key);
    wc_InitRng(&rng);
    int curveId = ECC_SECP256R1;
    int keySize = wc_ecc_get_curve_size_from_id(curveId);
    ret = wc_ecc_make_key_ex(&rng, keySize, &key, curveId);
    if (ret != MP_OKAY) {
    // error handling
    }
    
    //ecc_projective_add_point();
    word32 gxlen = mp_unsigned_bin_size(key.pubkey.x);
    cout<<"gxlen: "<<gxlen<<endl;
    word32 gylen = mp_unsigned_bin_size(key.pubkey.y);
    cout<<"gylen: "<<gylen<<endl;
    word32 pubkeyzlen = mp_unsigned_bin_size(key.pubkey.z);
    cout<<"pubkeyzlen: "<<pubkeyzlen<<endl;
    
    byte buf_z[1];
    mp_to_unsigned_bin(key.pubkey.z,buf_z);
    for(int i = 0;i<pubkeyzlen;i++){
		printf("%02x",buf_z[i]);
		}
	cout<<endl;
	
	mp_int a,b,prime,order,num;
    mp_init_multi(&a,&b,&prime,&order,&num,NULL);
    ret = mp_read_radix(&a,key.dp->Af,16);
    cout<<"get mp_int af: "<<ret<<endl;
    ret = mp_read_radix(&b,key.dp->Bf,16);
    cout<<"get mp_int bf: "<<ret<<endl;
    ret = mp_read_radix(&prime,key.dp->prime,16);
    cout<<"get mp_int prime: "<<ret<<endl;
    ret = mp_read_radix(&order,key.dp->order,16);
    cout<<"get mp_int order: "<<ret<<endl;
    ret = wc_ecc_gen_k(&rng,32,&num,&order);
    cout<<"get mp_int num: "<<ret<<endl;
    
    ecc_point* point = wc_ecc_new_point();
    ecc_point* point_res = wc_ecc_new_point();
    ret = wc_ecc_get_generator(point,wc_ecc_get_curve_idx(ECC_SECP256R1));
    cout<<"get ecc_point point: "<<ret<<endl;
    ret = wc_ecc_is_point(point,&a,&b,&prime);
    cout<<"point is on curve: "<<ret<<endl;
    ret = wc_ecc_mulmod(&num,point,point_res,&a,&prime,1);
    cout<<"get ecc_point point_res: "<<ret<<endl;
    ret = wc_ecc_is_point(point_res,&a,&b,&prime);
    cout<<"point_res is on curve: "<<ret<<endl;
    
    byte bufp_res[256] = {'0'};
    word32 bufp_res_len = 256;
    ret = wc_ecc_export_point_der(curveId,point_res,bufp_res,&bufp_res_len);
    cout<<"export point_res error: "<<ret<<endl;
    cout<<"point_res len: "<<bufp_res_len<<endl;
    for(int i = 0;i<bufp_res_len;i++){
		printf("%02x",bufp_res[i]);
		}
	cout<<endl;
	byte point_res_x[32];
	byte point_res_y[32];
	//byte point_res_[1];
	ret = mp_to_unsigned_bin(point_res->x,point_res_x);
	cout<<"export point_res_x error: "<<ret<<endl;
	for(int i = 0;i<32;i++){
		printf("%02x",point_res_x[i]);
		}
	cout<<endl;
	ret = mp_to_unsigned_bin(point_res->y,point_res_y);
	cout<<"export point_res_y error: "<<ret<<endl;
	for(int i = 0;i<32;i++){
		printf("%02x",point_res_y[i]);
		}
	cout<<endl;
	
    word32 p_res_z_len = mp_unsigned_bin_size(point_res->z);
    cout<<"p_res_z_len: "<<p_res_z_len<<endl;
    byte point_res_z[p_res_z_len];
    
    ret = mp_to_unsigned_bin(point_res->z,point_res_z);
	cout<<"export point_res_z error: "<<ret<<endl;
	for(int i = 0;i<p_res_z_len;i++){
		printf("%02x",point_res_z[i]);
		}
	cout<<endl;
	
	mp_int new_p_x,new_p_y,new_p_z;
	mp_init_multi(&new_p_x,&new_p_y,&new_p_z,NULL,NULL,NULL);
	mp_read_unsigned_bin(&new_p_x,point_res_x,32);
	mp_read_unsigned_bin(&new_p_y,point_res_y,32);
	mp_read_unsigned_bin(&new_p_z,point_res_z,1);
	ecc_point *point_new = wc_ecc_new_point();
	mp_copy(&new_p_x,point_new->x);
	mp_copy(&new_p_y,point_new->y);
	mp_copy(&new_p_z,point_new->z);
    ret = wc_ecc_cmp_point(point_res,point_new);
    cout<<"point_res is equal to point_new: "<<ret<<endl;
    return 0;
	}
int two_point_add_equal_num_mul_point_test(){
	ecc_key key;
    int ret;
    WC_RNG rng;
    wc_ecc_init(&key);
    wc_InitRng(&rng);
    int curveId = ECC_SECP256R1;
    int keySize = wc_ecc_get_curve_size_from_id(curveId);
    ret = wc_ecc_make_key_ex(&rng, keySize, &key, curveId);
    if (ret != MP_OKAY) {
    // error handling
    }
    
    //ecc_projective_add_point();
    ecc_point *point_a = wc_ecc_new_point();
    ecc_point *point_b = wc_ecc_new_point();
    
    mp_int num1,num2,num3;
    mp_init(&num1);
    mp_init(&num2);
    mp_init(&num3);
    mp_set_int(&num1,23);
    mp_set_int(&num2,45);
    mp_add(&num1,&num2,&num3);
    
    mp_int a,b,prime,order,num;
    mp_init_multi(&a,&b,&prime,&order,&num,NULL);
    ret = mp_read_radix(&a,key.dp->Af,16);
    cout<<"get mp_int af: "<<ret<<endl;
    ret = mp_read_radix(&b,key.dp->Bf,16);
    cout<<"get mp_int bf: "<<ret<<endl;
    ret = mp_read_radix(&prime,key.dp->prime,16);
    cout<<"get mp_int prime: "<<ret<<endl;
    ret = mp_read_radix(&order,key.dp->order,16);
    cout<<"get mp_int order: "<<ret<<endl;
    ret = wc_ecc_gen_k(&rng,32,&num,&order);
    cout<<"get mp_int num: "<<ret<<endl;
    
    ecc_point* point = wc_ecc_new_point();
    //ecc_point* point_res = wc_ecc_new_point();
    ret = wc_ecc_get_generator(point,wc_ecc_get_curve_idx(ECC_SECP256R1));
    cout<<"get ecc_point point: "<<ret<<endl;
    
    ret = wc_ecc_mulmod(&num1,point,point_a,&a,&prime,1);
    cout<<"num1 * point: "<<ret<<endl;
    ret = wc_ecc_mulmod(&num2,point,point_b,&a,&prime,1);
    cout<<"num2 * point: "<<ret<<endl;
    
    mp_int ka,kb;
    mp_init(&ka);
    mp_init(&kb);
    mp_set_int(&ka,1);
    mp_set_int(&kb,1);
    
    ecc_point* point_c = wc_ecc_new_point();
    
    ret = ecc_mul2add(point_a,&ka,point_b,&kb,point_c,&a,&prime,NULL);
    cout<<"ecc_mul2add: "<<ret<<endl;
    
    ecc_point* point_d = wc_ecc_new_point();
    ret = wc_ecc_mulmod(&num3,point,point_d,&a,&prime,1);
    cout<<"num3 * point: "<<ret<<endl; 
    
    ret = wc_ecc_cmp_point(point_c,point_d);
    cout<<"point_c is equal to point_d: "<<ret<<endl;
    
    
	return 0;
	}

int hash_to_mp_int(const byte * inbuf,mp_int * num){
	byte buf[20] = "0";
	//cout<<buf1<<endl;
	int err ;
	err = wc_ShaHash(inbuf,20,buf);
	printf("shahash:\n");
	for(int i = 0;i<20;i++){
		printf("%02x",buf[i]);
		}
	cout<<endl;
	const byte *buf3 = buf;
	
	err = mp_read_unsigned_bin(num,buf3,20);
	cout<<"hash_to_mp_int: "<<err<<endl;
	return err;
	}
int show(const mp_int *a){
	int err4 = 0;
	char  str1[64] = {'1'};
    int leng = 0;
    err4 = mp_toradix(a,str1,16);   
    cout<<err4<<endl;
    cout<<str1<<endl;
    return 0;
	}

int main(){
	
	ecc_key key;
    int ret;
    WC_RNG rng;
    wc_ecc_init(&key);
    wc_InitRng(&rng);
    int curveId = ECC_SECP256R1;
    int keySize = wc_ecc_get_curve_size_from_id(curveId);
    ret = wc_ecc_make_key_ex(&rng, keySize, &key, curveId);
    if (ret != MP_OKAY) {
    // error handling
    }
    //merge_and_pad_test();
    
	mp_int a,b,prime,order,ra,s;
    mp_init_multi(&a,&b,&prime,&order,&ra,&s);
    ret = mp_read_radix(&a,key.dp->Af,16);
    cout<<"get mp_int af: "<<ret<<endl;
    ret = mp_read_radix(&b,key.dp->Bf,16);
    cout<<"get mp_int bf: "<<ret<<endl;
    ret = mp_read_radix(&prime,key.dp->prime,16);
    cout<<"get mp_int prime: "<<ret<<endl;
    ret = mp_read_radix(&order,key.dp->order,16);
    cout<<"get mp_int order: "<<ret<<endl;
    ret = wc_ecc_gen_k(&rng,32,&ra,&order);
    cout<<"get mp_int ra: "<<ret<<endl;
    ret = mp_copy(&key.k,&s);
    cout<<"get mp_int s: "<<ret<<endl;
    
    ecc_point* pointG = wc_ecc_new_point();
    ret = wc_ecc_get_generator(pointG,wc_ecc_get_curve_idx(ECC_SECP256R1));
    cout<<"get ecc_point pointG: "<<ret<<endl;
    ret = wc_ecc_is_point(pointG,&a,&b,&prime);
    cout<<"point is on curve: "<<ret<<endl;
    
    mp_int da,z1,h_ecuid1;
    mp_init(&da);
    mp_init(&z1);
    mp_init(&h_ecuid1);
    byte ecuid[] = {"ecuid1"};
    ret = hash_to_mp_int(ecuid,&h_ecuid1);
    cout<<"hash ecuid1: "<<ret<<endl;
    ret = mp_mulmod(&ra,&h_ecuid1,&prime,&z1);
    show(&h_ecuid1);
    cout<<"z1 = ra * h_ecuid1: "<<ret<<endl;
    ret = mp_addmod(&s,&z1,&prime,&da);
    cout<<"da: "<<ret<<endl;
    
    ecc_point* RA = wc_ecc_new_point();
    ret = wc_ecc_mulmod(&ra,pointG,RA,&a,&prime,1);
    cout<<"RA: "<<ret<<endl;
    
    mp_int SA,za,z2;
    mp_init_multi(&SA,&za,&z2,NULL,NULL,NULL);
    ret = wc_ecc_gen_k(&rng,32,&za,&order);
    cout<<"get mp_int za: "<<ret<<endl;
    show(&h_ecuid1);
    ret = mp_mulmod(&za,&h_ecuid1,&prime,&z2);
    cout<<"z2= za * h_ecuid1: "<<ret<<endl;
    ret = mp_addmod(&da,&z2,&prime,&SA);
    cout<<"SA: "<<ret<<endl;
    
    ecc_point* ZA = wc_ecc_new_point();
    ret = wc_ecc_mulmod(&za,pointG,ZA,&a,&prime,1);
    cout<<"ZA: "<<ret<<endl;
    
    ecc_point* XA = wc_ecc_new_point();
    ecc_point* XA1 = wc_ecc_new_point();
    mp_int k1,k2,xa;
    mp_init(&k1);
    mp_init(&k2);
    mp_init(&xa);
    mp_add(&ra,&za,&xa);
    mp_set_int(&k1,1);
    mp_set_int(&k2,1);
    ret = ecc_mul2add(RA,&k1,ZA,&k2,XA,&a,&prime,NULL);
    cout<<"XA: "<<ret<<endl;
    
    ret = wc_ecc_mulmod(&xa,pointG,XA1,&a,&prime,1);
    cout<<"XA1: "<<ret<<endl;
    
    ret = wc_ecc_cmp_point(XA,XA1);
    cout<<"XA is equal to XA1: "<<ret<<endl;
    ret = wc_ecc_point_is_on_curve(XA,wc_ecc_get_curve_idx(ECC_SECP256R1));
    cout<< "XA is on curve: "<<ret<<endl;
    
    ecc_point * Ppub = wc_ecc_new_point();
    ret = wc_ecc_copy_point(&key.pubkey,Ppub);
    cout<<"Ppub: "<<ret<<endl;
    
    ecc_point * Ppub1 = wc_ecc_new_point();
    ret = wc_ecc_mulmod(&s,pointG,Ppub1,&a,&prime,1);
    cout<<"Ppub1: "<<ret<<endl;
    
    ret = wc_ecc_cmp_point(Ppub,Ppub1);
    cout<<"Ppub is equal to Ppub1: "<<ret<<endl;
    
    ecc_point *PA = wc_ecc_new_point();
    ret = wc_ecc_mulmod(&SA,pointG,PA,&a,&prime,1);
    
    ecc_point *H_XA = wc_ecc_new_point();
    ecc_point *PA1 = wc_ecc_new_point();
    ret = wc_ecc_mulmod(&h_ecuid1,XA,PA1,&a,&prime,1);
    cout<<"H_XA: "<<ret<<endl;
    ret = ecc_mul2add(Ppub,&k1,H_XA,&k2,PA1,&a,&prime,NULL);
    cout<<"PA1: "<<ret<<endl;
    ret = wc_ecc_cmp_point(PA,PA1);
    cout<<"PA is equal to PA1: "<<ret<<endl;
    show(PA->x);
    show(PA1->x);
    show(PA->y);
    show(PA1->y);
    show(PA->z);
    show(PA1->z);
	
	return 0;
	}
