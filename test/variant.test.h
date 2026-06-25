#include "test.h"
#include <stdlib.h>
#include <string.h>
#include <qlite.h>

// int ql_tests_run = 0;

TEST(test_encode_rfc_examples){
    uint8_t buf[8];

    EXPECT_EQ(ql_varint_encode(buf,sizeof(buf),37),1);
    EXPECT_EQ(buf[0],0x25);

    EXPECT_EQ(ql_varint_encode(buf,sizeof(buf),15293),2);
    EXPECT(memcmp(buf,(uint8_t[]){0x7B,0xBD},2)==0);

    EXPECT_EQ(ql_varint_encode(buf,sizeof(buf),494878333ULL),4);
    EXPECT(memcmp(buf,(uint8_t[]){0x9D,0x7F,0x3E,0x7D},4)==0);

    EXPECT_EQ(ql_varint_encode(buf,sizeof(buf),151288809941952652ULL),8);
    EXPECT(memcmp(buf,(uint8_t[]){0xC2,0x19,0x7C,0x5E,0xFF,0x14,0xE8,0x8C},8)==0);
}

TEST(test_decode_rfc_examples){
    ql_varint_t v;

    EXPECT_EQ(ql_varint_decode((uint8_t[]){0x25},1,&v),1);
    EXPECT_EQ(v,37);

    EXPECT_EQ(ql_varint_decode((uint8_t[]){0x7B,0xBD},2,&v),2);
    EXPECT_EQ(v,15293);

    EXPECT_EQ(ql_varint_decode((uint8_t[]){0x9D,0x7F,0x3E,0x7D},4,&v),4);
    EXPECT_EQ(v,494878333ULL);

    EXPECT_EQ(ql_varint_decode((uint8_t[]){0xC2,0x19,0x7C,0x5E,0xFF,0x14,0xE8,0x8C},8,&v),8);
    EXPECT_EQ(v,151288809941952652ULL);
}

TEST(test_boundary_values){
    ql_varint_t values[]={
        0,1,62,63,64,65,
        16382,16383,16384,16385,
        1073741822ULL,1073741823ULL,
        1073741824ULL,1073741825ULL,
        ((1ULL<<62)-2),((1ULL<<62)-1)
    };

    size_t count=sizeof(values)/sizeof(values[0]);

    for(size_t i=0;i<count;i++){
        uint8_t buf[8];
        ql_varint_t out;

        int enc=ql_varint_encode(buf,sizeof(buf),values[i]);
        EXPECT_GT(enc,0);

        int dec=ql_varint_decode(buf,enc,&out);

        EXPECT_EQ(dec,enc);
        EXPECT_EQ(out,values[i]);
    }
}

TEST(test_random_roundtrip){
    for(int i=0;i<100000;i++){
        ql_varint_t value=(((uint64_t)rand())<<31)^((uint64_t)rand());
        value&=((1ULL<<62)-1);

        uint8_t buf[8];
        ql_varint_t out;

        int enc=ql_varint_encode(buf,sizeof(buf),value);
        EXPECT_GT(enc,0);

        int dec=ql_varint_decode(buf,enc,&out);

        EXPECT_EQ(dec,enc);
        EXPECT_EQ(out,value);
    }
}

TEST(test_decode_errors){
    ql_varint_t out;

    EXPECT_LT(ql_varint_decode((uint8_t[]){0x7B},1,&out),0);
    EXPECT_LT(ql_varint_decode(NULL,0,&out),0);
    EXPECT_LT(ql_varint_decode((uint8_t[]){0xFF},1,&out),0);
}

TEST(test_pkt_num_encode_decode)
{
    uint8_t buf[4];
    int pn_len;
    uint64_t truncated_pn;
    ql_pkt_num_t decoded_pn;

    /*
     * Sender has acknowledged packet 990 and is about
     * to send packet 1000.
     */
    pn_len = ql_pkt_num_encode(buf, 1000, 990);

    /*
     * Only the least significant byte is needed:
     *
     * 1000 = 0x03E8
     * Sent = 0xE8
     */
    EXPECT_EQ(pn_len, 1);
    EXPECT_EQ(buf[0], 0xE8);

    /*
     * Receiver extracts the truncated packet number
     * from the wire.
     */
    truncated_pn = buf[0];

    /*
     * Receiver has already seen packet 999, so it
     * expects something close to 1000.
     */
    decoded_pn = ql_pkt_num_decode(
        truncated_pn,
        pn_len * 8,
        999);

    /*
     * The original packet number should be recovered.
     */
    EXPECT_EQ(decoded_pn, 1000);
}

TEST(test_pkt_num_decode_wrap)
{
    ql_pkt_num_t decoded_pn;

    /*
     * The wire only contains:
     *
     * 0x00
     *
     * This could mean:
     *
     *   0
     *   256
     *   512
     *   768
     *   ...
     *
     * Since we've already seen packet 255,
     * QUIC should reconstruct packet 256.
     */
    decoded_pn = ql_pkt_num_decode(
        0x00,
        8,
        255);

    EXPECT_EQ(decoded_pn, 256);
}

// int main(void){
//     RUN_TEST(test_encode_rfc_examples);
//     RUN_TEST(test_decode_rfc_examples);
//     RUN_TEST(test_boundary_values);
//     RUN_TEST(test_random_roundtrip);
//     RUN_TEST(test_decode_errors);
//     RUN_TEST(test_pkt_num_encode_decode);
//     RUN_TEST(test_pkt_num_decode_wrap);

//     ql_test_summary();
//     return 0;
// }