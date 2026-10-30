#include "../src/watermark_code.h"
#include <random>
#include <iostream>
using namespace fg;
int main(){
    std::string key="QA ONLY - not a production key";std::mt19937 rng(921814);
    int tests=0;auto require=[&](bool ok){tests++;if(!ok)throw std::runtime_error("Codec test failed: "+std::to_string(tests));};
    for(int sample=0;sample<12;sample++){
        std::vector<unsigned char>idbytes(8);for(auto&b:idbytes)b=(unsigned char)rng();auto id=hex(idbytes.data(),8),code=ecc_payload(id,key);
        for(int errors=0;errors<=18;errors++){
            auto noisy=unhex(code);std::vector<int>order(255);std::iota(order.begin(),order.end(),0);std::shuffle(order.begin(),order.end(),rng);
            for(int j=0;j<errors;j++)noisy[order[j]/8]^=1<<(7-order[j]%8);
            auto out=ecc_decode(hex(noisy.data(),32),key);require(out.value("valid",false)&&out["delivery_id"]==id&&out["corrected_bits"]==errors&&out["payload_hex"]==code);
        }
        require(!ecc_decode(code,"wrong key").value("valid",false));
        auto noisy=unhex(code);std::vector<float>logits(256,10);for(int i=0;i<20;i++){int pos=(i*11)%255;noisy[pos/8]^=1<<(7-pos%8);if(i<3)logits[pos]=.001f*(i+1);}
        require(!ecc_decode(hex(noisy.data(),32),key).value("valid",false));
        auto soft=ecc_decode(hex(noisy.data(),32),key,logits);require(soft.value("valid",false)&&soft["delivery_id"]==id&&soft["corrected_bits"]==20);
    }
    require(!ecc_decode(std::string(64,'0'),key).value("valid",false));
    for(int j=0;j<32;j++){std::vector<unsigned char>b(32);for(auto&v:b)v=(unsigned char)rng();require(!ecc_decode(hex(b.data(),32),key,std::vector<float>(256,1)).value("valid",false));}
    std::cout<<json({{"passed",tests},{"format","BCH(255,131,t=18)+64-bit copy ID+64-bit HMAC"}}).dump(2)<<"\n";
}
