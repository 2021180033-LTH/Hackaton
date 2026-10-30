#pragma once
#include "common.h"
#include "bch.h"
#include <numeric>
#include <map>
namespace fg {
inline const BCH255& bch(){static BCH255 codec;return codec;}
inline std::string ecc_payload(const std::string&id,const std::string&key){
    auto bytes=unhex(id);if(bytes.size()!=8)throw std::runtime_error("Expected 64-bit copy ID");
    auto mac=unhex(sha(std::string("Forensic_G/ecc-v3/")+std::string((char*)bytes.data(),bytes.size()),key).substr(0,16));bytes.insert(bytes.end(),mac.begin(),mac.end());
    std::vector<int>bits{1,0,1};for(auto byte:bytes)for(int j=7;j>=0;j--)bits.push_back((byte>>j)&1);
    auto code=bch().encode(bits);return hex(code.data(),code.size());
}
inline json ecc_decode(const std::string&raw,const std::string&key,const std::vector<float>&logits={}){
    auto input=unhex(raw);if(input.size()!=32)return {{"valid",false}};
    std::map<std::string,json>valid;int trials=0;
    auto attempt=[&](const std::vector<unsigned char>&candidate){
        trials++;std::vector<int>bits;int fixed=0;if(!bch().decode(candidate,bits,fixed))return;
        if(bits[0]!=1||bits[1]!=0||bits[2]!=1)return;
        std::vector<unsigned char>bytes(16);for(int i=0;i<128;i++)if(bits[i+3])bytes[i/8]|=1<<(7-i%8);
        auto id=hex(bytes.data(),8),expected=ecc_payload(id,key);auto enc=bch().encode(bits);auto decoded=hex(enc.data(),enc.size());
        unsigned char diff=0;for(size_t i=0;i<decoded.size();i++)diff|=decoded[i]^expected[i];if(diff)return;
        int errors=0;for(int i=0;i<255;i++)errors+=((input[i/8]^enc[i/8])>>(7-i%8))&1;
        valid[id]={{"valid",true},{"format","bch255_131_hmac64_v3"},{"delivery_id",id},{"payload_hex",expected},{"corrected_bits",errors},{"bch_capacity_bits",18}};
    };
    attempt(input);
    if(valid.empty()&&logits.size()==256){
        std::vector<int>order(255);std::iota(order.begin(),order.end(),0);std::partial_sort(order.begin(),order.begin()+8,order.end(),[&](int a,int b){return std::abs(logits[a])<std::abs(logits[b]);});
        for(int mask=1;mask<256;mask++){int count=0;for(int v=mask;v;v>>=1)count+=v&1;if(count>3)continue;auto candidate=input;for(int j=0;j<8;j++)if(mask&(1<<j))candidate[order[j]/8]^=1<<(7-order[j]%8);attempt(candidate);}
    }
    if(valid.size()==1){auto out=valid.begin()->second;out["decode_trials"]=trials;return out;}
    return {{"valid",false},{"ambiguous",valid.size()>1},{"decode_trials",trials}};
}
}
