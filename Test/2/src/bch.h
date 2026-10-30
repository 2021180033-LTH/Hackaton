#pragma once
#include <array>
#include <vector>
#include <stdexcept>
#include <algorithm>

// Binary primitive narrow-sense BCH(255,131), designed distance 37.
// Field GF(2^8), primitive polynomial x^8+x^4+x^3+x^2+1 (0x11d).
// Systematic, MSB-first: 131 data bits, 124 parity bits, one unused pad bit.
// A decoded codeword is NOT authentication. The caller MUST verify its MAC.
namespace fg {
class BCH255 {
    std::array<int,510> exp{};
    std::array<int,256> log{};
    std::vector<int> generator;
    int mul(int a,int b)const{return a&&b?exp[log[a]+log[b]]:0;}
    int div(int a,int b)const{if(!b)throw std::runtime_error("GF division by zero");return a?exp[(log[a]-log[b]+255)%255]:0;}
    std::array<int,37> syndromes(const std::array<int,255>&c)const{
        std::array<int,37>s{};for(int j=1;j<=36;j++)for(int i=0;i<255;i++)if(c[i])s[j]^=exp[(i*j)%255];return s;
    }
public:
    BCH255(){
        int x=1;for(int i=0;i<255;i++){exp[i]=x;log[x]=i;x<<=1;if(x&256)x^=0x11d;}for(int i=255;i<510;i++)exp[i]=exp[i-255];
        std::array<bool,255>root{};for(int i=1;i<=36;i++){int k=i;do{root[k]=true;k=(k*2)%255;}while(k!=i);}
        generator={1};for(int r=0;r<255;r++)if(root[r]){std::vector<int>p(generator.size()+1);for(size_t j=0;j<generator.size();j++){p[j]^=mul(generator[j],exp[r]);p[j+1]^=generator[j];}generator=std::move(p);}
        if(generator.size()!=125)throw std::runtime_error("Unexpected BCH polynomial degree");for(int a:generator)if(a!=0&&a!=1)throw std::runtime_error("Nonbinary BCH polynomial");
    }
    std::vector<unsigned char> encode(const std::vector<int>&data)const{
        if(data.size()!=131)throw std::runtime_error("BCH expects 131 data bits");
        std::array<int,255>c{};for(int j=0;j<131;j++)c[254-j]=data[j]&1;auto rem=c;
        for(int i=254;i>=124;i--)if(rem[i])for(int j=0;j<=124;j++)rem[i-124+j]^=generator[j];
        for(int i=0;i<124;i++)c[i]=rem[i];std::vector<unsigned char>out(32);for(int i=0;i<255;i++)if(c[254-i])out[i/8]|=1<<(7-i%8);return out;
    }
    bool decode(const std::vector<unsigned char>&input,std::vector<int>&data,int&errors)const{
        if(input.size()!=32)return false;std::array<int,255>c{};for(int i=0;i<255;i++)c[254-i]=(input[i/8]>>(7-i%8))&1;
        auto s=syndromes(c);errors=0;bool nonzero=false;for(int j=1;j<=36;j++)nonzero|=s[j]!=0;
        if(nonzero){
            std::array<int,37>C{},B{};C[0]=B[0]=1;int L=0,m=1,b=1;
            for(int n=0;n<36;n++){
                int d=s[n+1];for(int i=1;i<=L;i++)d^=mul(C[i],s[n+1-i]);
                if(!d){m++;continue;}auto old=C;int q=div(d,b);
                for(int i=0;i+m<=36;i++)C[i+m]^=mul(q,B[i]);
                if(2*L<=n){L=n+1-L;B=old;b=d;m=1;}else m++;
            }
            if(L<1||L>18)return false;
            for(int i=0;i<255;i++){int z=exp[(255-i)%255],p=1,v=C[0];for(int j=1;j<=L;j++){p=mul(p,z);v^=mul(C[j],p);}if(v==0){c[i]^=1;errors++;}}
            if(errors!=L)return false;auto check=syndromes(c);for(int j=1;j<=36;j++)if(check[j])return false;
        }
        data.resize(131);for(int j=0;j<131;j++)data[j]=c[254-j];return true;
    }
};
}
