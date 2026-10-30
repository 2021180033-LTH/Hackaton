#pragma once
#include <torch/optim/adam.h>
#include <torch/nn/functional/vision.h>
#include <torch/nn/functional/upsampling.h>

// Original pixels are used ONLY to estimate geometry, never to fill evidence.
// Axis-aligned scale/translation + flips. No camera homography or time alignment.
struct GeometryFit {int orientation=0;std::vector<float>params;double loss=1;};
static torch::Tensor oriented(torch::Tensor x,int k){if(k==1)return x.flip({3});if(k==2)return x.flip({2});if(k==3)return x.flip({2,3});return x;}
static GeometryFit fit_geometry(torch::Tensor reference,torch::Tensor evidence){
    torch::InferenceMode inference(false);torch::AutoGradMode enable(true);
    namespace F=torch::nn::functional;
    int count=(int)std::min<int64_t>(8,std::min(reference.size(0),evidence.size(0)));
    auto opts=F::InterpolateFuncOptions().size(std::vector<int64_t>{64,64}).mode(torch::kBilinear).align_corners(false);
    auto a=F::interpolate(reference.slice(0,0,count).clone(),opts),b=F::interpolate(evidence.slice(0,0,count).clone(),opts);
    std::vector<float>seeds;std::vector<int>directions;std::vector<torch::Tensor>targets;
    for(int k=0;k<4;k++)for(float s:{0.5f,2.f/3,0.8f,1.f,1.25f,1.5f})for(auto xy:std::vector<std::pair<float,float>>{{0,0},{-.25f,-.25f},{.25f,.25f},{-.25f,.25f},{.25f,-.25f}}){seeds.insert(seeds.end(),{s,s,xy.first,xy.second});directions.push_back(k);targets.push_back(oriented(b,k));}
    int n=(int)directions.size();auto p=torch::from_blob(seeds.data(),{n,4},torch::kFloat32).to(a.device()).clone().set_requires_grad(true);
    auto source=a.unsqueeze(0).expand({n,count,3,64,64}).reshape({n*count,3,64,64}),target=torch::cat(targets);
    torch::optim::Adam optimizer({p},torch::optim::AdamOptions(.025));torch::Tensor loss;
    for(int step=0;step<100;step++){
        optimizer.zero_grad();auto z=p.select(1,0)*0;
        auto theta=torch::stack({p.select(1,0),z,p.select(1,2),z,p.select(1,1),p.select(1,3)},1).reshape({n,2,3});
        auto grid=F::affine_grid(theta.repeat_interleave(count,0),source.sizes(),false);
        auto predicted=F::grid_sample(source,grid,F::GridSampleFuncOptions().align_corners(false));
        loss=(predicted-target).abs().mean({1,2,3}).reshape({n,count}).mean(1);loss.sum().backward();optimizer.step();
        torch::NoGradGuard guard;p.slice(1,0,2).clamp_(.3,2.);p.slice(1,2,4).clamp_(-1.,1.);
    }
    int idx=loss.argmin().item<int>();auto row=p.index({idx}).detach().cpu().contiguous();return {directions[idx],std::vector<float>(row.data_ptr<float>(),row.data_ptr<float>()+4),loss.index({idx}).item<double>()};
}
static torch::Tensor undo_geometry(torch::Tensor evidence,const GeometryFit&fit){
    namespace F=torch::nn::functional;auto x=oriented(evidence,fit.orientation);auto p=fit.params;
    std::vector<float> values{1/p[0],0,-p[2]/p[0],0,1/p[1],-p[3]/p[1]};
    auto matrix=torch::from_blob(values.data(),{1,2,3},torch::kFloat32).to(x.device()).repeat({x.size(0),1,1});
    return F::grid_sample(x,F::affine_grid(matrix,x.sizes(),false),F::GridSampleFuncOptions().align_corners(false).padding_mode(torch::kZeros));
}
