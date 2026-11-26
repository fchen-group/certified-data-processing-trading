#include <stdint.h>
extern "C" uint64_t work2_diag_now();
static uint64_t diag_stamps[6];
extern "C" int work2_svm_diag_read(uint64_t* out) {
    if(!out || !diag_stamps[0]) return 0;
    for(int i=0;i<6;++i) {
        if(!diag_stamps[i] || (i && diag_stamps[i]<diag_stamps[i-1])) return 0;
        out[i]=diag_stamps[i];
    }
    return 1;
}
struct DiagnosticLifetime {
    DiagnosticLifetime(){for(int i=0;i<6;++i)diag_stamps[i]=0;diag_stamps[0]=work2_diag_now();}
    ~DiagnosticLifetime(){diag_stamps[5]=work2_diag_now();}
};
#include "svm_task.h"
#include "svm.h"
#include "transform.hpp"
#include <cmath>
#include <cstdio>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <memory>
#include <string>
#include <vector>

namespace {
std::string trim(const std::string& s) {
    size_t a=0,b=s.size();
    while(a<b && (s[a]==' '||s[a]=='\t')) ++a;
    while(b>a && (s[b-1]==' '||s[b-1]=='\t')) --b;
    return s.substr(a,b-a);
}
bool uint53(const std::string& s, double& value) {
    if(s.empty()) return false;
    uint64_t v=0;
    for(unsigned char c:s) {
        if(c<'0'||c>'9'||v>((UINT64_C(1)<<53)-1-(c-'0'))/10) return false;
        v=v*10+(c-'0');
    }
    value=double(v); return true;
}
struct ModelDelete { void operator()(svm_model* m)const {svm_free_and_destroy_model(&m);} };
}

extern "C" int work2_svm_summary(const unsigned char* raw, size_t size, char* output, size_t capacity) {
    DiagnosticLifetime diagnostic;
    if(!raw||!size||size>(32U<<20)||!output||capacity<512) return -1;
    output[0]=0;
    try {
        std::vector<double> labels;
        std::vector<std::vector<svm_node>> rows;
        size_t pos=0;
        while(pos<size) {
            size_t end=pos;
            while(end<size && raw[end]!='\n') ++end;
            if(end-pos>=(1U<<20)) return -2;
            std::string row(reinterpret_cast<const char*>(raw+pos),end-pos);
            pos=end<size?end+1:end;
            if(row.empty()) return -3;
            for(unsigned char c:row) if(c>127||c=='\r'||c=='\n') return -4;
            std::vector<std::string> fields;
            size_t start=0;
            for(size_t j=0;j<=row.size();++j) if(j==row.size()||row[j]==',') {
                fields.push_back(trim(row.substr(start,j-start))); start=j+1;
                if(fields.back().empty()||fields.size()>15) return -5;
            }
            if(fields.size()!=15||rows.size()>=32561) return -6;
            std::string label=fields[14];
            if(!label.empty()&&label.back()=='.') label.pop_back();
            if(label!="<=50K"&&label!=">50K") return -7;
            labels.push_back(label==">50K"?1:-1);
            std::vector<svm_node> x;
            for(int j=0;j<6;++j) {
                double v=medians[j]; int col=numeric_columns[j];
                if(fields[col]!="?"&&!uint53(fields[col],v)) return -8;
                if((col==0&&(v<17||v>90))||(col==12&&(v<1||v>99))) return -9;
                double z=(v-means[j])/scales[j];
                if(!std::isfinite(z)) return -10;
                if(z!=0) x.push_back({j+1,z});
            }
            int offset=6;
            for(int j=0;j<8;++j) {
                for(int k=0;k<category_lengths[j];++k)
                    if(fields[categorical_columns[j]]==categories[j][k]) {x.push_back({offset+k+1,1});break;}
                offset+=category_lengths[j];
            }
            x.push_back({-1,0}); rows.push_back(std::move(x));
        }
        if(rows.size()<2) return -11;
        bool positive=false,negative=false;
        std::vector<svm_node*> pointers;
        for(size_t i=0;i<rows.size();++i) {
            pointers.push_back(rows[i].data()); positive|=labels[i]==1; negative|=labels[i]==-1;
        }
        if(!positive||!negative) return -12;
        svm_problem prob{}; prob.l=int(rows.size());prob.y=labels.data();prob.x=pointers.data();
        svm_parameter p{};
        p.svm_type=C_SVC;p.kernel_type=RBF;p.degree=3;p.gamma=1.0/dimension;p.coef0=0;
        p.cache_size=100;p.eps=1e-3;p.C=1;p.nu=0.5;p.p=0.1;p.shrinking=1;p.probability=0;
        if(svm_check_parameter(&prob,&p)) return -13;
        diag_stamps[1]=work2_diag_now();
        std::unique_ptr<svm_model,ModelDelete> model(svm_train(&prob,&p));
        diag_stamps[2]=work2_diag_now();
        if(!model||model->nr_class!=2||!std::isfinite(model->rho[0])) return -14;
        unsigned correct=0;
        for(size_t i=0;i<rows.size();++i) correct+=svm_predict(model.get(),rows[i].data())==labels[i];
        diag_stamps[3]=work2_diag_now();
        int length=snprintf(output,capacity,"{\"count\":%u,\"support_vectors\":%d,\"training_correct\":%u,\"rho\":%.17g}",
            unsigned(rows.size()),model->l,correct,model->rho[0]);
        if(length<=0||size_t(length)>=capacity) return -15;
        diag_stamps[4]=work2_diag_now();
        return length;
    } catch(...) {output[0]=0;return -16;}
}
