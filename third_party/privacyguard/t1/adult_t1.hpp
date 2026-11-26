// T1 workload adaptation: same complete Adult rows and Welford computation as
// work2/pkg/analyzer/adult.go. Included in the author's trusted CEE task path.
#pragma once
#include <cmath>
#include <cstdio>
#include <cstdint>
#include <string>
#include <vector>

static const uint32_t PG_MAX_INPUT = 32U * 1024U * 1024U;
static const uint32_t PG_MAX_RECORDS = 100000;
static const uint32_t PG_RESULT_CAP = 512;
static bool pg_space(unsigned char c) { return c==' ' || (c>='\t' && c<='\r'); }
static std::string pg_trim(const std::string& s) {
    size_t a=0,b=s.size();
    while(a<b && pg_space(s[a])) ++a;
    while(b>a && pg_space(s[b-1])) --b;
    return s.substr(a,b-a);
}
static bool pg_uint53(const std::string& s, uint64_t& v) {
    if(s.empty()) return false;
    v=0;
    for(unsigned char c:s) {
        if(c<'0'||c>'9'||v>((UINT64_C(1)<<53)-1-(c-'0'))/10) return false;
        v=v*10+(c-'0');
    }
    return true;
}
static bool pg_adult_statistics(const uint8_t* raw,size_t size,std::string& result) {
    double mean[2]={0,0},m2[2]={0,0};
    uint64_t count=0;
    size_t pos=0;
    while(pos<size) {
        size_t end=pos;
        while(end<size && raw[end]!='\n') ++end;
        size_t row_end=end;
        if(row_end>pos && raw[row_end-1]=='\r') --row_end;
        if(end-pos>=(1U<<20)) return false;
        std::string row(reinterpret_cast<const char*>(raw+pos),row_end-pos);
        pos=end<size?end+1:end;
        std::string trimmed=pg_trim(row);
        if(trimmed.empty()||trimmed[0]=='|') continue;
        if(++count>PG_MAX_RECORDS) return false;
        for(unsigned char c:row) if(c>127||c=='\r'||c=='\n') return false;
        std::vector<std::string> fields;
        size_t a=0;
        for(size_t b=0;b<=row.size();++b) if(b==row.size()||row[b]==',') {
            if(fields.size()==15) return false;
            fields.push_back(pg_trim(row.substr(a,b-a))); a=b+1;
            if(fields.back().empty()) return false;
        }
        if(fields.size()!=15) return false;
        std::string label=fields[14];
        if(!label.empty()&&label.back()=='.') label.pop_back();
        if(label!="<=50K"&&label!=">50K") return false;
        uint64_t age=0,hours=0;
        for(int i: {0,2,4,10,11,12}) {
            if(fields[i]=="?") { if(i==0||i==12) return false; continue; }
            uint64_t v;
            if(!pg_uint53(fields[i],v)||(i==0&&(v<17||v>90))||(i==12&&(v<1||v>99))) return false;
            if(i==0) age=v;
            if(i==12) hours=v;
        }
        double values[2]={double(age),double(hours)};
        for(int j=0;j<2;++j) {
            double delta=values[j]-mean[j]; mean[j]+=delta/double(count);
            m2[j]+=delta*(values[j]-mean[j]);
        }
    }
    if(count==0) return false;
    for(int j=0;j<2;++j) if(!std::isfinite(mean[j])||!std::isfinite(m2[j])) return false;
    char out[PG_RESULT_CAP];
    // Seventeen significant digits preserve double values. No fixed padding.
    int n=snprintf(out,sizeof(out),"{\"count\":%llu,\"age\":{\"mean\":%.17g,\"population_variance\":%.17g},\"hours_per_week\":{\"mean\":%.17g,\"population_variance\":%.17g}}",
        static_cast<unsigned long long>(count),mean[0],m2[0]/double(count),mean[1],m2[1]/double(count));
    if(n<0||size_t(n)>=sizeof(out)) return false;
    result.assign(out,size_t(n));
    return true;
}
