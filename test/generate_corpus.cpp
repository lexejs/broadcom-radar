#include "Fixtures.h"
#include <fstream>
#include <string>
int main(int argc,char** argv) {
    if(argc!=2) return 1;
    auto broadcom=fixtures::beacon();fixtures::proprietary(broadcom);
    auto truncated=fixtures::beacon();truncated.insert(truncated.end(),{221,255,0});
    auto bad=fixtures::beacon();fixtures::wps(bad,{0x10,0x21,0xff,0xff,0});
    auto probe=fixtures::fixedUuid();probe[0]=0x50;
    unsigned index=0;
    for(const auto& data:{broadcom,fixtures::ordinaryWps(),fixtures::fixedUuid(),fixtures::defaults(),fixtures::beacon(),fixtures::beacon({},2),truncated,bad,probe}) {
        std::ofstream file(std::string(argv[1])+"/seed-"+std::to_string(index++),std::ios::binary);
        file.write(reinterpret_cast<const char*>(data.data()),data.size());
    }
}
