#include "Parsers.h"
#include "AccessPointStore.h"
#include <cstdlib>
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    radar::Observation observation;
    if (radar::parseAdvertisement(data,size,-70,6,0,observation)) {
        if(observation.ssid.length>32 || observation.vendorCount>8 || (observation.malformed && observation.evidence)) std::abort();
        radar::AccessPointStore store; store.observe(observation);
        const auto first = radar::classify(store.at(0)); store.observe(observation);
        if(first != radar::classify(store.at(0))) std::abort();
    }
    radar::WpsIdentity identity; radar::parseWpsAttributes(data,size,identity);
    return 0;
}
