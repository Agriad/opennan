#include "cluster.h"
#include "frame.h"
#include "log.h"
#include "utils.h"
#include "timer.h"
#include "math.h"

struct ether_addr nan_cluster_id_new()
{
    struct ether_addr cluster_id = NAN_CLUSTER_ID_BASE;

    cluster_id.ether_addr_octet[4] = get_rand_num(0, 255);
    cluster_id.ether_addr_octet[5] = get_rand_num(0, 255);
    return cluster_id;
}

void nan_cluster_state_init(struct nan_cluster_state *state)
{
    state->cluster_id = nan_cluster_id_new();
}

// int nan_cluster_compare_grade(uint8_t master_preferenceA, uint64_t timestampA,
//                               uint8_t master_preferenceB, uint64_t timestampB)
// {
//     log_debug("nan cluster compare grade: master preference A - %lld", master_preferenceA);
//     log_debug("nan cluster compare grade: master preference B - %lld", master_preferenceB);
//     log_debug("nan cluster compare grade: timestamp A - %lld", timestampA & 0x7ffff);
//     log_debug("nan cluster compare grade: timestamp B - %lld", timestampB & 0x7ffff);
//     log_debug("nan cluster compare grade: timestamp A full - %lld", timestampA);
//     log_debug("nan cluster compare grade: timestamp B full - %lld", timestampB);


//     if (master_preferenceA == master_preferenceB)
//         return (timestampA & 0x7ffff) < (timestampB & 0x7ffff);
        
//     return master_preferenceA < master_preferenceB;
// }

int nan_cluster_compare_grade(uint8_t master_preferenceA, uint64_t timestampA,
                              uint8_t master_preferenceB, uint64_t timestampB)
{
    uint64_t first_value = timestampA & 0xfffffffffff80000;
    double master_preferenceA_float = master_preferenceA;
    double product_master_preferenceA = pow(2, 64) * master_preferenceA_float;
    double total_master_preferenceA = product_master_preferenceA + first_value;

    uint64_t second_value = timestampB & 0xfffffffffff80000;
    double master_preferenceB_float = master_preferenceB;
    double product_master_preferenceB = pow(2, 64) * master_preferenceB_float;
    double total_master_preferenceB = product_master_preferenceB + second_value;

    log_debug("nan cluster compare grade: total master preference A - %f", total_master_preferenceA);
    log_debug("nan cluster compare grade: total master preference B - %f", total_master_preferenceB);
        
    return total_master_preferenceA < total_master_preferenceB;
}

double U64ToDoubleConverter(uint64_t val)
{
    double convertedValue = 0.0;
    memcpy(&convertedValue, &val, sizeof(convertedValue));
    return convertedValue;
}

uint64_t nan_calculate_cluster_grade(uint8_t master_preference, uint64_t timestamp)
{
    uint64_t cluster_grade = master_preference << 6;
    cluster_grade += timestamp & 0x7ffff;
    return cluster_grade;
}
