#include <stdint.h>
#include "wire.h"

struct nan_rx_return
{
    uint64_t timestamp;
    int return_state;
    int rx_result;
    struct buf *frame;
};

struct buf get_buf(struct nan_rx_return *nan_rx);