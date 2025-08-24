#include "sephix/sandbox.h"
#include "sephix/util.h"

int
sandbox__init()
{
	if (fs__init()) {
		LOG_ERROR("fs__init failed");
		return -1;
	}
	return 0;
}
