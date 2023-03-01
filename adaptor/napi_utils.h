#include "stdlib.h"
#include "node_api.h"
#include "./constants.h"

napi_status napi_utils_get_value_string(napi_env env, napi_value value, char **str);
napi_status napi_utils_define_uint32_value(napi_env env, napi_value exports, char *utf8name, uint32_t source);
