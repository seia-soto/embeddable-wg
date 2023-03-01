#include "stdlib.h"
#include "node_api.h"
#include "./constants.h"

extern napi_status napi_utils_get_value_string(napi_env env, napi_value value, char **str)
{
  size_t length;
  ASSERT_NAPI_CALL(env, napi_get_value_string_utf8(env, value, NULL, NAPI_AUTO_LENGTH, &length), napi_string_expected);
  char *alt_str = (char *)calloc(length + 1, sizeof(char));
  ASSERT_NAPI_CALL(env, napi_get_value_string_utf8(env, value, alt_str, length + 1, NULL), napi_string_expected);

  *str = alt_str;

  return napi_ok;
}

extern napi_status napi_utils_define_uint32_value(napi_env env, napi_value exports, char *utf8name, uint32_t source)
{
  napi_value value;
  ASSERT_NAPI_CALL(env, napi_create_uint32(env, source, &value), napi_number_expected);

  napi_property_descriptor a = {utf8name, 0, 0, 0, 0, value, napi_default, 0};
  ASSERT_NAPI_CALL(env, napi_define_properties(env, exports, 1, &a), napi_generic_failure);

  return napi_ok;
}
