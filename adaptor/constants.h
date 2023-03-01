#define EWB_AF_UNSPEC "EWB_AF_UNSPEC"       // If the ip address format is not valid ipv4 or ipv6.
#define EWB_AI_UNFORMAT "EWB_AI_UNFORMAT"   // If the value is not in valid format: for example, peer->endpoint takes `ip:port` schema.
#define EWB_OBJ_UNSPEC "EWB_OBJ_UNSPEC"     // If we failed to unwrap napi_value object into wireguard structs.
#define EWB_ARG_UNSPEC "EWB_ARG_UNSPEC"     // If the argument given is not valid.
#define EWB_LIB_CALLFAIL "EWB_LIB_CALLFAIL" // If we failed to call wireguard library functions.
#define EWB_NNA_CALLFAIL "EWB_NNA_CALLFAIL" // If we failed to call napi library functions.
#define EWB_SOC_CALLFAIL "EWB_SOC_CALLFAIL" // If we failed to call socket to kernel or related system calls.

#define NAPI_CALL(env, call)                                                                                                      \
  if (call != napi_ok)                                                                                                            \
  {                                                                                                                               \
    const napi_extended_error_info *extended_error_info = NULL;                                                                   \
    napi_get_last_error_info((env), &extended_error_info);                                                                        \
    const char *error_message_str = extended_error_info->error_message ? extended_error_info->error_message : "No error message"; \
    if (extended_error_info->engine_reserved != 0)                                                                                \
    {                                                                                                                             \
      fprintf(stderr, "Error %s:%d: Call to %s failed with an error %s\n", __FILE__, __LINE__, #call, error_message_str);         \
    }                                                                                                                             \
    else if (strlen(error_message_str) > 0)                                                                                       \
    {                                                                                                                             \
      napi_throw_error((env), EWB_NNA_CALLFAIL, error_message_str);                                                               \
    }                                                                                                                             \
    else                                                                                                                          \
    {                                                                                                                             \
      napi_throw_error((env), EWB_NNA_CALLFAIL, "NAPI call failed");                                                              \
    }                                                                                                                             \
    return NULL;                                                                                                                  \
  }

#define ASSERT_NAPI_CALL(env, call, status)                      \
  if ((call) != napi_ok)                                         \
  {                                                              \
    napi_throw_error(env, EWB_NNA_CALLFAIL, "NAPI call failed"); \
    return status;                                               \
  }
