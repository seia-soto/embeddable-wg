#include "assert.h"
#include "arpa/inet.h"
#include "ifaddrs.h"
#include "stdio.h"
#include "stdlib.h"
#include "string.h"
#include "sys/ioctl.h"
#include "netdb.h"
#include "node_api.h"
#include "unistd.h"
#include "../externs/wireguard-tools/contrib/embeddable-wg-library/wireguard.h"
#include "./constants.h"
#include "./napi_utils.h"

static napi_value create_allowedip_object_from_wg_allowedip(napi_env env, const struct wg_allowedip *allowedip)
{
  napi_value allowedip_obj;
  NAPI_CALL(env, napi_create_object(env, &allowedip_obj));

  char ip_str[INET6_ADDRSTRLEN];
  if (allowedip->family == AF_INET)
  {
    struct sockaddr_in *addr_in = (struct sockaddr_in *) &allowedip->ip4;
    inet_ntop(AF_INET, &(addr_in->sin_addr), ip_str, INET_ADDRSTRLEN);
  }
  else if (allowedip->family == AF_INET6)
  {
    struct sockaddr_in6 *addr_in6 = (struct sockaddr_in6 *) &allowedip->ip6;
    inet_ntop(AF_INET6, &(addr_in6->sin6_addr), ip_str, INET6_ADDRSTRLEN);
  }
  else
  {
    napi_throw_error(env, EWB_AF_UNSPEC, "Failed to validate the address family! Please, give a valid ip address.");
    return NULL;
  }

  napi_value family, addr, cidr;
  NAPI_CALL(env, napi_create_uint32(env, allowedip->family, &family));
  NAPI_CALL(env, napi_create_string_utf8(env, ip_str, NAPI_AUTO_LENGTH, &addr));
  NAPI_CALL(env, napi_create_uint32(env, allowedip->cidr, &cidr));
  NAPI_CALL(env, napi_set_named_property(env, allowedip_obj, "family", family));
  NAPI_CALL(env, napi_set_named_property(env, allowedip_obj, "ip", addr));
  NAPI_CALL(env, napi_set_named_property(env, allowedip_obj, "cidr", cidr));

  return allowedip_obj;
}

static napi_value create_peer_object_from_wg_peer(napi_env env, const struct wg_peer *peer)
{
  napi_value peer_obj;
  NAPI_CALL(env, napi_create_object(env, &peer_obj));

  napi_value public_key, preshared_key, endpoint, last_handshake_time, rx_bytes, tx_bytes, persistent_keepalive_interval, allowedips_array;
  wg_key_b64_string b64_public_key, b64_preshared_key;
  wg_key_to_base64(b64_public_key, peer->public_key);
  wg_key_to_base64(b64_preshared_key, peer->preshared_key);

  NAPI_CALL(env, napi_create_string_utf8(env, b64_public_key, NAPI_AUTO_LENGTH, &public_key));
  NAPI_CALL(env, napi_create_string_utf8(env, b64_preshared_key, NAPI_AUTO_LENGTH, &preshared_key));

  char endpoint_str[INET6_ADDRSTRLEN + 6];
  if (peer->endpoint.addr.sa_family == AF_INET)
  {
    char ip[INET_ADDRSTRLEN];
    uint16_t port = htons(peer->endpoint.addr4.sin_port);
    inet_ntop(AF_INET, &peer->endpoint.addr4.sin_addr, ip, sizeof(ip));

    sprintf(endpoint_str, "%s:%d", ip, port);
    NAPI_CALL(env, napi_create_string_utf8(env, endpoint_str, NAPI_AUTO_LENGTH, &endpoint));
  }
  else if (peer->endpoint.addr.sa_family == AF_INET6)
  {
    char ip[INET6_ADDRSTRLEN];
    uint16_t port = htons(peer->endpoint.addr6.sin6_port);
    inet_ntop(AF_INET6, &peer->endpoint.addr6.sin6_addr, ip, sizeof(ip));

    sprintf(endpoint_str, "%s:%d", ip, port);
    NAPI_CALL(env, napi_create_string_utf8(env, endpoint_str, NAPI_AUTO_LENGTH, &endpoint));
  }
  else 
  {
    napi_throw_error(env, EWB_AF_UNSPEC, "Failed to validate the address family! Please, give a valid ip address.");
    return NULL;
  }

  NAPI_CALL(env, napi_create_uint32(env, (uint32_t) peer->last_handshake_time.tv_nsec, &last_handshake_time));
  NAPI_CALL(env, napi_create_uint32(env, (uint32_t) peer->rx_bytes, &rx_bytes));
  NAPI_CALL(env, napi_create_uint32(env, (uint32_t) peer->tx_bytes, &tx_bytes));
  NAPI_CALL(env, napi_create_uint32(env, peer->persistent_keepalive_interval, &persistent_keepalive_interval));
  NAPI_CALL(env, napi_create_array(env, &allowedips_array));

  struct wg_allowedip *allowedip;
  uint32_t index = 0;
  wg_for_each_allowedip(peer, allowedip)
  {
    napi_value allowedip_obj = create_allowedip_object_from_wg_allowedip(env, allowedip);
    NAPI_CALL(env, napi_set_element(env, allowedips_array, index++, allowedip_obj));
  }

  NAPI_CALL(env, napi_set_named_property(env, peer_obj, "publicKey", public_key));
  NAPI_CALL(env, napi_set_named_property(env, peer_obj, "presharedKey", preshared_key));
  NAPI_CALL(env, napi_set_named_property(env, peer_obj, "endpoint", endpoint));
  NAPI_CALL(env, napi_set_named_property(env, peer_obj, "lastHandshakeTime", last_handshake_time));
  NAPI_CALL(env, napi_set_named_property(env, peer_obj, "rxBytes", rx_bytes));
  NAPI_CALL(env, napi_set_named_property(env, peer_obj, "txBytes", tx_bytes));
  NAPI_CALL(env, napi_set_named_property(env, peer_obj, "persistentKeepaliveInterval", persistent_keepalive_interval));
  NAPI_CALL(env, napi_set_named_property(env, peer_obj, "allowedips", allowedips_array));

  return peer_obj;
}

static napi_value create_device_object_from_wg_device(napi_env env, const struct wg_device *device)
{
  napi_value device_obj;
  NAPI_CALL(env, napi_create_object(env, &device_obj));

  napi_value name, ifindex, flags, public_key, private_key, fwmark, listen_port, peers_array;
  wg_key_b64_string b64_public_key, b64_private_key;
  wg_key_to_base64(b64_public_key, device->public_key);
  wg_key_to_base64(b64_private_key, device->private_key);

  NAPI_CALL(env, napi_create_string_utf8(env, device->name, NAPI_AUTO_LENGTH, &name));
  NAPI_CALL(env, napi_create_uint32(env, device->ifindex, &ifindex));
  NAPI_CALL(env, napi_create_uint32(env, device->flags, &flags));
  NAPI_CALL(env, napi_create_string_utf8(env, b64_public_key, NAPI_AUTO_LENGTH, &public_key));
  NAPI_CALL(env, napi_create_string_utf8(env, b64_private_key, NAPI_AUTO_LENGTH, &private_key));
  NAPI_CALL(env, napi_create_uint32(env, device->fwmark, &fwmark));
  NAPI_CALL(env, napi_create_uint32(env, device->listen_port, &listen_port));
  NAPI_CALL(env, napi_create_array(env, &peers_array));

  struct wg_peer *peer;
  uint32_t index = 0;
  wg_for_each_peer(device, peer)
  {
    napi_value peer_obj = create_peer_object_from_wg_peer(env, peer);
    NAPI_CALL(env, napi_set_element(env, peers_array, index++, peer_obj));
  }

  NAPI_CALL(env, napi_set_named_property(env, device_obj, "name", name));
  NAPI_CALL(env, napi_set_named_property(env, device_obj, "ifindex", ifindex));
  NAPI_CALL(env, napi_set_named_property(env, device_obj, "flags", flags));
  NAPI_CALL(env, napi_set_named_property(env, device_obj, "publicKey", public_key));
  NAPI_CALL(env, napi_set_named_property(env, device_obj, "privateKey", private_key));
  NAPI_CALL(env, napi_set_named_property(env, device_obj, "fwmark", fwmark));
  NAPI_CALL(env, napi_set_named_property(env, device_obj, "listenPort", listen_port));
  NAPI_CALL(env, napi_set_named_property(env, device_obj, "peers", peers_array));

  return device_obj;
}

static uint32_t get_wg_allowedip_from_napi_object(napi_env env, napi_value object, wg_allowedip *allowedip)
{
  napi_value family_prop, ip_prop, cidr_prop;
  ASSERT_NAPI_CALL(env, napi_get_named_property(env, object, "family", &family_prop), 1);
  ASSERT_NAPI_CALL(env, napi_get_named_property(env, object, "addr", &ip_prop), 1);
  ASSERT_NAPI_CALL(env, napi_get_named_property(env, object, "cidr", &cidr_prop), 1);

  napi_valuetype family_type, ip_type, cidr_type;
  ASSERT_NAPI_CALL(env, napi_typeof(env, family_prop, &family_type), 1);
  ASSERT_NAPI_CALL(env, napi_typeof(env, ip_prop, &ip_type), 1);
  ASSERT_NAPI_CALL(env, napi_typeof(env, cidr_prop, &cidr_type), 1);

  if (family_type != napi_number)
  {
    napi_throw_type_error(env, EWB_ARG_UNSPEC, "The expected type of family property of allowed ip is number!");
    return 1;
  }
  if (ip_type != napi_string)
  {
    napi_throw_type_error(env, EWB_ARG_UNSPEC, "The expected type of addr property of allowed ip is string!");
    return 1;
  }
  if (cidr_type != napi_number)
  {
    napi_throw_type_error(env, EWB_ARG_UNSPEC, "The expected type of cidr property of allowed ip is string!");
    return 1;
  }

  uint32_t family, cidr;
  ASSERT_NAPI_CALL(env, napi_get_value_uint32(env, family_prop, &family), 1);
  allowedip->family = family;

  char *ip_str;
  ASSERT_NAPI_CALL(env, napi_utils_get_value_string(env, ip_prop, &ip_str), 1);

  if (allowedip->family == AF_INET)
  {
    inet_pton(AF_INET, ip_str, &allowedip->ip4);
  }
  else if (allowedip->family == AF_INET6)
  {
    inet_pton(AF_INET6, ip_str, &allowedip->ip6);
  }
  else
  {
    free(ip_str);

    napi_throw_error(env, EWB_AF_UNSPEC, "The expected format of addr property is ipv4 or ipv6!");
    return 1;
  }
  free(ip_str);

  ASSERT_NAPI_CALL(env, napi_get_value_uint32(env, cidr_prop, &cidr), 1);
  allowedip->cidr = cidr;

  return 0;
}

static uint32_t get_wg_peer_from_napi_object(napi_env env, napi_value object, wg_peer *peer)
{
  napi_value flags_prop, public_key_prop, preshared_key_prop, endpoint_prop, allowedips_prop, persistent_keepalive_interval_prop;
  ASSERT_NAPI_CALL(env, napi_get_named_property(env, object, "flags", &flags_prop), 1);
  ASSERT_NAPI_CALL(env, napi_get_named_property(env, object, "publicKey", &public_key_prop), 1);
  ASSERT_NAPI_CALL(env, napi_get_named_property(env, object, "presharedKey", &preshared_key_prop), 1);
  ASSERT_NAPI_CALL(env, napi_get_named_property(env, object, "endpoint", &endpoint_prop), 1);
  ASSERT_NAPI_CALL(env, napi_get_named_property(env, object, "allowedIps", &allowedips_prop), 1);
  ASSERT_NAPI_CALL(env, napi_get_named_property(env, object, "persistentKeepaliveInterval", &persistent_keepalive_interval_prop), 1);

  napi_valuetype flags_type, public_key_type, preshared_key_type, endpoint_type, allowedips_type, persistent_keepalive_interval_type;
  ASSERT_NAPI_CALL(env, napi_typeof(env, flags_prop, &flags_type), 1);
  ASSERT_NAPI_CALL(env, napi_typeof(env, public_key_prop, &public_key_type), 1);
  ASSERT_NAPI_CALL(env, napi_typeof(env, preshared_key_prop, &preshared_key_type), 1);
  ASSERT_NAPI_CALL(env, napi_typeof(env, endpoint_prop, &endpoint_type), 1);
  ASSERT_NAPI_CALL(env, napi_typeof(env, allowedips_prop, &allowedips_type), 1);
  ASSERT_NAPI_CALL(env, napi_typeof(env, persistent_keepalive_interval_prop, &persistent_keepalive_interval_type), 1);

  if (flags_type != napi_number)
  {
    napi_throw_type_error(env, EWB_ARG_UNSPEC, "The expected type of flags property of peer is number!");
    return 1;
  }
  if (public_key_type != napi_string)
  {
    napi_throw_type_error(env, EWB_ARG_UNSPEC, "The expected type of publicKey property of peer is string!");
    return 1;
  }
  if (preshared_key_type != napi_string)
  {
    napi_throw_type_error(env, EWB_ARG_UNSPEC, "The expected type of presharedKey property of peer is string!");
    return 1;
  }
  if (endpoint_type != napi_string)
  {
    napi_throw_type_error(env, EWB_ARG_UNSPEC, "The expected type of endpoint property of peer is string!");
    return 1;
  }
  bool is_allowedips_type_array;
  ASSERT_NAPI_CALL(env, napi_is_array(env, allowedips_prop, &is_allowedips_type_array), 1);
  if (allowedips_type != napi_object || !is_allowedips_type_array)
  {
    napi_throw_type_error(env, EWB_ARG_UNSPEC, "The expected type of allowedIps property of peer is array!");
    return 1;
  }
  if (persistent_keepalive_interval_type != napi_number)
  {
    napi_throw_type_error(env, EWB_ARG_UNSPEC, "The expected type of persistentKeepaliveInterval property of peer is number!");
    return 1;
  }

  uint32_t flags;
  ASSERT_NAPI_CALL(env, napi_get_value_uint32(env, flags_prop, &flags), 1);
  peer->flags = flags;

  char *public_key_str;
  ASSERT_NAPI_CALL(env, napi_utils_get_value_string(env, public_key_prop, &public_key_str), 1);
  wg_key_from_base64(peer->public_key, public_key_str);
  free(public_key_str);

  char *preshared_key_str;
  ASSERT_NAPI_CALL(env, napi_utils_get_value_string(env, preshared_key_prop, &preshared_key_str), 1);
  wg_key_from_base64(peer->preshared_key, preshared_key_str);
  free(preshared_key_str);

  char *endpoint_str;
  ASSERT_NAPI_CALL(env, napi_utils_get_value_string(env, endpoint_prop, &endpoint_str), 1);
  char *endpoint_port_str = strrchr(endpoint_str, ':');
  if (endpoint_port_str == NULL)
  {
    free(endpoint_str);

    napi_throw_error(env, EWB_AI_UNFORMAT, "The endpoint property of peer should be in `ip:port` format!");
    return 1;
  }
  *endpoint_port_str++ = '\0';

  if (inet_pton(AF_INET, endpoint_str, &(peer->endpoint.addr4.sin_addr)) == 1)
  {
    peer->endpoint.addr.sa_family = AF_INET;
    peer->endpoint.addr4.sin_port = ntohs(atoi(endpoint_port_str));
  }
  else if (inet_pton(AF_INET6, endpoint_str, &(peer->endpoint.addr6.sin6_addr)) == 1)
  {
    peer->endpoint.addr.sa_family = AF_INET6;
    peer->endpoint.addr6.sin6_port = ntohs(atoi(endpoint_port_str));
  }
  else
  {
    napi_throw_error(env, EWB_AF_UNSPEC, "The endpoint property of peer should be in the valid ipv4 or ipv6 format!");
    return 1;
  }
  free(endpoint_str);

  uint32_t allowedips_length;
  ASSERT_NAPI_CALL(env, napi_get_array_length(env, allowedips_prop, &allowedips_length), 1);

  wg_allowedip *last_allowedip = NULL;
  for (uint32_t i = 0; i < allowedips_length; i++)
  {
    napi_value allowedip_value;
    ASSERT_NAPI_CALL(env, napi_get_element(env, allowedips_prop, i, &allowedip_value), 1);

    napi_valuetype allowedip_type;
    ASSERT_NAPI_CALL(env, napi_typeof(env, allowedip_value, &allowedip_type), 1);
    
    if (allowedip_type != napi_object)
    {
      napi_throw_type_error(env, EWB_ARG_UNSPEC, "The expected type of the element of allowedIps property is object!");
      return 1;
    }

    wg_allowedip *allowedip = calloc(1, sizeof(wg_allowedip));
    uint32_t ret = get_wg_allowedip_from_napi_object(env, allowedip_value, allowedip);

    if (ret)
    {
      napi_throw_error(env, EWB_OBJ_UNSPEC, "Failed to unwrap the object to wg_allowedip!");
      return 1;
    }

    if (peer->first_allowedip == NULL)
    {
      peer->first_allowedip = allowedip;
      last_allowedip = allowedip;
    }
    else
    {
      last_allowedip->next_allowedip = allowedip;
      last_allowedip = allowedip;
    }
  }
  peer->last_allowedip = last_allowedip;

  uint32_t persistent_keepalive_interval;
  ASSERT_NAPI_CALL(env, napi_get_value_uint32(env, persistent_keepalive_interval_prop, &persistent_keepalive_interval), 1);
  peer->persistent_keepalive_interval = persistent_keepalive_interval;

  return 0;
}

static uint32_t get_wg_device_from_napi_object(napi_env env, napi_value object, wg_device *device)
{
  napi_value name_props, ifindex_props, flags_props, public_key_props, private_key_props, fwmark_props, listen_port_props, peers_props;
  ASSERT_NAPI_CALL(env, napi_get_named_property(env, object, "name", &name_props), 1);
  ASSERT_NAPI_CALL(env, napi_get_named_property(env, object, "ifindex", &ifindex_props), 1);
  ASSERT_NAPI_CALL(env, napi_get_named_property(env, object, "flags", &flags_props), 1);
  ASSERT_NAPI_CALL(env, napi_get_named_property(env, object, "publicKey", &public_key_props), 1);
  ASSERT_NAPI_CALL(env, napi_get_named_property(env, object, "privateKey", &private_key_props), 1);
  ASSERT_NAPI_CALL(env, napi_get_named_property(env, object, "fwmark", &fwmark_props), 1);
  ASSERT_NAPI_CALL(env, napi_get_named_property(env, object, "listenPort", &listen_port_props), 1);
  ASSERT_NAPI_CALL(env, napi_get_named_property(env, object, "peers", &peers_props), 1);

  napi_valuetype name_type, ifindex_type, flags_type, public_key_type, private_key_type, fwmark_type, listen_port_type, peers_type;
  ASSERT_NAPI_CALL(env, napi_typeof(env, name_props, &name_type), 1);
  ASSERT_NAPI_CALL(env, napi_typeof(env, ifindex_props, &ifindex_type), 1);
  ASSERT_NAPI_CALL(env, napi_typeof(env, flags_props, &flags_type), 1);
  ASSERT_NAPI_CALL(env, napi_typeof(env, public_key_props, &public_key_type), 1);
  ASSERT_NAPI_CALL(env, napi_typeof(env, private_key_props, &private_key_type), 1);
  ASSERT_NAPI_CALL(env, napi_typeof(env, fwmark_props, &fwmark_type), 1);
  ASSERT_NAPI_CALL(env, napi_typeof(env, listen_port_props, &listen_port_type), 1);
  ASSERT_NAPI_CALL(env, napi_typeof(env, peers_props, &peers_type), 1);

  if (name_type != napi_string)
  {
    napi_throw_type_error(env, EWB_ARG_UNSPEC, "The expected type of name property of device is string!");
    return 1;
  }
  if (ifindex_type != napi_number)
  {
    napi_throw_type_error(env, EWB_ARG_UNSPEC, "The expected type of ifindex property of device is number!");
    return 1;
  }
  if (flags_type != napi_number)
  {
    napi_throw_type_error(env, EWB_ARG_UNSPEC, "The expected type of flags property of device is number!");
    return 1;
  }
  if (public_key_type != napi_string)
  {
    napi_throw_type_error(env, EWB_ARG_UNSPEC, "The expected type of publicKey property of device is string!");
    return 1;
  }
  if (private_key_type != napi_string)
  {
    napi_throw_type_error(env, EWB_ARG_UNSPEC, "The expected type of privateKey property of device is string!");
    return 1;
  }
  if (fwmark_type != napi_number)
  {
    napi_throw_type_error(env, EWB_ARG_UNSPEC, "The expected type of fwmark property of device is number!");
    return 1;
  }
  if (listen_port_type != napi_number)
  {
    napi_throw_type_error(env, EWB_ARG_UNSPEC, "The expected type of listenPort property of device is number!");
    return 1;
  }
  bool is_peers_type_array;
  ASSERT_NAPI_CALL(env, napi_is_array(env, peers_props, &is_peers_type_array), 1);
  if (peers_type != napi_object || !is_peers_type_array)
  {
    napi_throw_type_error(env, EWB_ARG_UNSPEC, "The expected type of peers property of device is array!");
    return 1;
  }

  char *name;
  ASSERT_NAPI_CALL(env, napi_utils_get_value_string(env, name_props, &name), 1);
  strcpy(device->name, name);
  free(name);

  uint32_t ifindex;
  ASSERT_NAPI_CALL(env, napi_get_value_uint32(env, ifindex_props, &ifindex), 1);
  device->ifindex = ifindex;

  uint32_t flags;
  ASSERT_NAPI_CALL(env, napi_get_value_uint32(env, flags_props, &flags), 1);
  device->flags = flags;

  char *public_key_str;
  ASSERT_NAPI_CALL(env, napi_utils_get_value_string(env, public_key_props, &public_key_str), 1);
  wg_key_from_base64(device->public_key, public_key_str);
  free(public_key_str);

  char *private_key_str;
  ASSERT_NAPI_CALL(env, napi_utils_get_value_string(env, private_key_props, &private_key_str), 1);
  wg_key_from_base64(device->private_key, private_key_str);
  free(private_key_str);

  uint32_t fwmark;
  ASSERT_NAPI_CALL(env, napi_get_value_uint32(env, fwmark_props, &fwmark), 1);
  device->fwmark = fwmark;

  uint32_t listen_port;
  ASSERT_NAPI_CALL(env, napi_get_value_uint32(env, listen_port_props, &listen_port), 1);
  device->listen_port = listen_port;

  uint32_t peers_length;
  ASSERT_NAPI_CALL(env, napi_get_array_length(env, peers_props, &peers_length), 1);

  wg_peer *last_peer = NULL;
  for (uint32_t i = 0; i < peers_length; i++)
  {
    napi_value peer_value;
    ASSERT_NAPI_CALL(env, napi_get_element(env, peers_props, i, &peer_value), 1);

    napi_valuetype peer_type;
    ASSERT_NAPI_CALL(env, napi_typeof(env, peers_props, &peer_type), 1);

    if (peer_type != napi_object)
    {
      napi_throw_type_error(env, EWB_ARG_UNSPEC, "The expected type of the element of peer property is object!");
      return 1;
    }

    wg_peer *peer = calloc(1, sizeof(wg_peer));
    uint32_t ret = get_wg_peer_from_napi_object(env, peer_value, peer);

    if (ret)
    {
      napi_throw_error(env, EWB_OBJ_UNSPEC, "Failed to unwrap the object to wg_peer!");
      return 1;
    }

    if (device->first_peer == NULL)
    {
      device->first_peer = peer;
      last_peer = peer;
    }
    else
    {
      last_peer->next_peer = peer;
      last_peer = peer;
    }
  }
  device->last_peer = last_peer;

  return 0;
}

static napi_value set_device(napi_env env, const napi_callback_info info)
{
  size_t argc = 1;
  napi_value args[1];
  NAPI_CALL(env, napi_get_cb_info(env, info, &argc, args, NULL, NULL));
  if (argc != 1)
  {
    napi_throw_type_error(env, EWB_ARG_UNSPEC, "The expected argument size of set_device is 1!");
    return NULL;
  }

  napi_valuetype argt_0;
  NAPI_CALL(env, napi_typeof(env, args[0], &argt_0));
  if (argt_0 != napi_object)
  {
    napi_throw_type_error(env, EWB_ARG_UNSPEC, "The expected type of first argument of set_device is object!");
    return NULL;
  }

  struct wg_device *device = calloc(1, sizeof(struct wg_device));

  if (get_wg_device_from_napi_object(env, args[0], device))
  {
    wg_free_device(device);

    napi_throw_error(env, EWB_OBJ_UNSPEC, "Failed to unwrap the object to wg_device!");
    return NULL;
  }

  if (wg_set_device(device))
  {
    wg_free_device(device);

    napi_throw_error(env, EWB_LIB_CALLFAIL, "Failed to set the device!");
    return NULL;
  }

  wg_free_device(device);

  return NULL;
}

static napi_value get_device(napi_env env, const napi_callback_info info)
{
  size_t argc = 1;
  napi_value args[1];
  NAPI_CALL(env, napi_get_cb_info(env, info, &argc, args, NULL, NULL));
  if (argc != 1)
  {
    napi_throw_type_error(env, EWB_ARG_UNSPEC, "The expected argument size of get_device is 1!");
    return NULL;
  }

  napi_valuetype argt_0;
  NAPI_CALL(env, napi_typeof(env, args[0], &argt_0));
  if (argt_0 != napi_string)
  {
    napi_throw_type_error(env, EWB_ARG_UNSPEC, "The expected type of first argument of get_device is string!");
    return NULL;
  }

  char *device_name;
  NAPI_CALL(env, napi_utils_get_value_string(env, args[0], &device_name));
  struct wg_device *device = {0};

  if (wg_get_device(&device, device_name))
  {
    free(device_name);
    wg_free_device(device);

    napi_throw_error(env, EWB_LIB_CALLFAIL, "Failed to get the device!");
    return NULL;
  }

  free(device_name);

  if (device == NULL)
  {
    napi_throw_error(env, EWB_LIB_CALLFAIL, "Failed to get the device!");
    return NULL;
  }

  napi_value result = create_device_object_from_wg_device(env, device);
  wg_free_device(device);

  return result;
}

static napi_value add_device(napi_env env, const napi_callback_info info)
{
  size_t argc = 1;
  napi_value args[1];
  NAPI_CALL(env, napi_get_cb_info(env, info, &argc, args, NULL, NULL));
  if (argc != 1)
  {
    napi_throw_type_error(env, EWB_ARG_UNSPEC, "The expected argument size of add_device is 1!");
    return NULL;
  }

  napi_valuetype argt_0;
  NAPI_CALL(env, napi_typeof(env, args[0], &argt_0));
  if (argt_0 != napi_string)
  {
    napi_throw_type_error(env, EWB_ARG_UNSPEC, "The expected type of first argument of add_device is string!");
    return NULL;
  }

  char *device_name;
  NAPI_CALL(env, napi_utils_get_value_string(env, args[0], &device_name));
  if (wg_add_device(device_name))
  {
    free(device_name);

    napi_throw_error(env, EWB_LIB_CALLFAIL, "Failed to get the device!");
    return NULL;
  }

  free(device_name);

  return NULL;
}

static napi_value remove_device(napi_env env, const napi_callback_info info)
{
  size_t argc = 1;
  napi_value args[1];
  NAPI_CALL(env, napi_get_cb_info(env, info, &argc, args, NULL, NULL));
  if (argc != 1)
  {
    napi_throw_type_error(env, EWB_ARG_UNSPEC, "The expected argument size of add_device is 1!");
    return NULL;
  }

  napi_valuetype argt_0;
  NAPI_CALL(env, napi_typeof(env, args[0], &argt_0));
  if (argt_0 != napi_string)
  {
    napi_throw_type_error(env, EWB_ARG_UNSPEC, "The expected type of first argument of add_device is string!");
    return NULL;
  }

  char *device_name;
  NAPI_CALL(env, napi_utils_get_value_string(env, args[0], &device_name));
  if (wg_del_device(device_name))
  {
    free(device_name);

    napi_throw_error(env, EWB_LIB_CALLFAIL, "Failed to get the device!");
    return NULL;
  }

  free(device_name);

  return NULL;
}

static napi_value list_device_names(napi_env env, napi_callback_info info)
{
  napi_status status;
  napi_value device_names_value;

  status = napi_create_array(env, &device_names_value);
  assert(status == napi_ok);

  char *device_names = wg_list_device_names();

  uint32_t segment_start_position = 0;
  uint32_t device_names_value_iteration = 0;
  size_t i = 0;

  for (;;)
  {
    if (device_names[i] == '\0')
    {
      size_t segment_size = i - segment_start_position;
      char *segment_value = calloc(segment_size, sizeof(char));
      strncpy(segment_value, device_names + segment_start_position, i - segment_start_position);

      napi_value segment;
      status = napi_create_string_utf8(env, segment_value, NAPI_AUTO_LENGTH, &segment);
      assert(status == napi_ok);

      status = napi_set_element(env, device_names_value, device_names_value_iteration++, segment);
      assert(status == napi_ok);

      segment_start_position = i + 1;

      free(segment_value);

      if (device_names[i + 1] == '\0')
      {
        break;
      }
    }

    i++;
  }
  free(device_names);

  return device_names_value;
}

static napi_value generate_public_key(napi_env env, const napi_callback_info info)
{
  size_t argc = 1;
  napi_value args[1];
  NAPI_CALL(env, napi_get_cb_info(env, info, &argc, args, NULL, NULL));
  if (argc != 1)
  {
    napi_throw_type_error(env, EWB_ARG_UNSPEC, "The expected argument size of generate_public_key is 1!");
    return NULL;
  }

  napi_valuetype argt_0;
  NAPI_CALL(env, napi_typeof(env, args[0], &argt_0));
  if (argt_0 != napi_string)
  {
    napi_throw_type_error(env, EWB_ARG_UNSPEC, "The expected type of first argument of generate_public_key is string!");
    return NULL;
  }

  char *private_key_str;
  wg_key private_key;
  wg_key public_key;

  NAPI_CALL(env, napi_utils_get_value_string(env, args[0], &private_key_str));
  if (wg_key_from_base64(private_key, private_key_str))
  {
    free(private_key_str);

    napi_throw_error(env, EWB_LIB_CALLFAIL, "Failed to parse base64 encoded key!");
    return NULL;
  }

  wg_generate_public_key(public_key, private_key);
  free(private_key_str);

  wg_key_b64_string public_key_str;
  wg_key_to_base64(public_key_str, public_key);

  napi_value result;
  NAPI_CALL(env, napi_create_string_utf8(env, public_key_str, NAPI_AUTO_LENGTH, &result));

  return result;
}

static napi_value generate_private_key(napi_env env, const napi_callback_info info)
{
  wg_key private_key;
  wg_key_b64_string private_key_str;
  wg_generate_private_key(private_key);
  wg_key_to_base64(private_key_str, private_key);

  napi_value result;
  NAPI_CALL(env, napi_create_string_utf8(env, private_key_str, NAPI_AUTO_LENGTH, &result));

  return result;
}

static napi_value generate_preshared_key(napi_env env, const napi_callback_info info)
{
  wg_key preshared_key;
  wg_key_b64_string preshared_key_str;
  wg_generate_preshared_key(preshared_key);
  wg_key_to_base64(preshared_key_str, preshared_key);

  napi_value result;
  NAPI_CALL(env, napi_create_string_utf8(env, preshared_key_str, NAPI_AUTO_LENGTH, &result));

  return result;
}

static napi_value get_interface_address(napi_env env, const napi_callback_info info)
{
  size_t argc = 1;
  napi_value args[1];
  NAPI_CALL(env, napi_get_cb_info(env, info, &argc, args, NULL, NULL));
  if (argc != 1)
  {
    napi_throw_type_error(env, EWB_ARG_UNSPEC, "The expected argument size of get_device is 1!");
    return NULL;
  }

  napi_valuetype argt_0;
  NAPI_CALL(env, napi_typeof(env, args[0], &argt_0));
  if (argt_0 != napi_string)
  {
    napi_throw_type_error(env, EWB_ARG_UNSPEC, "The expected type of first argument of get_interface_address is string!");
    return NULL;
  }

  char *device_name;
  NAPI_CALL(env, napi_utils_get_value_string(env, args[0], &device_name));

  struct ifaddrs *ifaddr, *ifa;
  char host[NI_MAXHOST];

  napi_value ifaddrs_value;
  NAPI_CALL(env, napi_create_array(env, &ifaddrs_value));

  if (getifaddrs(&ifaddr) == -1)
  {
    free(device_name);

    napi_throw_error(env, EWB_SOC_CALLFAIL, "Unable to get socket addresses!");
    return NULL;
  }

  uint32_t index = 0;
  for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next)
  {
    if (ifa->ifa_addr == NULL || strcmp(ifa->ifa_name, device_name) != 0)
    {
      continue;
    }

    if (ifa->ifa_addr->sa_family == AF_INET)
    {
      struct sockaddr_in *sa = (struct sockaddr_in *)ifa->ifa_addr;
      inet_ntop(AF_INET, &sa->sin_addr, host, NI_MAXHOST);
    }
    else if (ifa->ifa_addr->sa_family == AF_INET6)
    {
      struct sockaddr_in6 *sa = (struct sockaddr_in6 *)ifa->ifa_addr;
      inet_ntop(AF_INET6, &sa->sin6_addr, host, NI_MAXHOST);
    }
    else
    {
      continue;
    }

    napi_value entry_value, family_value, ip_value;
    NAPI_CALL(env, napi_create_object(env, &entry_value));
    NAPI_CALL(env, napi_create_string_utf8(env, host, NAPI_AUTO_LENGTH, &ip_value));
    NAPI_CALL(env, napi_create_uint32(env, ifa->ifa_addr->sa_family, &family_value));
    NAPI_CALL(env, napi_set_named_property(env, entry_value, "family", family_value));
    NAPI_CALL(env, napi_set_named_property(env, entry_value, "ip", ip_value));
    NAPI_CALL(env, napi_set_element(env, ifaddrs_value, index++, entry_value));
  }

  free(device_name);
  freeifaddrs(ifaddr);

  return ifaddrs_value;
}

static napi_value set_interface_address(napi_env env, const napi_callback_info info)
{
  size_t argc = 2;
  napi_value args[2];
  NAPI_CALL(env, napi_get_cb_info(env, info, &argc, args, NULL, NULL));
  if (argc != 2)
  {
    napi_throw_type_error(env, EWB_ARG_UNSPEC, "The expected argument size of set_interface_address is 2!");
    return NULL;
  }

  napi_valuetype argt_0, argt_1;
  NAPI_CALL(env, napi_typeof(env, args[0], &argt_0));
  NAPI_CALL(env, napi_typeof(env, args[1], &argt_1));

  if (argt_0 != napi_string)
  {
    napi_throw_type_error(env, EWB_ARG_UNSPEC, "The expected type of first argument of set_interface_address is string!");
    return NULL;
  }
  if (argt_1 != napi_object)
  {
    napi_throw_type_error(env, EWB_ARG_UNSPEC, "The expected type of second argument of set_interface_address is object!");
    return NULL;
  }

  napi_value family_props, ip_props;
  NAPI_CALL(env, napi_get_named_property(env, args[1], "family", &family_props));
  NAPI_CALL(env, napi_get_named_property(env, args[1], "ip", &ip_props));

  napi_valuetype family_type, ip_type;
  NAPI_CALL(env, napi_typeof(env, family_props, &family_type));
  NAPI_CALL(env, napi_typeof(env, ip_props, &ip_type));

  if (family_type != napi_number)
  {
    napi_throw_type_error(env, EWB_ARG_UNSPEC, "The expected type of family property of address is number!");
    return NULL;
  }
  if (ip_type != napi_string)
  {
    napi_throw_type_error(env, EWB_ARG_UNSPEC, "The expected type of ip property of address is string!");
    return NULL;
  }

  uint32_t family;
  char *device_name, *ip;
  NAPI_CALL(env, napi_get_value_uint32(env, family_props, &family));
  NAPI_CALL(env, napi_utils_get_value_string(env, args[0], &device_name));
  NAPI_CALL(env, napi_utils_get_value_string(env, ip_props, &ip));

  union
  {
    struct in_addr v4;
    struct in6_addr v6;
  } addr;

  if (inet_pton(family, ip, &addr) != 1)
  {
    napi_throw_type_error(env, EWB_AF_UNSPEC, "Failed to validate the address family! Please, give a valid ip address.");
    goto clean;
  }

  int sockfd = socket(family, SOCK_DGRAM, 0);
  if (sockfd == -1)
  {
    napi_throw_error(env, EWB_SOC_CALLFAIL, "Failed to open socket for interface!");
    goto clean;
  }

  // The warning here is expected, but will not remove for the future debug and improvement.
  struct ifreq ifr;
  strncpy(ifr.ifr_name, device_name, IFNAMSIZ);

  if (family == AF_INET)
  {
    ifr.ifr_addr.sa_family = AF_INET;
    memcpy(&((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr, &addr.v4, sizeof(struct in_addr));
  }
  else
  {
    ifr.ifr_addr.sa_family = AF_INET6;
    memcpy(&((struct sockaddr_in6 *)&ifr.ifr_addr)->sin6_addr, &addr.v6, sizeof(struct in6_addr));
  }

  if (ioctl(sockfd, SIOCSIFADDR, &ifr) == -1)
  {
    napi_throw_error(env, EWB_SOC_CALLFAIL, "SIOCSIFADDR");

    close(sockfd);
    goto clean;
  }

  close(sockfd);
  return NULL;

clean:
  free(device_name);
  free(ip);

  return NULL;
}

#define DECLARE_NAPI_METHOD(name, func)     \
  {                                         \
    name, 0, func, 0, 0, 0, napi_default, 0 \
  }

static napi_value init(napi_env env, napi_value exports)
{
  napi_property_descriptor get_device_descriptor = DECLARE_NAPI_METHOD("getDevice", get_device);
  napi_property_descriptor set_device_descriptor = DECLARE_NAPI_METHOD("setDevice", set_device);
  napi_property_descriptor add_device_descriptor = DECLARE_NAPI_METHOD("addDevice", add_device);
  napi_property_descriptor remove_device_descriptor = DECLARE_NAPI_METHOD("removeDevice", remove_device);
  napi_property_descriptor list_device_names_descriptor = DECLARE_NAPI_METHOD("listDeviceNames", list_device_names);
  napi_property_descriptor generate_public_key_descriptor = DECLARE_NAPI_METHOD("generatePublicKey", generate_public_key);
  napi_property_descriptor generate_private_key_descriptor = DECLARE_NAPI_METHOD("generatePrivateKey", generate_private_key);
  napi_property_descriptor generate_preshared_key_descriptor = DECLARE_NAPI_METHOD("generatePresharedKey", generate_preshared_key);
  napi_property_descriptor get_interface_address_descriptor = DECLARE_NAPI_METHOD("getInterfaceAddress", get_interface_address);
  napi_property_descriptor set_interface_address_descriptor = DECLARE_NAPI_METHOD("setInterfaceAddress", set_interface_address);
  NAPI_CALL(env, napi_define_properties(env, exports, 1, &get_device_descriptor));
  NAPI_CALL(env, napi_define_properties(env, exports, 1, &set_device_descriptor));
  NAPI_CALL(env, napi_define_properties(env, exports, 1, &add_device_descriptor));
  NAPI_CALL(env, napi_define_properties(env, exports, 1, &remove_device_descriptor));
  NAPI_CALL(env, napi_define_properties(env, exports, 1, &list_device_names_descriptor));
  NAPI_CALL(env, napi_define_properties(env, exports, 1, &generate_public_key_descriptor));
  NAPI_CALL(env, napi_define_properties(env, exports, 1, &generate_private_key_descriptor));
  NAPI_CALL(env, napi_define_properties(env, exports, 1, &generate_preshared_key_descriptor));
  NAPI_CALL(env, napi_define_properties(env, exports, 1, &get_interface_address_descriptor));
  NAPI_CALL(env, napi_define_properties(env, exports, 1, &set_interface_address_descriptor));
  NAPI_CALL(env, napi_utils_define_uint32_value(env, exports, "WGDEVICE_REPLACE_PEERS", WGDEVICE_REPLACE_PEERS));
  NAPI_CALL(env, napi_utils_define_uint32_value(env, exports, "WGDEVICE_HAS_PRIVATE_KEY", WGDEVICE_HAS_PRIVATE_KEY));
  NAPI_CALL(env, napi_utils_define_uint32_value(env, exports, "WGDEVICE_HAS_PUBLIC_KEY", WGDEVICE_HAS_PUBLIC_KEY));
  NAPI_CALL(env, napi_utils_define_uint32_value(env, exports, "WGDEVICE_HAS_LISTEN_PORT", WGDEVICE_HAS_LISTEN_PORT));
  NAPI_CALL(env, napi_utils_define_uint32_value(env, exports, "WGDEVICE_HAS_FWMARK", WGDEVICE_HAS_FWMARK));
  NAPI_CALL(env, napi_utils_define_uint32_value(env, exports, "WGPEER_REMOVE_ME", WGPEER_REMOVE_ME));
  NAPI_CALL(env, napi_utils_define_uint32_value(env, exports, "WGPEER_REPLACE_ALLOWEDIPS", WGPEER_REPLACE_ALLOWEDIPS));
  NAPI_CALL(env, napi_utils_define_uint32_value(env, exports, "WGPEER_HAS_PUBLIC_KEY", WGPEER_HAS_PUBLIC_KEY));
  NAPI_CALL(env, napi_utils_define_uint32_value(env, exports, "WGPEER_HAS_PRESHARED_KEY", WGPEER_HAS_PRESHARED_KEY));
  NAPI_CALL(env, napi_utils_define_uint32_value(env, exports, "WGPEER_HAS_PERSISTENT_KEEPALIVE_INTERVAL", WGPEER_HAS_PERSISTENT_KEEPALIVE_INTERVAL));
  NAPI_CALL(env, napi_utils_define_uint32_value(env, exports, "AF_INET", AF_INET));
  NAPI_CALL(env, napi_utils_define_uint32_value(env, exports, "AF_INET6", AF_INET6));

  return exports;
}

NAPI_MODULE(NODE_GYP_MODULE_NAME, init)
