{
    "target_defaults": {
        "configurations": {
            "Release": {
                "defines+": ["_FORTIFY_SOURCE=2"]
            },
            "Debug": {
                "cflags": ["-g"]
            }
        }
    },
    "targets": [
        {
            "target_name": "<(module_name)",
            "defines": [
                "NAPI_VERSION=<(napi_build_version)",
            ],
            "sources": [
                "./adaptor/EmbeddableWireguardExtension.c",
                "./adaptor/napi_utils.c",
                "./externs/wireguard-tools/contrib/embeddable-wg-library/wireguard.c"
            ]
        },
        {
            "target_name": "action_after_build",
            "type": "none",
            "dependencies": ["<(module_name)"],
            "copies": [
                {
                    "files": ["<(PRODUCT_DIR)/<(module_name).node"],
                    "destination": "<(module_path)"
                }
            ]
        }
    ]
}
