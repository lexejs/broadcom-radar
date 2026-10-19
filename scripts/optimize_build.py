"""Keep M5GFX's include-dependent base class consistent when using LTO."""
Import("env")


def consistent_gfx_header(build_env, node):
    # Internal sources otherwise include LGFXBase without the public wrapper.
    return build_env.Object(node, CXXFLAGS=build_env["CXXFLAGS"] + ["-include", "M5GFX.h"])


env.AddBuildMiddleware(consistent_gfx_header, "*/M5GFX/*.cpp")
