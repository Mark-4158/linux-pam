subdir('include/security')

libpam_ply_src = [
  'help_socket.c',
  'ply_conv.c',
]

libpam_ply_inc = include_directories('include')

libpam_ply_version = '1.0.0'
libpam_ply_map = 'libpam_ply.map'
libpam_ply_map_path = meson.current_source_dir() / libpam_ply_map

libpam_ply_link_deps = [libpam_ply_map]
libpam_ply_link_args = ['-Wl,--version-script=' + libpam_ply_map_path]

libpam_ply = shared_library(
  'pam_ply',
  sources: libpam_ply_src,
  include_directories: [libpam_ply_inc, libpamc_inc],
  dependencies: [libply_boot_client, libpam_internal_dep, libpam_dep],
  link_depends: libpam_ply_link_deps,
  link_args: libpam_ply_link_args,
  version: libpam_ply_version,
  install: true,
)

libpam_ply_dep = declare_dependency(
  include_directories: [libpam_ply_inc],
  link_with: [libpam_ply],
)

pkgconfig.generate(
  libpam_ply,
  description: 'PAM conversation function that uses Plymouth as its UX',
  name: 'pam_ply',
  filebase: 'pam_ply',
  version: meson.project_version(),
  url: 'http://www.linux-pam.org/'
)
