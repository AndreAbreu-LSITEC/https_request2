#
# "main" pseudo-component makefile.
#
# (Uses default behaviour of compiling all source files in directory, adding 'include' to include path.)
# COMPONENT_EMBED_TXTFILES := server_root_cert.pem local_server_cert.pem
COMPONENT_EMBED_TXTFILES := certs/ClientCert.pem
COMPONENT_EMBED_TXTFILES += certs/ServerCert.pem
COMPONENT_EMBED_TXTFILES += certs/ServerKey.pem
