PROJECT(libsodium-chacha20 C)

SET(VERSION "0.0.1")

CMAKE_MINIMUM_REQUIRED(VERSION 2.6.0 FATAL_ERROR)

FIND_LIBRARY(LIBSODIUM NAMES sodium PATH_SUFFIXES lib64 lib
	                  PATHS
	                      ~/Library/Frameworks
	                      /Library/Frameworks
	                      /usr/local
	                      /usr
	                      /sw
	                      /opt/local
	                      /opt/csw
	                      /opt
	                 DOC "Path where the libsodium library can be found")
IF(NOT LIBSODIUM)
	MESSAGE(FATAL_ERROR "libsodium is required")
ENDIF(NOT LIBSODIUM)

FIND_PATH(LIBSODIUM_INCLUDE sodium.h PATHS 	/opt/include
										/usr/include
										/usr/local/include
										DOC "Path where the libsodium header files can be found")
IF(NOT LIBSODIUM_INCLUDE)
	MESSAGE(FATAL_ERROR "libsodium header is required")
ENDIF(NOT LIBSODIUM_INCLUDE)
GET_FILENAME_COMPONENT(LIBSODIUM_PATH "${LIBSODIUM}" PATH)
INCLUDE_DIRECTORIES("${LIBSODIUM_INCLUDE}")
LINK_DIRECTORIES("${LIBSODIUM_PATH}")

INCLUDE_DIRECTORIES("${CMAKE_SOURCE_DIR}/include")

SET(LIBSRC src/crypto_stream/chacha20/ref/chacha.c
		   src/crypto_stream/chacha20/ref/stream_chacha20_ref.c
		   src/crypto_stream/chacha20/stream_chacha20_api.c
		   src/crypto_stream/try.c
		   src/crypto_secretbox/chacha20poly1305/secretbox_chacha20poly1305_api.c
		   src/crypto_secretbox/chacha20poly1305/ref/box_chacha20poly1305.c)

ADD_LIBRARY(sodium-chacha20 SHARED ${LIBSRC})

TARGET_LINK_LIBRARIES(sodium-chacha20 sodium)