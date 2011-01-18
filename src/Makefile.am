ACLOCAL_AMFLAGS			=	-I m4

APXS_libexec_LTLIBRARIES	=	mod_badge.la

mod_badge_la_SOURCES		=	mod_badge.c			\
					formatter.c			\
					html.c				\
					mapper.c			\
					factory.c			\
					decoder.c			\
					ssl_util.c			\
					misc.c				\
					mod_badge.h

mod_badge_la_LDFLAGS		=	@APXS_LDFLAGS@ @APR_LDFLAGS@	\
					@SSL_LIBS@ -module -avoid-version

mod_badge_la_CFLAGS		=	@CFLAGS@ @APXS_CFLAGS@		\
					@APR_CFLAGS@ @SSL_CFLAGS@	\
					@APXS_INCLUDES@ @APR_INCLUDES@
