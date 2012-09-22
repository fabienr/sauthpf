PHP_ARG_ENABLE(sauthpf, Whether to enable SAuthPF support Functions,
    [  --enable-sauthpf Enable SAuthPF Support ])

if test "$PHP_SAUTHPF" = "yes"; then

	PHP_NEW_EXTENSION(sauthpf, php-sauthpf.c \
	    modules/*.c, $ext_shared, ,-I@ext_srcdir@/modules)
	PHP_SUBST(SAUTHPF_SHARED_LIBADD)

	AC_DEFINE(HAVE_SAUTHPF, 1, [Whether you have SauthPF Support])
fi

export CFLAGS="-g -c -Wall -O0 `pkg-config --cflags sqlite3` $DEFINES"
