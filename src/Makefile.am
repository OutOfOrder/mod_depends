CLEANFILES = .libs/libmod_depends *~

libmod_depends_la_SOURCES = mod_depends.c
libmod_depends_la_CFLAGS = -Wall ${MODULE_CFLAGS}
libmod_depends_la_LDFLAGS =  -rpath ${AP_LIBEXECDIR} -module -avoid-version

lib_LTLIBRARIES = libmod_depends.la 

make_so: ${lib_LTLIBRARIES}
	@if test ! -L mod_depends.so ; then ln -s .libs/libmod_depends.so mod_depends.so ; fi

clean:
	rm -fr .libs
	rm -f *.o *.lo *.la
	rm -f mod_depends.so

install: make_so
	@${APXS_BIN} -i -n depends mod_depends.so
	cp ../include/mod_depends.h ${AP_INCLUDEDIR}
	@echo ""
	@echo ""
	@echo "***********************************************"
	@echo ""
	@echo "   Please read the documentation at            "
	@echo "   http://www.outoforder.cc/projects/apache/mod_depends/ "
	@echo "   for details on configuration of this module     "
	@echo ""
	@echo "***********************************************"
	@echo ""

activate: make_so
	@${APXS_BIN} -i -a -n depends mod_depends.so
	@echo ""
	@echo ""
	@echo "***********************************************"
	@echo ""
	@echo "   Please read the documentation at            "
	@echo "   http://www.outoforder.cc/projects/apache/mod_depends/ "
	@echo "   for details on configuration of this module     "
	@echo ""
	@echo "***********************************************"
	@echo ""
