Name:           pam_wrapper
Version:        1.0.0
Release:        1%{?dist}

Summary:        A tool to test PAM applications and PAM modules
License:        GPLv3+
Url:            http://cwrap.org/

Source0:        %{name}-%{version}.tar.gz

BuildRequires:  cmake
BuildRequires:  libcmocka-devel
BuildRequires:  python-devel
BuildRequires:  pam-devel

Requires:       cmake
Requires:       pkgconfig

%description
This component of cwrap allows you to either test your PAM (Linux-PAM
and OpenPAM) application or module.

For testing PAM applications, simple PAM module called pam_matrix is
included. If you plan to test a PAM module you can use the pamtest library,
which simplifies testing of modules. You can combine it with the cmocka
unit testing framework or you can use the provided Python bindings to
write tests for your module in Python.


%package libpamtest
Summary:        A tool to test PAM applications and PAM modules
License:        GPLv3+
Requires:       pam_wrapper = %{version}-%{release}

%description libpamtest
If you plan to test a PAM module you can use this library, which simplifies
testing of modules.


%package libpamtest-devel
Summary:        A tool to test PAM applications and PAM modules
License:        GPLv3+
Requires:       pam_wrapper = %{version}-%{release}
Requires:       libpamtest = %{version}-%{release}

%description libpamtest-devel
If you plan to develop tests for a PAM module you can use this library,
which simplifies testing of modules. This subpackage includes the header
files for libpamtest


%package python-libpamtest
Summary:        A python wrapper for libpamtest
License:        GPLv3+
Requires:       pam_wrapper = %{version}-%{release}
Requires:       libpamtest = %{version}-%{release}

%description python-libpamtest
If you plan to develop python tests for a PAM module you can use this
library, which simplifies testing of modules. This subpackage includes
the header files for libpamtest


%prep
%setup -q


%build
if test ! -e "obj"; then
  mkdir obj
fi
pushd obj
%cmake \
  -DUNIT_TESTING=ON \
  %{_builddir}/%{name}-%{version}

make %{?_smp_mflags} VERBOSE=1
popd


%install
pushd obj
make DESTDIR=%{buildroot} install
popd


%post -p /sbin/ldconfig


%postun -p /sbin/ldconfig


%check
pushd obj
make test
popd

%files
%defattr(-,root,root,-)
%{_libdir}/libpam_wrapper.so*
%{_libdir}/pkgconfig/pam_wrapper.pc
%{_libdir}/cmake/pam_wrapper/pam_wrapper-config-version.cmake
%{_libdir}/cmake/pam_wrapper/pam_wrapper-config.cmake
%{_libdir}/pam_wrapper/pam_matrix.so
%{_libdir}/pam_wrapper/pam_get_items.so
%{_libdir}/pam_wrapper/pam_set_items.so
%{_mandir}/man1/pam_wrapper.1*
%{_mandir}/man8/pam_matrix.8*
%{_mandir}/man8/pam_get_items.8*
%{_mandir}/man8/pam_set_items.8*

%files libpamtest
%defattr(-,root,root,-)
%{_libdir}/libpamtest.so

%files libpamtest-devel
%defattr(-,root,root,-)
%{_libdir}/libpamtest.so.*
%{_libdir}/pkgconfig/libpamtest.pc
%{_libdir}/cmake/libpamtest/libpamtest-config-version.cmake
%{_libdir}/cmake/libpamtest/libpamtest-config.cmake
%{_includedir}/libpamtest.h

%files python-libpamtest
%defattr(-,root,root,-)
%{python2_sitearch}/pypamtest.so


%changelog
* Wed Dec 16 2015 Jakub Hrozek <jakub.hrozek@posteo.se> - 1.0.0-1
- Initial packaging
