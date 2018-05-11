# 
# ocmd spec file
#

Name: ocmd
Summary: CERNBox Open Cloud Mesh Daemon
Version: 1.0.0
Release: 1%{?dist}
License: AGPLv3
BuildRoot: %{_tmppath}/%{name}-buildroot
Group: CERN-IT/ST
BuildArch: x86_64
Source: %{name}-%{version}.tar.gz

%description
This RPM provides a golang webserver that provides an authentication service for web clients.

# Don't do any post-install weirdness, especially compiling .py files
%define __os_install_post %{nil}

%prep
%setup -n %{name}-%{version}

%install
# server versioning

# installation
rm -rf %buildroot/
mkdir -p %buildroot/usr/local/bin
mkdir -p %buildroot/etc/ocmd
mkdir -p %buildroot/etc/logrotate.d
mkdir -p %buildroot/usr/lib/systemd/system
mkdir -p %buildroot/var/log/ocmd
install -m 755 ocmd	     %buildroot/usr/local/bin/ocmd
install -m 644 ocmd.service    %buildroot/usr/lib/systemd/system/ocmd.service
install -m 644 ocmd.yaml       %buildroot/etc/ocmd/ocmd.yaml
install -m 644 ocmd.logrotate  %buildroot/etc/logrotate.d/ocmd

%clean
rm -rf %buildroot/

%preun

%post

%files
%defattr(-,root,root,-)
/etc/ocmd
/etc/logrotate.d/ocmd
/var/log/ocmd
/usr/lib/systemd/system/ocmd.service
/usr/local/bin/*
%config(noreplace) /etc/ocmd/ocmd.yaml


%changelog
* Wed May 09 2018 Hugo Gonzalez Labrador <hugo.gonzalez.labrador@cern.ch> 1.0.0
- v1.0.0

