				mod_badge


This is an Apache httpd module capable of dynamic redirection and
authentication using an encrypted URI path component.
This module is compatible with Apache httpd version 2.2 and 2.4.


When to use it
  When a particular site has to give access to assigned subtrees to different
users, all non-badge solutions involve heavy configuration changes such
as (for each user):
- Use mod_user and create a Unix user.
- Create a specific directory, update authentication database and Apache
configuration accordingly, then reload server configuration.

If the user count is high and/or new users occur frequently, these operations
can quickly load the administrator tasks and Apache configuration files.

The solution to this problem is mod_badge: this module allows an URL to contain
a badge giving access to a specific subtree during a defined period of time and
containing its own authentication parameters (equivalent to a pass in a theme
park, for example). Since it is encrypted, the badge owner is not able to
decode it to gain direct access to the underlying subtree.

It is much easier to generate a badge for a new user than to create the
specific configuration and authentication parameters that will be needed
without mod_badge.


How it works
  Assuming an URL containing a badge is of the form:

scheme://srvr/path-prfx/badge/pathinfo

mod_badge maps it internally to:

scheme://badge-usr:badge-pswd@srvr/badge-path-prfx/pathinfo

where badge-usr, badge-pswd and badge-path-prfx are extracted from the badge.

  This is only an URL mapping, not a redirection: in particular, the client
never receives information about the translated URL.

  The badge itself is an URL path component consisting in a modified base64
string (to accomodate URL syntax) that contains the encrypted specific
parameters.


How to build an installation tarball from a git clone.

1. $ git clone https://github.com/monnerat/mod_badge.git
2. $ cd mod_badge
3. $ ./buildconf
4. $ ./configure --prefix=/usr
5. $ make dist

Then find the tarball mod_badge-*.tar.gz in the current directory.


How to install from a distribution tarball:

1. Download the tarball, gunzip and untar
2. $ cd mod_badge-*
3. $ ./configure --prefix=/usr/
4. $ make
5. $ sudo make install

Then read mod_badge documentation for configuration.


How to build an rpm package from a distribution tarball.

1. rpmbuild -ta mod_badge-*.tar.gz
