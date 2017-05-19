package Redhat;

# Standard pragmas
use utf8;
use strict;
use warnings FATAL => 'all';

# Module version
our $VERSION = 0.01;

use Module::Pluggable
    require     => 1,
    search_path => ['Redhat::6'],
    sub_name    => 'get_redhat6_plugins';
use Module::Pluggable
    require     => 1,
    search_path => ['Redhat::7'],
    sub_name    => 'get_redhat7_plugins';

1;

__END__
