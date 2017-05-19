package Redhat;

use strict;
use warnings FATAL => 'all';

use Module::Pluggable
    require => 1,
    search_path => ['Redhat::6'],
    sub_name    => 'get_redhat6_plugins';
use Module::Pluggable
    require => 1,
    search_path => ['Redhat::7'],
    sub_name    => 'get_redhat7_plugins';



1;

__END__
