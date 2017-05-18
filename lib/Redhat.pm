package Redhat;

use strict;
use warnings FATAL => 'all';

use Module::Pluggable
    search_path => ['Redhat::6'],
    sub_name    => 'get_redhat6_plugins';
use Module::Pluggable
    search_path => ['Redhat::7'],
    sub_name    => 'get_redhat7_plugins';



1;

__END__
