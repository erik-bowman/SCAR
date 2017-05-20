#!/bin/env perl
use strict;
use warnings FATAL => 'all';

use FindBin;
use File::Spec::Functions;
use lib File::Spec::Functions::catdir($FindBin::Bin, q{..}, 'lib');

use Redhat::6;

use Data::Dumper;


my $redhat6 = Redhat::6->new();

print Data::Dumper::Dumper($redhat6->{files});
