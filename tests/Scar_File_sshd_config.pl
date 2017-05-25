#!/usr/bin/perl
use strict;
use warnings FATAL => 'all';

use FindBin;
use File::Spec::Functions;
use lib File::Spec::Functions::catdir( $FindBin::Bin, qw{.. lib} );

use Scar::File::sshd_config;

use Data::Dumper;

my $sshd_config = Scar::File::sshd_config->new();

#print Data::Dumper::Dumper($sshd_config);
