#!/bin/env perl

# Standard Pragmas
use utf8;
use strict;
use warnings FATAL => 'all';

# Standard Modules
use POSIX;
use FindBin;
use Carp qw( croak );
use File::Spec::Functions;
use English qw{ -no_match_vars };

# Add Local Modules
use lib File::Spec::Functions::catdir( $FindBin::Bin, '..', 'lib' );

# Local modules
use Redhat::6;
use Scar::Util::Log;

# Version
our $VERSION = 1.40;

# Permissions self check
if ( POSIX::getuid() ne '0' ) {
    croak 'Permissions Error: Script not running as root';
}

# Directory checks
if ( !-d '/SCAR' ) {
    print "Creating missing directory '/SCAR'\n";
    mkdir '/SCAR', 0700;
}

if ( !-d '/SCAR/logs' ) {
    print "Creating missing directory '/SCAR/logs'\n";
    mkdir '/SCAR/logs', 0700;
}

if ( !-d '/SCAR/backups' ) {
    print "Creating missing directory '/SCAR/backups'\n";
    mkdir '/SCAR/backups', 0700;
}

if ( !-d '/SCAR/reports' ) {
    print "Creating missing directory '/SCAR/reports'\n";
    mkdir '/SCAR/reports', 0700;
}

# Set Defaults
$main::Debug = 0;

#@type Redhat::6;
$main::Redhat_6 = Redhat::6->new();

log_info('Loading plugins');
my $plugin_count = 0;
foreach my $plugin ( $main::Redhat_6->plugins() ) {
    $plugin_count++;
    log_debug( 'Loading pluigin ' . $plugin->get_stig_id() );
}
log_info('Done loading plugins');
log_info("$plugin_count plugins loaded");

__END__
