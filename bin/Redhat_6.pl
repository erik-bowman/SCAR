#!/bin/env perl

=comment

Perl Core Pragmas

=cut

use utf8;
use strict;
use warnings FATAL => 'all';

=comment

Perl Core Modules

=cut

use POSIX;
use FindBin;
use Carp qw( croak );
use File::Spec::Functions;
use English qw{ -no_match_vars };

=comment

Update Perl's library paths to include Local Scar libraries

=cut

use lib File::Spec::Functions::catdir( $FindBin::Bin, '..', 'lib' );

=comment

Scar Local Modules

=cut

use Redhat;
use Scar::Util::Log;

=comment

Script Version

=cut

our $VERSION = 1.4.0;

=comment

Compilation time checks and tasks

=cut

BEGIN {

=comment

Clear the terminal

=cut

    system 'clear';

=comment

Require root privileges

=cut

    if ( POSIX::getuid() ne '0' ) {
        croak 'Permissions Error: Script not running as root';
    }

=comment

Required directory checks and creation

=cut

    if ( !-d '/SCAR' ) {
        print "Creating missing directory '/SCAR'\n";

        mkdir '/SCAR', 0700
            or croak "Unable to create directory '/SCAR': $OS_ERROR";
    }

    if ( !-d '/SCAR/logs' ) {
        print "Creating missing directory '/SCAR/logs'\n";

        mkdir '/SCAR/logs', 0700
            or croak "Unable to create directory '/SCAR/logs': $OS_ERROR";
    }

    if ( !-d '/SCAR/backups' ) {
        print "Creating missing directory '/SCAR/backups'\n";

        mkdir '/SCAR/backups', 0700
            or croak "Unable to create directory '/SCAR/backups': $OS_ERROR";
    }

    if ( !-d '/SCAR/reports' ) {
        print "Creating missing directory '/SCAR/reports'\n";

        mkdir '/SCAR/reports', 0700
            or croak "Unable to create directory '/SCAR/reports': $OS_ERROR";
    }

=comment

Default debugging output value

=cut

    $main::debug = 1;
}

log_info('Starting Scar for Redhat Enterprise Linux 6');

#@type Redhat
$main::redhat = Redhat->new();

my @checks       = $main::redhat->load_medium_severity();

foreach my $plugin (@checks) {

    $plugin->check();

    log_info( $plugin->get_stig_id() . ": " . $plugin->get_status() );
}

log_info(' Attempting remediations...');

foreach my $plugin (@checks) {

    if ($plugin->get_status eq 'O') {

        $plugin->remediate();

        if ($plugin->get_status eq 'O') {
            log_info( $plugin->get_stig_id().': Remediation failed' );
            next;
        }

        if ($plugin->get_status eq 'NF') {
            log_info( $plugin->get_stig_id().': Remediation successful' );
            next;
        }

    }

}

__END__
