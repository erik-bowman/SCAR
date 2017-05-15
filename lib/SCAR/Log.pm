#!/usr/bin/perl
# ------------------------------------------------------------------------------
# NAME
#   SCAR::Log
#
# DESCRIPTION
#   Handles all logging, stdout and stderr functionality for SCAR
#
# SEE ALSO
#   SCAR
#
# AUTHOR
#   Erik Bowman (erik.bowman@icsinc.com)
#
# ------------------------------------------------------------------------------

package SCAR::Log;

# Standard pragmas
use 5.010;
use utf8;
use strict;
use warnings FATAL => 'all';
use open ':std', ':encoding(UTF-8)';

# Standard modules
use POSIX;
use Term::Cap;
use IO::Socket::UNIX qw( SOCK_STREAM SOMAXCONN );

# SCAR modules
use SCAR;

# ------------------------------------------------------------------------------

my $VERSION = 0.01;
my @spinner = ("-", "\\", "|", "/");

# ------------------------------------------------------------------------------
# SYNOPSIS
#
# DESCRIPTION
#
# ARGUMENTS
#
# ------------------------------------------------------------------------------

sub new {
    my ($class, $base_directory, $sock_file, $debug) = @_;
    SCAR->version_check($class, $VERSION);
    my @timestamp = SCAR->timestamp();
    my $self = bless {
            base => $base_directory,
            sock_file => $sock_file,
            debug => $debug,
            active => "$base_directory/$timestamp[0]",
        }, $class;
    $self->{socket} = IO::Socket::UNIX->new(
        Type => SOCK_STREAM,
        Peer => $self->{sock_file},
    );
    mkdir $self->{active} unless -d $self->{active};
    $self->{pos} = 0;
    $self->{'bksp'} = chr(0x08);
    $self->{'last_size'} = 0;
    $self->debug("$class loaded");
    return $self;
}

# ------------------------------------------------------------------------------
# SYNOPSIS
#
# DESCRIPTION
#
# ARGUMENTS
#
# ------------------------------------------------------------------------------

sub err {
    my ($self, $message) = @_;
    my @timestamp = SCAR->timestamp();
    $self->write_to_file("error.log", "$timestamp[0]: $message");
    return 0 unless $self->{quiet};
    print $self->{'bksp'} x $self->{'last_size'};
    die "$timestamp[0]: ERROR: $message\n";
    return $self;
}

# ------------------------------------------------------------------------------
# SYNOPSIS
#
# DESCRIPTION
#
# ARGUMENTS
#
# ------------------------------------------------------------------------------

sub info {
    my ($self, $message) = @_;
    my @timestamp = SCAR->timestamp();
    $self->write_to_file("scar.log", "$timestamp[0]: $message\n");
    return 0 if $self->{quiet};
    $self->next("$timestamp[0]:  INFO: $message");
    return $self;
}

# ------------------------------------------------------------------------------
# SYNOPSIS
#
# DESCRIPTION
#
# ARGUMENTS
#
# ------------------------------------------------------------------------------

sub warn {
    my ($self, $message) = @_;
    my @timestamp = SCAR->timestamp();
    $self->write_to_file("scar.log", "$timestamp[0]: $message");
    return 0 if $self->{quiet};
    $self->next("$timestamp[0]:  WARN: $message");
    return $self;
}

# ------------------------------------------------------------------------------
# SYNOPSIS
#
# DESCRIPTION
#
# ARGUMENTS
#
# ------------------------------------------------------------------------------

sub debug {
    my ($self, $message) = @_;
    my @timestamp = SCAR->timestamp();
    $self->write_to_file("debug.log", "$timestamp[0]: $message");
    print $self->{socket}, "$timestamp[1]:$message";
    return $self;
}

# ------------------------------------------------------------------------------
# SYNOPSIS
#   SCAR::Log->write_to_file($file, $message);
#
# DESCRIPTION
#   Writes an entry into the specified log file
#
# ARGUMENTS
#   $file       - the log file for writing to
#   $message    - the entry for the log file
#
# ------------------------------------------------------------------------------

sub write_to_file {
    my ($self, $file, $message ) = @_;
    open( my $fh, '>', "$self->{active}/$file" )
        or die "Could not open file '$file' $!\n";
    print $fh $message;
    close $fh;
}

# ------------------------------------------------------------------------------

1;

__END__
