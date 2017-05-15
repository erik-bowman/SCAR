#!/usr/bin/perl
# ------------------------------------------------------------------------------
# NAME
#   SCAR::Core
#
# DESCRIPTION
#
#
# SEE ALSO
#
#
# AUTHOR
#   Erik Bowman (erik.bowman@icsinc.com)
#
# ------------------------------------------------------------------------------

package SCAR::Core;

# Standard pragmas
use strict;
use warnings FATAL => 'all';

# Standard modules
use POSIX qw(strftime);

# ------------------------------------------------------------------------------

require Exporter;

our $VERSION = 0.01;
our @ISA = qw(Exporter);
our @EXPORT = qw(version_check);
our @EXPORT_OK = qw(timestamp);

1;

__END__
