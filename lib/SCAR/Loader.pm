#!/bin/env perl
# ------------------------------------------------------------------------------
# NAME
#   SCAR::Loader
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

package SCAR::Loader;

# Standard pragmas
use utf8;
use strict;
use warnings FATAL => 'all';

# Standard modules
use File::Find;
use Carp qw( croak );
use File::Spec::Functions;

# Module version
our $VERSION = 1.40;

# ------------------------------------------------------------------------------
# SYNOPSIS
#   new
#
# DESCRIPTION
#
# ------------------------------------------------------------------------------

sub new {
    my ( $class, %args ) = @_;
    my $self = bless \%args, $class;

    croak 'Unable to load plugins: no plugin directory specified'
        if !defined $self->{plugins};
    croak 'Unable to load plugins: not a valid directory'
        if !-d $self->{plugins};
    return $self;
}

# ------------------------------------------------------------------------------
# SYNOPSIS
#   load_plugins
#
# DESCRIPTION
#
# ------------------------------------------------------------------------------

sub load_plugins {
    my ($self)  = @_;
    my $method  = 'new';
    my @objs    = ();
    my @plugins = $self->find_files;
    push @INC, $self->{plugins};
    return () unless @plugins;
    foreach my $plugin (@plugins) {
        my @plugin_info = File::Spec::Functions::splitpath($plugin);
        if ($plugin_info[2] =~ /^(.*)[.]pm$/msx) {
            $plugin = $1
        }
        eval qq{"require $plugin;"};
        croak $EVAL_ERROR if $EVAL_ERROR;
        next unless $plugin->can($method);
        push @objs, $plugin;
    }
    return @objs;
}

# ------------------------------------------------------------------------------
# SYNOPSIS
#   find_files
#
# DESCRIPTION
#
# ------------------------------------------------------------------------------

sub find_files {
    my ($self) = @_;
    my @files = ();
    {
        local $_;
        File::Find::find(
            {   no_chdir => 1,
                wanted   => sub {
                    return unless $File::Find::name =~ /[.]pm$/msx;
                    ( my $path = $File::Find::name ) =~ s#^\\./##;
                    push @files, $path;
                }
            },
            $self->{plugins}
        );
    }
    return @files;
}

# ------------------------------------------------------------------------------

1;

__END__
