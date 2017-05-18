# ------------------------------------------------------------------------------
# NAME
#   Scar::Loader
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

package Scar::Util::Loader;

# Standard modules
use utf8;
use strict;
use File::Find;
use Carp qw( croak );
use warnings FATAL => 'all';

# Scar modules
use Scar qw( EXPLODEPATH );

# Module version
our $VERSION = 1.40;

sub new {
    my ( $class, %args ) = @_;
    my $self = bless \%args, $class;

    if ( !defined $self->{plugins} ) {
        croak 'Unable to load plugins: no plugin directory specified';
    }

    if ( !-d $self->{plugins} ) {
        croak 'Unable to load plugins: not a valid directory';
    }
    return $self;
}

sub PLUGINS {
    my ($self)      = @_;
    my $CONSTRUCTOR = 'new';
    my @OBJECTS     = ();
    my @PLUGINS     = $self->FIND_PLUGINS;
    push @INC, $self->{PLUGINS};
    if ( !@PLUGINS ) {
        return ();
    }
    foreach my $PLUGIN (@PLUGINS) {
        my @plugin_info = EXPLODEPATH($PLUGIN);
        if ( $plugin_info[2] =~ /^(.*)[.]pm$/msx ) {
            $PLUGIN = $1;
        }
        eval qq{"require $PLUGIN;"};
        croak $EVAL_ERROR if $EVAL_ERROR;
        if ( !$PLUGIN->can($CONSTRUCTOR) ) {
            next;
        }
        push @OBJECTS, $PLUGIN;
    }
    return @OBJECTS;
}

sub FIND_PLUGINS {
    my ($self) = @_;
    my @FILES = ();
    {
        local $_;
        File::Find::find(
            {   no_chdir => 1,
                wanted   => sub {
                    if ( !$File::Find::name =~ /[.]pm$/msx ) {
                        return;
                    }
                    ( my $PATH = $File::Find::name ) =~ s{^\\.}{}msx;
                    push @FILES, $PATH;
                }
            },
            $self->{plugins}
        );
    }
    return @FILES;
}

1;

__END__
