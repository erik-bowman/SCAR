package Scar::Util::Loader;

# Standard pragmas
use utf8;
use strict;
use warnings FATAL => 'all';

# Standard modules
use File::Find;
use Carp qw( croak );

# Scar modules
use Scar qw( explode_path );

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

sub get_plugins_list {
    my ($self)             = @_;
    my $plugin_constructor = 'new';
    my @plugin_objects     = ();
    my @plugins            = $self->_find_plugins;
    push @INC, $self->{plugins};
    if ( !@plugins ) {
        return ();
    }
    foreach my $plugin (@plugins) {
        my @plugin_path_components = explode_path($plugin);
        if ( $plugin_path_components[2] =~ /^(.*)[.]pm$/msx ) {
            $plugin = $1;
            eval qq{"require $plugin;"};
            croak $EVAL_ERROR if $EVAL_ERROR;
            if ( !$plugin->can($plugin_constructor) ) {
                next;
            }
            push @plugin_objects, $plugin;
        }
    }
    return @plugin_objects;
}

sub _find_plugins {
    my ($self) = @_;
    my @files = ();
    {
        File::Find::find(
            {   no_chdir => 1,
                wanted   => sub {
                    if ( !$File::Find::name =~ /[.]pm$/msx ) {
                        return;
                    }
                    ( my $path = $File::Find::name ) =~ s{^\\.}{}msx;
                    push @files, $path;
                    }
            },
            $self->{plugins}
        );
    }
    return @files;
}

1;

__END__
