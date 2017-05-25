package Redhat::6;

# Standard Pragmas
use utf8;
use strict;
use warnings FATAL => 'all';

# Standard Modules
use FindBin;
use Carp qw( croak );
use English qw{ -no_matches_vars };

# Local Modules
use Scar::Services;
use Scar::File::Bin;
use Scar::File::Lib;
use Scar::File::fstab;
use Scar::File::yum_conf;
use Scar::File::sshd_config;
use Scar::File::auditd_conf;

# Module Plugins
use Scar::Loader
    require     => 1,
    search_path => ['Redhat::6'];

# Module version
our $VERSION = 1.40;

#@method
#@returns Redhat::6
sub new {
    my ($class) = @ARG;
    my $self = bless {}, $class;

    #@type Scar::Services
    our $services = Scar::Services->new();

    #@type Scar::File::Bin
    our $bin = Scar::File::Bin->new();

    #@type Scar::File::Lib
    our $lib = Scar::File::Lib->new();

    #@type Scar::File::fstab
    our $fstab = Scar::File::fstab->new();

    #@type Scar::File::yum_conf
    our $yum_conf = Scar::File::yum_conf->new();

    #@type Scar::File::sshd_config
    our $sshd_config = Scar::File::sshd_config->new();

    #@type Scar::File::auditd_conf
    our $auditd_conf = Scar::File::auditd_conf->new();

    return $self;
}

1;

__END__
