package Scar::File::sshd_config;

# Standard Pragmas
use strict;
use warnings FATAL => 'all';

# Standard Modules
use Carp qw{ croak };
use English qw{ -no_match_vars };

# Local Modules
use Scar::File;
use Scar::Util::Log;

our $VERSION = 1.40;

#@method
#@returns Scar::File::sshd_config
sub new {
    my ($class) = @ARG;
    my $self = bless {
        Ciphers                 => undef,
        Banner                  => undef,
        Protocol                => undef,
        IgnoreRhosts            => undef,
        PrintLastlog            => undef,
        PermitRootLogin         => undef,
        ClientAliveInterval     => undef,
        ClientAliveCountMax     => undef,
        PermitEmptyPasswords    => undef,
        PermitUserEnvironment   => undef,
        HostbasedAuthentication => undef,
    }, $class;

    log_info('Reading /etc/ssh/sshd_config');

    my @file_contents = read_file( '/etc/ssh/sshd_config', 'utf8' );

    foreach my $line (@file_contents) {
        if ( $line =~ /^Ciphers\s+(.*)$/imsx ) {
            $self->set_Ciphers($1);
        }
        if ( $line =~ /^Banner\s+(.*)$/imsx ) {
            $self->set_Banner($1);
        }
        if ( $line =~ /^Protocol\s+(.*)$/imsx ) {
            $self->set_Protocol($1);
        }
        if ( $line =~ /^IgnoreRhosts\s+(.*)$/imsx ) {
            $self->set_IgnoreRhosts($1);
        }
        if ( $line =~ /^PrintLastlog\s+(.*)$/imsx ) {
            $self->set_PrintLastlog($1);
        }
        if ( $line =~ /^PermitRootLogin\s+(.*)$/imsx ) {
            $self->set_PermitRootLogin($1);
        }
        if ( $line =~ /^ClientAliveInterval\s+(.*)$/imsx ) {
            $self->set_ClientAliveInterval($1);
        }
        if ( $line =~ /^ClientAliveCountMax\s+(.*)$/imsx ) {
            $self->set_ClientAliveCountMax($1);
        }
        if ( $line =~ /^PermitEmptyPasswords\s+(.*)$/imsx ) {
            $self->set_PermitEmptyPasswords($1);
        }
        if ( $line =~ /^PermitUserEnvironment\s+(.*)$/imsx ) {
            $self->set_PermitUserEnvironment($1);
        }
        if ( $line =~ /^HostbasedAuthentication\s+(.*)$/imsx ) {
            $self->set_HostbasedAuthentication($1);
        }

    }

    log_info('Done reading /etc/ssh/sshd_config');
    return $self;
}

sub set_Ciphers {
    my ( $self, @values ) = @ARG;
    foreach my $value (@values) {
        push @{ $self->{Ciphers} }, $value;
    }
    return $self->{Ciphers};
}

sub set_Banner {
    my ( $self, $value ) = @ARG;
    $self->{Banner} = $value;
    return $self->{Banner};
}

sub set_Protocol {
    my ( $self, $value ) = @ARG;
    $self->{Protocol} = $value;
    return $self->{Protocol};
}

sub set_IgnoreRhosts {
    my ( $self, $value ) = @ARG;
    $self->{IgnoreRhosts} = $value;
    return $self->{IgnoreRhosts};
}

sub set_PrintLastlog {
    my ( $self, $value ) = @ARG;
    $self->{PrintLastlog} = $value;
    return $self->{PrintLastlog};
}

sub set_PermitRootLogin {
    my ( $self, $value ) = @ARG;
    $self->{PermitRootLogin} = $value;
    return $self->{PermitRootLogin};
}

sub set_ClientAliveInterval {
    my ( $self, $value ) = @ARG;
    $self->{ClientAliveInterval} = $value;
    return $self->{ClientAliveInterval};
}

sub set_ClientAliveCountMax {
    my ( $self, $value ) = @ARG;
    $self->{ClientAliveCountMax} = $value;
    return $self->{ClientAliveCountMax};
}

sub set_PermitEmptyPasswords {
    my ( $self, $value ) = @ARG;
    $self->{PermitEmptyPasswords} = $value;
    return $self->{PermitEmptyPasswords};
}

sub set_PermitUserEnvironment {
    my ( $self, $value ) = @ARG;
    $self->{PermitUserEnvironment} = $value;
    return $self->{PermitUserEnvironment};
}

sub set_HostbasedAuthentication {
    my ( $self, $value ) = @ARG;
    $self->{HostbasedAuthentication} = $value;
    return $self->{HostbasedAuthentication};
}

sub get_Ciphers {
    my ($self) = @ARG;
    return $self->{Ciphers};
}

sub get_Banner {
    my ($self) = @ARG;
    return $self->{Banner};
}

sub get_Protocol {
    my ($self) = @ARG;
    return $self->{Protocol};
}

sub get_IgnoreRhosts {
    my ($self) = @ARG;
    return $self->{IgnoreRhosts};
}

sub get_PrintLastlog {
    my ($self) = @ARG;
    return $self->{PrintLastlog};
}

sub get_PermitRootLogin {
    my ($self) = @ARG;
    return $self->{PermitRootLogin};
}

sub get_ClientAliveInterval {
    my ($self) = @ARG;
    return $self->{ClientAliveInterval};
}

sub get_ClientAliveCountMax {
    my ($self) = @ARG;
    return $self->{ClientAliveCountMax};
}

sub get_PermitEmptyPasswords {
    my ($self) = @ARG;
    return $self->{PermitEmptyPasswords};
}

sub get_PermitUserEnvironment {
    my ($self) = @ARG;
    return $self->{PermitUserEnvironment};
}

sub get_HostbasedAuthentication {
    my ($self) = @ARG;
    return $self->{HostbasedAuthentication};
}

1;

__END__
