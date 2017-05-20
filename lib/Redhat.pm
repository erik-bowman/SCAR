package Redhat;

# Standard pragmas
use utf8;
use strict;
use warnings FATAL => 'all';

# Module version
our $VERSION = 0.01;

use Scar::Loader
    require     => 1,
    search_path => ['Redhat::6'],
    sub_name    => 'get_redhat6_plugins';
use Scar::Loader
    require     => 1,
    search_path => ['Redhat::7'],
    sub_name    => 'get_redhat7_plugins';

use Scar qw( read_file );

sub _ingest_sshd_config {
    my ($self) = @_;
    my @keywords = qw(
        AcceptEnv AddressFamily AllowAgentForwarding
        AllowGroups AllowTcpForwarding AllowUsers
        AuthorizedKeysFile AuthorizedKeysFile Banner
        ChallengeResponseAuthentication ChrootDirectory Ciphers
        ClientAliveCountMax ClientAliveInterval Compression
        DenyGroups DenyUsers ForceCommand
        GatewayPorts GSSAPIAuthentication GSSAPIKeyExchange
        GSSAPICleanupCredentials GSSAPIStrictAcceptorCheck GSSAPIStoreCredentialsOnRekey
        HostbasedAuthentication HostbasedUsesNameFromPacketOnly HostKey
        IgnoreRhosts IgnoreUserKnownHosts KerberosAuthentication
        KerberosGetAFSToken KerberosOrLocalPasswd KerberosTicketCleanup
        KerberosUseKuserok KeyRegenerationInterval ListenAddress
        LoginGraceTime LogLevel MACs
        MaxAuthTries MaxSessions MaxStartups
        PasswordAuthentication PermitEmptyPasswords PermitOpen
        PermitRootLogin PermitTunnel PermitUserEnvironment
        PidFile Port PrintLastLog
        PrintMotd Protocol PubkeyAuthentication
        AuthorizedKeysCommand AuthorizedKeysCommandRunAs RequiredAuthentications1
        RequiredAuthentications2 RSAAuthentication ServerKeyBits
        ShowPatchLevel StrictModes Subsystem
        SyslogFacility TCPKeepAlive UseDNS
        UseLogin UsePAM UsePrivilegeSeparation
        X11DisplayOffset X11Forwarding X11UseLocalhost
        XAuthLocation
    );

    my @sshd_config_entries = read_file('/etc/ssh/sshd_config');

    foreach my $keyword (@keywords) {

        foreach my $sshd_config_entry (@sshd_config_entries) {

            if ($sshd_config_entry =~ /^($keyword)\W+(.*)$/imxsg) {
                push @{$self->{files}->{'/etc/ssh/sshd_config'}->{$1}}, $2;
            }

        }

    }

    return $self->{files}->{'/etc/ssh/sshd_config'};
}

1;

__END__
