#! /usr/bin/perl

use Fcntl;
use IO::Socket::UNIX;

my $usage = "[$0] Usage: $0 SOCKETPATH [--connect|--listen] CMD...";

my $mode = shift or die($usage);
my $sopath = shift or die($usage);


my $listen;
if ($mode eq "--listen") {
  $listen = 1;
} elsif ($mode eq "--connect") {
  $listen = 0;
} else {
  die($usage);
}

my $socket;
if ($listen == 1) {
  $socket = IO::Socket::UNIX->new(
      Type => SOCK_STREAM(),
      Local => $sopath,
      Listen => 1,
  ) or die "[$0] Error listening on socket socket: $!";
} else {
  $socket = IO::Socket::UNIX->new(
      Type => SOCK_STREAM(),
      Peer => $sopath,
  ) or die "[$0] Error listening on socket socket: $!";
}

my $fd_flags = $socket->fcntl(F_GETFD, 0) or die "[$0] fcntl F_GETFD: $!";
$socket->fcntl(F_SETFD, $fd_flags & ~FD_CLOEXEC) or die "[$0] fcntl F_SETFD: $!";

exec(@ARGV, $socket->fileno);  # pass it on the command line
