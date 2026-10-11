package KSI::App;

use v5.36;
use strict;
use warnings;
use parent 'Mojolicious';
use KSI::DB;
use KSI::Auth qw(check_password new_token utc_after);
use POSIX qw(strftime);

sub startup ($self) {
    $self->secrets([$ENV{MOJO_SECRET} // die 'Set MOJO_SECRET']);
    $self->helper(db => sub ($c) {
        state $dbh = KSI::DB->connect;
        return $dbh;
    });

    $self->hook(before_dispatch => sub ($c) {
        $c->stash(user => undef);
        return if $c->req->method eq 'OPTIONS';
        my $auth = $c->req->headers->authorization // '';
        return unless $auth =~ /^Bearer\s+(\S+)\z/i;
        my $token = $c->db->selectrow_hashref(
            'SELECT access_token, user, expire FROM oauth2_tokens WHERE access_token = ?', undef, $1
        ) or return;
        my $now = strftime('%Y-%m-%d %H:%M:%S', gmtime);
        return if !defined $token->{expire} || $token->{expire} lt $now;
        $c->stash(user => $token->{user});
    });

    my $r = $self->routes;
    $r->post('/auth')->to(cb => sub ($c) {
        my $grant = $c->param('grant_type') // '';
        return $c->render(status => 400) unless $grant eq 'password' || $grant eq 'refresh_token';
        my $dbh = $c->db;
        $dbh->do('DELETE FROM oauth2_tokens WHERE expire < ?', undef, utc_after(-14 * 86400));
        my $user;
        my $in_tx = 0;
        if ($grant eq 'password') {
            my $username = $c->param('username') // '';
            my $password = $c->param('password') // '';
            $user = $dbh->selectrow_hashref(
                'SELECT id, password, enabled FROM users WHERE email = ?', undef, $username
            );
            return $c->render(json => {error => 'unauthorized_client'}, status => 400)
                unless $user && $password ne '';
            return $c->render(json => {error => 'account_disabled'}, status => 400)
                unless $user->{enabled};
            return $c->render(json => {error => 'unauthorized_client'}, status => 400)
                unless check_password($password, $user->{password});
        }
        else {
            my $refresh = $c->param('refresh_token') // '';
            $dbh->begin_work;
            $in_tx = 1;
            $user = $dbh->selectrow_hashref(
                'SELECT u.id FROM oauth2_tokens t JOIN users u ON u.id = t.user WHERE t.refresh_token = ?',
                undef, $refresh
            );
            unless ($user) {
                $dbh->rollback;
                return $c->render(json => {error => 'unauthorized_client'}, status => 400);
            }
            my $deleted = $dbh->do('DELETE FROM oauth2_tokens WHERE refresh_token = ?', undef, $refresh);
            unless ($deleted && $deleted == 1) {
                $dbh->rollback;
                return $c->render(json => {error => 'unauthorized_client'}, status => 400);
            }
        }
        return $c->render(status => 401) unless $user->{enabled} // 1;

        my $access = new_token();
        my $refresh = new_token();
        my $expires = utc_after(3600);
        my $granted = strftime('%Y-%m-%d %H:%M:%S', gmtime);
        eval {
            $dbh->begin_work unless $in_tx;
            $dbh->do('INSERT INTO oauth2_tokens (access_token, user, expire, refresh_token, granted) VALUES (?, ?, ?, ?, ?)',
                undef, $access, $user->{id}, $expires, $refresh, $granted);
            $dbh->do('UPDATE users SET last_logged_in = ? WHERE id = ?', undef, $granted, $user->{id});
            $dbh->commit;
            1;
        } or do {
            my $error = $@ || 'Token issue failed';
            eval { $dbh->rollback };
            die $error;
        };
        return $c->render(json => {
            access_token => $access, token_type => 'Bearer', expires_in => 3600,
            refresh_token => $refresh,
        });
    });

    $r->get('/logout')->to(cb => sub ($c) {
        return $c->rendered(204) unless $c->stash('user');
        my ($token) = ($c->req->headers->authorization // '') =~ /^Bearer\s+(\S+)\z/i;
        $c->db->do('DELETE FROM oauth2_tokens WHERE access_token = ?', undef, $token // '');
        return $c->rendered(204);
    });
}

1;
