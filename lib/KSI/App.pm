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
            'SELECT t.access_token, t.user, t.expire, u.role FROM oauth2_tokens t JOIN users u ON u.id = t.user WHERE t.access_token = ?',
            undef, $1
        ) or return;
        my $now = strftime('%Y-%m-%d %H:%M:%S', gmtime);
        return if !defined $token->{expire} || $token->{expire} lt $now;
        $c->stash(user => $token);
    });
    $self->hook(before_dispatch => sub ($c) {
        return if $c->req->method eq 'OPTIONS';
        my $year = $c->req->headers->header('Year');
        if (!defined $year) {
            ($year) = $c->db->selectrow_array('SELECT id FROM years ORDER BY id DESC LIMIT 1');
        }
        $c->stash(year => $year);
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

    $r->any([qw(HEAD GET)], '/years')->to(cb => sub ($c) {
        my $years = _years($c);
        return $c->rendered(200) if $c->req->method eq 'HEAD';
        return $c->render(json => {years => $years});
    });
    $r->get('/years/:id')->to(cb => sub ($c) {
        my $id = $c->param('id');
        return $c->rendered(404) unless $id =~ /\A\d+\z/;
        my $years = _years($c);
        my ($year) = grep { $_->{id} == $id } @$years;
        return $c->rendered(404) unless $year;
        return $c->render(json => {year => $year});
    });
    $r->put('/years/:id')->to(cb => sub ($c) {
        return $c->rendered(400) unless _admin($c);
        my $id = $c->param('id');
        return $c->rendered(404) unless $id =~ /\A\d+\z/;
        my $body = $c->req->json;
        my $data = ref($body) eq 'HASH' ? $body->{year} : undef;
        return $c->rendered(400) unless ref($data) eq 'HASH'
            && defined $data->{index} && defined $data->{year}
            && exists $data->{sealed} && defined $data->{point_pad}
            && ref($data->{active_orgs}) eq 'ARRAY';
        my $dbh = $c->db;
        return $c->rendered(404) unless $dbh->selectrow_array('SELECT 1 FROM years WHERE id = ?', undef, $id);
        eval {
            $dbh->begin_work;
            $dbh->do('DELETE FROM active_orgs WHERE year = ?', undef, $id);
            $dbh->do('UPDATE years SET id = ?, year = ?, sealed = ?, point_pad = ? WHERE id = ?',
                undef, @$data{qw(index year sealed point_pad)}, $id);
            for my $org (@{$data->{active_orgs}}) {
                $dbh->do('INSERT INTO active_orgs (org, year) VALUES (?, ?)', undef, $org, $data->{index});
            }
            $dbh->commit;
            1;
        } or do {
            my $error = $@ || 'Year update failed';
            eval { $dbh->rollback };
            die $error;
        };
        my ($year) = grep { $_->{id} == $data->{index} } @{_years($c)};
        return $c->render(json => {year => $year});
    });
    $r->post('/years')->to(cb => sub ($c) {
        return $c->rendered(400) unless _admin($c);
        my $body = $c->req->json;
        return $c->rendered(400) unless ref($body) eq 'HASH';
        my $data = $body->{year};
        return $c->rendered(400) unless ref($data) eq 'HASH';
        my $dbh = $c->db;
        eval {
            $dbh->begin_work;
            $dbh->do('INSERT INTO years (id, year, sealed, point_pad) VALUES (?, ?, ?, ?)', undef,
                @$data{qw(index year sealed point_pad)});
            for my $org (@{$data->{active_orgs} // []}) {
                $dbh->do('INSERT INTO active_orgs (org, year) VALUES (?, ?)', undef, $org, $data->{index});
            }
            $dbh->commit;
            1;
        } or do {
            my $error = $@ || 'Year creation failed';
            eval { $dbh->rollback };
            die $error;
        };
        my ($year) = grep { $_->{id} == $data->{index} } @{_years($c)};
        return $c->render(json => {year => $year});
    });
    $r->delete('/years/:id')->to(cb => sub ($c) {
        return $c->rendered(400) unless _admin($c);
        my $id = $c->param('id');
        return $c->rendered(404) unless $id =~ /\A\d+\z/;
        my $dbh = $c->db;
        return $c->rendered(404) unless $dbh->selectrow_array('SELECT 1 FROM years WHERE id = ?', undef, $id);
        return $c->rendered(403) if $dbh->selectrow_array('SELECT 1 FROM waves WHERE year = ? LIMIT 1', undef, $id);
        $dbh->do('DELETE FROM years WHERE id = ?', undef, $id);
        return $c->render(json => {});
    });
    $r->get('/waves')->to(cb => sub ($c) {
        my $waves = _waves($c, $c->stash('year'));
        my $user = $c->stash('user') // {};
        $waves = [grep { $_->{public} || ($user->{role} // '') =~ /\A(?:admin|org|tester)\z/ } @$waves];
        return $c->render(json => {waves => $waves});
    });
    $r->get('/waves/:id')->to(cb => sub ($c) {
        my $id = $c->param('id');
        return $c->rendered(404) unless $id =~ /\A\d+\z/;
        my ($wave) = @{_waves($c, undef, $id)};
        return $c->rendered(404) unless $wave;
        return $c->render(json => {wave => $wave});
    });
    $r->post('/waves')->to(cb => sub ($c) {
        my $user = $c->stash('user') // {};
        return $c->rendered(400) unless ($user->{role} // '') eq 'admin';
        my $body = $c->req->json;
        my $data = ref($body) eq 'HASH' ? $body->{wave} : undef;
        return $c->rendered(400) unless ref($data) eq 'HASH' && defined $data->{time_published};
        my $dbh = $c->db;
        $dbh->do('INSERT INTO waves (year, `index`, caption, garant, time_published) VALUES (?, ?, ?, ?, ?)',
            undef, $c->stash('year'), @$data{qw(index caption garant time_published)});
        my $id = $dbh->last_insert_id(undef, undef, 'waves', 'id');
        my ($wave) = @{_waves($c, undef, $id)};
        return $c->render(json => {wave => $wave});
    });
    $r->put('/waves/:id')->to(cb => sub ($c) {
        my $user = $c->stash('user') // {};
        return $c->rendered(400) unless ($user->{role} // '') =~ /\A(?:admin|org)\z/;
        my $id = $c->param('id');
        return $c->rendered(404) unless $id =~ /\A\d+\z/;
        my ($wave) = @{_waves($c, undef, $id)};
        return $c->rendered(404) unless $wave;
        return $c->rendered(400) if ($user->{role} // '') ne 'admin' && $user->{user} != $wave->{garant};
        my $body = $c->req->json;
        my $data = ref($body) eq 'HASH' ? $body->{wave} : undef;
        return $c->rendered(400) unless ref($data) eq 'HASH' && exists $data->{index}
            && exists $data->{caption} && exists $data->{garant};
        $c->db->do('UPDATE waves SET `index` = ?, caption = ?, garant = ?, time_published = ? WHERE id = ?',
            undef, @$data{qw(index caption garant)}, $data->{time_published} || $wave->{time_published}, $id);
        my ($updated) = @{_waves($c, undef, $id)};
        return $c->render(json => {wave => $updated});
    });
    $r->delete('/waves/:id')->to(cb => sub ($c) {
        my $user = $c->stash('user') // {};
        return $c->rendered(400) unless ($user->{role} // '') eq 'admin';
        my $id = $c->param('id');
        return $c->rendered(404) unless $id =~ /\A\d+\z/;
        return $c->rendered(404) unless $c->db->selectrow_array('SELECT 1 FROM waves WHERE id = ?', undef, $id);
        return $c->rendered(403) if $c->db->selectrow_array('SELECT 1 FROM tasks WHERE wave = ? LIMIT 1', undef, $id);
        $c->db->do('DELETE FROM waves WHERE id = ?', undef, $id);
        return $c->render(json => {});
    });
    $r->get('/achievements')->to(cb => sub ($c) {
        my $rows = $c->db->selectall_arrayref(
            'SELECT id, title, picture, description, year FROM achievements WHERE year IS NULL OR year = ? ORDER BY id',
            {Slice => {}}, $c->stash('year') // 0);
        return $c->render(json => {achievements => [map {_achievement_json($_)} @$rows]});
    });
    $r->get('/achievements/special/successful')->to(cb => sub ($c) {
        my ($id) = $c->db->selectrow_array(
            q{SELECT value FROM config WHERE key = 'successful_participant_trophy_id'}
        );
        return $c->rendered(404) unless defined $id;
        return _get_achievement($c, $id);
    });
    $r->get('/achievements/:id')->to(cb => sub ($c) {
        return _get_achievement($c, $c->param('id'));
    });
    $r->post('/achievements')->to(cb => sub ($c) {
        return $c->rendered(400) unless _org($c);
        my $body = $c->req->json;
        my $data = ref($body) eq 'HASH' ? $body->{achievement} : undef;
        return $c->rendered(400) unless ref($data) eq 'HASH'
            && defined $data->{title} && defined $data->{picture} && exists $data->{persistent};
        my $year = $data->{persistent} ? undef : $c->stash('year');
        $c->db->do('INSERT INTO achievements (title, picture, description, year) VALUES (?, ?, ?, ?)',
            undef, @$data{qw(title picture description)}, $year);
        my $id = $c->db->last_insert_id(undef, undef, 'achievements', 'id');
        my $row = $c->db->selectrow_hashref('SELECT id, title, picture, description, year FROM achievements WHERE id = ?', undef, $id);
        return $c->render(json => {achievement => _achievement_json($row)});
    });
    $r->put('/achievements/:id')->to(cb => sub ($c) {
        return $c->rendered(400) unless _org($c);
        my $body = $c->req->json;
        my $data = ref($body) eq 'HASH' ? $body->{achievement} : undef;
        return $c->rendered(400) unless ref($data) eq 'HASH'
            && defined $data->{title} && defined $data->{picture} && exists $data->{persistent};
        my $id = $c->param('id');
        return $c->rendered(404) unless $id =~ /\A\d+\z/;
        return $c->rendered(404) unless $c->db->selectrow_array('SELECT 1 FROM achievements WHERE id = ?', undef, $id);
        my $year = $data->{persistent} ? undef : $c->stash('year');
        $c->db->do('UPDATE achievements SET title = ?, picture = ?, description = ?, year = ? WHERE id = ?',
            undef, @$data{qw(title picture description)}, $year, $id);
        return _get_achievement($c, $id);
    });
    $r->delete('/achievements/:id')->to(cb => sub ($c) {
        return $c->rendered(400) unless _admin($c);
        my $id = $c->param('id');
        return $c->rendered(404) unless $id =~ /\A\d+\z/;
        return $c->rendered(404) unless $c->db->selectrow_array('SELECT 1 FROM achievements WHERE id = ?', undef, $id);
        $c->db->do('DELETE FROM achievements WHERE id = ?', undef, $id);
        return $c->render(json => {});
    });
}

sub _admin ($c) {
    return (($c->stash('user') // {})->{role} // '') eq 'admin';
}

sub _org ($c) {
    return (($c->stash('user') // {})->{role} // '') =~ /\A(?:admin|org)\z/;
}

sub _get_achievement ($c, $id) {
    return $c->rendered(404) unless defined $id && $id =~ /\A\d+\z/;
    my $row = $c->db->selectrow_hashref(
        'SELECT id, title, picture, description, year FROM achievements WHERE id = ?', undef, $id
    );
    return $c->rendered(404) unless $row;
    return $c->render(json => {achievement => _achievement_json($row)});
}

sub _achievement_json ($row) {
    return {id => 0 + $row->{id}, title => $row->{title}, active => Mojo::JSON->true,
        picture => $row->{picture}, description => $row->{description},
        persistent => defined $row->{year} ? Mojo::JSON->false : Mojo::JSON->true,
        year => defined $row->{year} ? 0 + $row->{year} : undef};
}

sub _years ($c) {
    my $rows = $c->db->selectall_arrayref(q{
        SELECT y.id, y.year, y.sealed, y.point_pad,
               COALESCE(SUM(wp.points), 0) AS sum_points,
               COALESCE(SUM(wp.tasks_cnt), 0) AS tasks_cnt
        FROM years y
        LEFT JOIN waves w ON w.year = y.id
        LEFT JOIN (
            SELECT w.id, SUM(pt.points) AS points, COUNT(t.id) AS tasks_cnt
            FROM waves w
            LEFT JOIN tasks t ON t.wave = w.id
            LEFT JOIN (
                SELECT task, SUM(max_points) AS points
                FROM modules WHERE bonus = 0 GROUP BY task
            ) pt ON pt.task = t.id
            GROUP BY w.id
        ) wp ON wp.id = w.id
        GROUP BY y.id
        ORDER BY y.id
    }, {Slice => {}});
    return [map {
        +{id => 0 + $_->{id}, index => 0 + $_->{id}, year => $_->{year},
          sum_points => 0 + $_->{sum_points}, tasks_cnt => 0 + $_->{tasks_cnt},
          sealed => $_->{sealed} ? 1 : 0, point_pad => 0 + $_->{point_pad}}
    } @$rows];
}

sub _waves ($c, $year, $id = undef) {
    return [] unless defined $year || defined $id;
    my $sql = q{
        SELECT w.id, w.year, w.`index` AS wave_index, w.caption, w.garant,
               w.time_published,
               COALESCE(SUM(pt.points), 0) AS sum_points,
               COUNT(t.id) AS tasks_cnt
        FROM waves w
        LEFT JOIN tasks t ON t.wave = w.id
        LEFT JOIN (
            SELECT task, SUM(max_points) AS points
            FROM modules WHERE bonus = 0 GROUP BY task
        ) pt ON pt.task = t.id
    };
    $sql .= defined $id ? ' WHERE w.id = ?' : ' WHERE w.year = ?';
    $sql .= ' GROUP BY w.id';
    my $rows = $c->db->selectall_arrayref($sql, {Slice => {}}, defined $id ? $id : $year);
    my $now = strftime('%Y-%m-%d %H:%M:%S', localtime);
    return [map {
        my $public = ($_->{time_published} // '') lt $now ? 1 : 0;
        +{id => 0 + $_->{id}, year => 0 + $_->{year}, index => 0 + $_->{wave_index},
          caption => $_->{caption}, garant => 0 + $_->{garant},
          time_published => $_->{time_published}, public => $public,
          sum_points => 0 + $_->{sum_points}, tasks_cnt => 0 + $_->{tasks_cnt}}
    } @$rows];
}

1;
