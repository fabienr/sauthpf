/*
 * Copyright (c) 2009 Fabien Romano <fromano@asystant.net>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */
#define PF_C

#include "../modules/compat.h"

#include <sys/types.h>
#include <sys/file.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/wait.h>

#include <net/if.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <err.h>
#include <errno.h>
#include <net/pfvar.h>
#include <login_cap.h>

#include <pwd.h>
#include <grp.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>

#include "pf.h"
#include "../modules/log.h"
#include "../modules/bool.h"

void pf_quit(void)
{
	if (dev != -1)
		close(dev);
}

int pf_init(void)
{
	static bool init = false;
	if (init)
		return (0);

	if (read_config()) {
		log(LOG_WARNING, "invalid config file %s", PATH_CONFFILE);
		return (1);
	}

	dev = open(PATH_DEVFILE, O_RDWR);
	if (dev == -1) {
		log(LOG_WARNING, "cannot open packet filter device : %m");
		return (1);
	}

	init = true;
	return (0);
}

bool pf_auth(const char *user, const char *ip, struct timeval start)
{
	FILE *pidfp;
	int pidfd, n;
	char pidfile[MAXPATHLEN]; /* we save pid in this file. */
	struct passwd *pw;

	if (pf_init() != 0)
		return (false);

	/* pf_init must be call before */
	if (dev == -1)
		return (false);

	n = snprintf(pidfile, sizeof(pidfile), "%s/%s", PATH_PIDFILE, ip);
	if (n < 0 || (u_int)n >= sizeof(pidfile)) {
		log(LOG_WARNING, "pidfile's path too long, snprintf error : %m");
		return (false);
	}

	/*
	 * If someone else is already using this ip, then this person
	 * wants to switch users - so kill the old process and exit
	 * as well.
	 *
	 * This kind of situation can happen if the user was log in with authpf
	 */
	do {
		int	save_errno, otherpid = -1;
		char	otherluser[MAXLOGNAME];
		int lockcnt = 0;

		if ((pidfd = open(pidfile, O_RDWR|O_CREAT, 0644)) == -1 ||
		    (pidfp = fdopen(pidfd, "r+")) == NULL) {
			if (pidfd != -1)
				close(pidfd);
			log(LOG_WARNING, "cannot open or create %s : %m",
			    pidfile);
			return (false);
		}

		if (flock(fileno(pidfp), LOCK_EX|LOCK_NB) == 0)
			break;
		save_errno = errno;

		/* Mark our pid, and username to our file. */
		rewind(pidfp);
		/* 31 == MAXLOGNAME - 1 */
		if (fscanf(pidfp, "%d\n%31s\n", &otherpid, otherluser) != 2)
			otherpid = -1;
		log(LOG_INFO, "tried to lock %s, in use by pid %d: %s",
		    pidfile, otherpid, strerror(save_errno));

		if (otherpid > 0) {
			log(LOG_INFO,
			    "killing prior auth (pid %d) of %s by user %s",
			    otherpid, ip, otherluser);
			if (kill((pid_t) otherpid, SIGTERM) == -1) {
				log(LOG_WARNING,
				    "could not kill process %d : %m", otherpid);
			}
		}

		/*
		 * We try to kill the previous process and acquire the lock
		 * for 10 seconds, trying once a second. if we can't after
		 * 10 attempts we log an error and give up.
		 */
		if (++lockcnt > 10) {
			log(LOG_WARNING, "cannot kill previous authpf "
			    "(pid %d)", otherpid);
			fclose(pidfp);
			return (false);
		}
		sleep(1);

		/* re-open, and try again. The previous authpf process
		 * we killed above should unlink the file and release
		 * it's lock, giving us a chance to get it now
		 */
		fclose(pidfp);
	} while (1);

	if (!check_luser(PATH_BAN_DIR, user) || !allowed_luser(pw)) {
		log(LOG_INFO, "user %s prohibited", user);
		fclose(pidfp);
		return (false);
	}

	if (remove_stale_rulesets()) {
		log(LOG_WARNING, "error removing stale rulesets");
		fclose(pidfp);
		return (false);
	}

	rewind(pidfp);
	fprintf(pidfp, "%ld\n%s\n", (long)getpid(), user);
	fflush(pidfp);
	(void) ftruncate(fileno(pidfp), ftello(pidfp));
	fclose(pidfp);

	if (change_filter(1, user, ip, start) == -1) {
		log(LOG_WARNING, "unable to modify filters");
		return (false);
	}
	if (change_table(1, ip) == -1) {
		log(LOG_WARNING, "unable to modify table");
		change_filter(0, user, ip, start);
		return (false);
	}

	return (true);
}

void pf_unauth(const char *user, const char *ip, struct timeval start)
{
	if (pf_init() != 0)
		return;

	change_filter(0, user, ip, start);
	change_table(0, ip);
	authpf_kill_states(ip);
}

/* reads config file in PATH_CONFFILE to set optional behaviours up */
static int read_config(void)
{
	char	buf[1024];
	int	i = 0;
	FILE	*config;

	config = fopen(PATH_CONFFILE, "r");
	if (config == NULL) {
		log(LOG_INFO, "cannot open %s : %m", PATH_CONFFILE);
		return (1);
	}

	do {
		char	**ap;
		char	 *pair[4], *cp, *tp;
		int	  len;

		if (fgets(buf, sizeof(buf), config) == NULL) {
			fclose(config);
			return (0);
		}
		i++;
		len = strlen(buf);
		if (len == 0)
			continue;
		if (buf[len - 1] != '\n' && !feof(config)) {
			log(LOG_INFO, "line %d too long in %s", i,
			    PATH_CONFFILE);
			return (1);
		}
		buf[len - 1] = '\0';

		for (cp = buf; *cp == ' ' || *cp == '\t'; cp++)
			; /* nothing */

		if (!*cp || *cp == '#' || *cp == '\n')
			continue;

		for (ap = pair; ap < &pair[3] &&
		    (*ap = strsep(&cp, "=")) != NULL; ) {
			if (**ap != '\0')
				ap++;
		}
		if (ap != &pair[2])
			goto parse_error;

		tp = pair[1] + strlen(pair[1]);
		while ((*tp == ' ' || *tp == '\t') && tp >= pair[1])
			*tp-- = '\0';

		if (strcasecmp(pair[0], "anchor") == 0) {
			if (!pair[1][0] || strlcpy(anchorname, pair[1],
			    sizeof(anchorname)) >= sizeof(anchorname))
				goto parse_error;
		}
		if (strcasecmp(pair[0], "table") == 0) {
			if (!pair[1][0] || strlcpy(tablename, pair[1],
			    sizeof(tablename)) >= sizeof(tablename))
				goto parse_error;
		}
	} while (!feof(config) && !ferror(config));
	fclose(config);
	return (0);

parse_error:
	fclose(config);
	log(LOG_WARNING, "parse error, line %d of %s", i, PATH_CONFFILE);
	return (1);
}

/*
 * allowed_luser checks to see if user "luser" is allowed to
 * use this gateway by virtue of being listed in an allowed
 * users file, namely /etc/authpf/authpf.allow .
 * Users may be listed by <username>, %<group>, or @<login_class>.
 *
 * If /etc/authpf/authpf.allow does not exist, then we assume that
 * all users who are allowed in by sshd(8) are permitted to
 * use this gateway. If /etc/authpf/authpf.allow does exist, then a
 * user must be listed if the connection is to continue, else
 * the session terminates in the same manner as being banned.
 */
static int allowed_luser(struct passwd *pw)
{
	char	*buf, *lbuf;
	int	 matched;
	size_t	 len;
	FILE	*f;

	int gl_init = 0, ngroups = NGROUPS + 1;
	gid_t groups[NGROUPS + 1];

	if ((f = fopen(PATH_ALLOWFILE, "r")) == NULL) {
		if (errno == ENOENT) {
			/*
			 * allowfile doesn't exist, thus this gateway
			 * isn't restricted to certain users...
			 */
			return (1);
		}

		/*
		 * luser may in fact be allowed, but we can't open
		 * the file even though it's there. probably a config
		 * problem.
		 */
		log(LOG_WARNING, "cannot open allowed users file %s : %m",
		    PATH_ALLOWFILE);
		return (0);
	}

	/*
	 * /etc/authpf/authpf.allow exists, thus we do a linear
	 * search to see if they are allowed.
	 * also, if username "*" exists, then this is a
	 * "public" gateway, such as it is, so let
	 * everyone use it.
	 */
	lbuf = NULL;
	matched = 0;

	while ((buf = fgetln(f, &len))) {

		if (buf[len - 1] == '\n') {
			buf[len - 1] = '\0';
		}
		else {
			if ((lbuf = (char *)malloc(len + 1)) == NULL)
				err(1, NULL);
			memcpy(lbuf, buf, len);
			lbuf[len] = '\0';
			buf = lbuf;
		}

		if (buf[0] == '@') {
			/* check login class */
			if (strcmp(pw->pw_class, buf + 1) == 0)
				matched++;
		}
		else if (buf[0] == '%') {
			/* check group membership */
			int cnt;
			struct group *group;

			if ((group = getgrnam(buf + 1)) == NULL) {
				log(LOG_WARNING, "invalid group '%s' in %s : "
				    "%m", buf + 1, PATH_ALLOWFILE);
				return (0);
			}

			if (!gl_init) {
				(void) getgrouplist(pw->pw_name, pw->pw_gid,
				    groups, &ngroups);
				gl_init++;
			}

			for (cnt = 0; cnt < ngroups; cnt++) {
				if (group->gr_gid == groups[cnt]) {
					matched++;
					break;
				}
			}
		}
		else {
			/* check username and wildcard */
			matched = strcmp(pw->pw_name, buf) == 0 ||
			    strcmp("*", buf) == 0;
		}

		if (lbuf != NULL) {
			free(lbuf);
			lbuf = NULL;
		}

		if (matched)
			return (1); /* matched an allowed user/group */
	}
	log(LOG_INFO, "denied access to %s: not listed in %s",
	    pw->pw_name, PATH_ALLOWFILE);

	/* reuse buf */
	/* XXX : change this
	 * permit sauthpf to return an error message
	 */
	/*
	buf = "\n\nSorry, you are not allowed to use this facility!\n";
	fputs(buf, stdout);
	*/

	return (0);
}

/*
 * check_luser checks to see if user "luser" has been banned
 * from using us by virtue of having an file of the same name
 * in the "luserdir" directory.
 *
 * If the user has been banned, we copy the contents of the file
 * to the user's screen. (useful for telling the user what to
 * do to get un-banned, or just to tell them they aren't
 * going to be un-banned.)
 */
static int check_luser(const char *luserdir, const char *luser)
{
	FILE	*f;
	int	 n;
	char	 tmp[MAXPATHLEN];

	n = snprintf(tmp, sizeof(tmp), "%s/%s", luserdir, luser);
	if (n < 0 || (u_int)n >= sizeof(tmp)) {
		log(LOG_WARNING, "banned directory's path too long : %m");
		return (0);
	}
	if ((f = fopen(tmp, "r")) == NULL) {
		if (errno == ENOENT) {
			/*
			 * file or dir doesn't exist, so therefore
			 * this luser isn't banned..  all is well
			 */
			return (1);
		}
		else {
			/*
			 * luser may in fact be banned, but we can't open the
			 * file even though it's there. probably a config
			 * problem.
			 */
			log(LOG_WARNING, "open banned file %s error : %m", tmp);
			return (0);
		}
	}
	else {
		/*
		 * luser is banned - spit the file at them to
		 * tell what they can do and where they can go.
		 */
		log(LOG_INFO, "denied access to %s: %s exists",
		    luser, tmp);

		/* reuse tmp */
		/* XXX : change this
		 * permit sauthpf to return an error message
		 */
		/*
		strlcpy(tmp, "\n\n-**- Sorry, you have been banned! -**-\n\n",
		    sizeof(tmp));
		while (fputs(tmp, stdout) != EOF && !feof(f))
		{
			if (fgets(tmp, sizeof(tmp), f) == NULL)
			{
				fflush(stdout);
				fclose(f);
				return (0);
			}
		}
		*/
		fclose(f);
	}
	return (0);
}

/*
 * Search for rulesets left by other authpf processes (either because they
 * died ungracefully or were terminated) and remove them.
 */
static int remove_stale_rulesets(void)
{
	struct pfioc_ruleset	 prs;
	u_int32_t		 nr;

	memset(&prs, 0, sizeof(prs));
	strlcpy(prs.path, anchorname, sizeof(prs.path));
	if (ioctl(dev, DIOCGETRULESETS, &prs)) {
		if (errno == EINVAL)
			return (0);
		else
			return (1);
	}

	nr = prs.nr;
	while (nr) {
		char	*s, *t;
		pid_t	 pid;

		prs.nr = nr - 1;
		if (ioctl(dev, DIOCGETRULESET, &prs))
			return (1);
		errno = 0;
		if ((t = strchr(prs.name, '(')) == NULL)
			t = prs.name;
		else
			t++;
		pid = strtoul(t, &s, 10);
		if (!prs.name[0] || errno || (*s &&
		    (t == prs.name || *s != ')')))
			return (1);
		if (kill(pid, 0) && errno != EPERM)
			if (recursive_ruleset_purge(anchorname, prs.name))
				return (1);
		nr--;
	}
	return (0);
}

static int recursive_ruleset_purge(char *an, char *rs)
{
	struct pfioc_trans_e     *t_e = NULL;
	struct pfioc_trans	 *t = NULL;
	struct pfioc_ruleset	 *prs = NULL;

	/* purge rules */
	errno = 0;
	if ((t = calloc(1, sizeof(struct pfioc_trans))) == NULL)
		goto no_mem;
	if ((t_e = calloc(2, sizeof(struct pfioc_trans_e))) == NULL)
		goto no_mem;
	t->size = 2;
	t->esize = sizeof(struct pfioc_trans_e);
	t->array = t_e;
	t_e[0].type = PF_TRANS_RULESET;
	snprintf(t_e[0].anchor, sizeof(t_e[0].anchor), "%s/%s", an, rs);
	t_e[1].type = PF_TRANS_TABLE;

	if ((ioctl(dev, DIOCXBEGIN, t) ||
	    ioctl(dev, DIOCXCOMMIT, t)) &&
	    errno != EINVAL)
		goto cleanup;

	/* purge any children */
	if ((prs = calloc(1, sizeof(struct pfioc_ruleset))) == NULL)
		goto no_mem;
	snprintf(prs->path, sizeof(prs->path), "%s/%s", an, rs);
	if (ioctl(dev, DIOCGETRULESETS, prs)) {
		if (errno != EINVAL)
			goto cleanup;
		errno = 0;
	} else {
		int nr = prs->nr;

		while (nr) {
			prs->nr = 0;
			if (ioctl(dev, DIOCGETRULESET, prs))
				goto cleanup;

			if (recursive_ruleset_purge(prs->path, prs->name))
				goto cleanup;
			nr--;
		}
	}

no_mem:
	if (errno == ENOMEM)
		syslog(LOG_ERR, "calloc failed");

cleanup:
	free(t);
	free(t_e);
	free(prs);
	return (errno);
}

/*
 * Add/remove filter entries for user "luser" from ip "ipsrc"
 */
static int change_filter(int add, const char *luser, const char *ipsrc,
    struct timeval start)
{
	char	*fdpath = NULL, *userstr = NULL, *ipstr = NULL;
	char	*rsn = NULL, *fn = NULL;
	pid_t	pid;
	gid_t	gid;
	int	s;
	struct	timeval end;

	if (add) {
		struct stat sb;
		char	*pargv[13] = {
			"pfctl", "-p", "/dev/pf", "-q", "-a", "anchor/ruleset",
			"-D", "user_id=X", "-D", "user_ip=X", "-f", "file", NULL
		};

		if (luser == NULL || !luser[0] || ipsrc == NULL || !ipsrc[0]) {
			log(LOG_INFO, "invalid luser/ipsrc");
			goto error;
		}

		if ((s = snprintf(rulesetname, sizeof(rulesetname), "%s(%ld)",
		    luser, (long)getpid())) < 0 ||
		    (u_int)s >= sizeof(rulesetname)) {
			log(LOG_INFO, "%s(%ld) too large, ruleset name will "
			    "be %ld", luser, (long)getpid(), (long)getpid());
			if ((s = snprintf(rulesetname, sizeof(rulesetname),
			    "%ld", (long)getpid())) < 0 ||
			    (u_int)s >= sizeof(rulesetname)) {
				log(LOG_ERR, "pid too large for ruleset name");
				goto error;
			}
		}

		if (asprintf(&rsn, "%s/%s", anchorname, rulesetname) == -1)
			goto no_mem;
		if (asprintf(&fdpath, "/dev/fd/%d", dev) == -1)
			goto no_mem;
		if (asprintf(&ipstr, "user_ip=%s", ipsrc) == -1)
			goto no_mem;
		if (asprintf(&userstr, "user_id=%s", luser) == -1)
			goto no_mem;
		if (asprintf(&fn, "%s/%s/authpf.rules",
		    PATH_USER_DIR, luser) == -1)
			goto no_mem;
		if (stat(fn, &sb) == -1) {
			free(fn);
			if ((fn = strdup(PATH_PFRULES)) == NULL)
				goto no_mem;
		}
		pargv[2] = fdpath;
		pargv[5] = rsn;
		pargv[7] = userstr;
		if (user_ip) {
			pargv[9] = ipstr;
			pargv[11] = fn;
		}
		else {
			pargv[8] = "-f";
			pargv[9] = fn;
			pargv[10] = NULL;
		}

		log(LOG_DEBUG, "exec %s (%s %s %s %s %s %s %s %s %s %s %s %s)",
		    PATH_PFCTL, pargv[0], pargv[1], pargv[2], pargv[3],
		    pargv[4], pargv[5], pargv[6], pargv[7], pargv[8],
		    pargv[9], pargv[10], pargv[11]);

		switch (pid = fork()) {
		case -1:
			log(LOG_WARNING, "fork error : %m");
			goto error;
		case 0:
			/* revoke group privs before exec */
			gid = getgid();
			if (setregid(gid, gid) == -1)
				log(LOG_WARNING, "setregid error : %m");
			execvp(PATH_PFCTL, pargv);
			log(LOG_WARNING, "exec of %s error : %m", PATH_PFCTL);
			goto error;
		}

		/* parent */
		waitpid(pid, &s, 0);
		if (s != 0) {
			log(LOG_WARNING, "pfctl exited abnormally");
			goto error;
		}

		log(LOG_INFO, "allowing %s, user %s in authpf", ipsrc, luser);
	}
	else {
		remove_stale_rulesets();

		gettimeofday(&end, NULL);
		log(LOG_INFO, "removed %s, user %s - duration %ld seconds : "
		    "(%ld - %ld)",
		    ipsrc, luser, end.tv_sec - start.tv_sec, end.tv_sec,
		    start.tv_sec);
	}
	return (0);
no_mem:
	log(LOG_WARNING, "malloc error : %m");
error:
	if (fdpath)
		free(fdpath);
	if (rsn)
		free(rsn);
	if (userstr)
		free(userstr);
	if (ipstr)
		free(ipstr);
	if (fn)
		free(fn);
	return (-1);
}

/*
 * Add/remove this IP from the "authpf_users" table.
 */
static int
change_table(int add, const char *ipsrc)
{
	struct pfioc_table	io;
	struct pfr_addr		addr;

	bzero(&io, sizeof(io));
	strlcpy(io.pfrio_table.pfrt_name, tablename,
	    sizeof(io.pfrio_table.pfrt_name));
	io.pfrio_buffer = &addr;
	io.pfrio_esize = sizeof(addr);
	io.pfrio_size = 1;

	bzero(&addr, sizeof(addr));
	if (ipsrc == NULL || !ipsrc[0])
		return (-1);
	if (inet_pton(AF_INET, ipsrc, &addr.pfra_ip4addr) == 1) {
		addr.pfra_af = AF_INET;
		addr.pfra_net = 32;
	}
	else if (inet_pton(AF_INET6, ipsrc, &addr.pfra_ip6addr) == 1) {
		addr.pfra_af = AF_INET6;
		addr.pfra_net = 128;
	}
	else {
		log(LOG_INFO, "invalid ipsrc");
		return (-1);
	}

	if (ioctl(dev, add ? DIOCRADDADDRS : DIOCRDELADDRS, &io) &&
	    errno != ESRCH) {
		log(LOG_WARNING, "cannot %s %s from table %s : %m",
		    add ? "add" : "remove", ipsrc, tablename);
		return (-1);
	}
	return (0);
}

/*
 * This is to kill off states that would otherwise be left behind stateful
 * rules. This means we don't need to allow in more traffic than we really
 * want to, since we don't have to worry about any luser sessions lasting
 * longer than their ssh session. This function is based on
 * pfctl_kill_states from pfctl.
 */
static void authpf_kill_states(const char *ipsrc)
{
	struct pfioc_state_kill psk;
	struct pf_addr target;

	memset(&psk, 0, sizeof(psk));
	memset(&target, 0, sizeof(target));

	if (inet_pton(AF_INET, ipsrc, &target.v4) == 1) {
		psk.psk_af = AF_INET;
	}
	else if (inet_pton(AF_INET6, ipsrc, &target.v6) == 1) {
		psk.psk_af = AF_INET6;
	}
	else {
		log(LOG_WARNING, "inet_pton(%s) error : %m", ipsrc);
		return;
	}

	/* Kill all states from ipsrc */
	memcpy(&psk.psk_src.addr.v.a.addr, &target,
	    sizeof(psk.psk_src.addr.v.a.addr));
	memset(&psk.psk_src.addr.v.a.mask, 0xff,
	    sizeof(psk.psk_src.addr.v.a.mask));
	if (ioctl(dev, DIOCKILLSTATES, &psk))
		log(LOG_WARNING, "DIOCKILLSTATES error : %m");

	/* Kill all states to ipsrc */
	memset(&psk.psk_src, 0, sizeof(psk.psk_src));
	memcpy(&psk.psk_dst.addr.v.a.addr, &target,
	    sizeof(psk.psk_dst.addr.v.a.addr));
	memset(&psk.psk_dst.addr.v.a.mask, 0xff,
	    sizeof(psk.psk_dst.addr.v.a.mask));
	if (ioctl(dev, DIOCKILLSTATES, &psk))
		log(LOG_WARNING, "DIOCKILLSTATES error : %m");
}
