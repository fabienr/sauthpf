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
#define REWRITE_PROGRAM_C

#include <string.h>
#include <sys/wait.h>
#include <stdio.h>
#include <errno.h>
#include <signal.h>
#include <stdlib.h>

#include <sys/types.h>
#include <unistd.h>


#include "rewrite_program.h"
#include "../modules/conf.h"
#include "../modules/log.h"

bool rewrite_program_write(const char *querry)
{
	if (!program_execute(true))
		return (false);

	if (write(stdin_fd[PIPE_WRITE], querry, strlen(querry)) < 0) {
		log(LOG_WARNING, "write error : %m");
		program_engine_quit();
		return (false);
	}
	log(LOG_DEBUG, "write '%s' to rewrite_program", querry);
	return (true);
}

char *rewrite_program_read(void)
{
	char read_str[MAX_BUF];
	size_t read_byte;

	if (!program_execute(false))
		return (NULL);

	if ((read_byte = read(stdout_fd[PIPE_READ], read_str, MAX_BUF)) < 0) {
		log(LOG_WARNING, "fgets error : %m");
		program_engine_quit();
		return (NULL);
	}
	read_str[read_byte] = '\0';
	log(LOG_DEBUG, "read '%s' from rewrite_program", read_str);
	return (strdup(read_str));
}

void program_engine_quit(void)
{
	if (pid != -1) {
		close(stdout_fd[PIPE_READ]);
		close(stdin_fd[PIPE_WRITE]);
		kill(pid, SIGTERM);
		/* XXX : rechercher une meilleur manière de le faire
		 * vérifier que le programme s'est bien terminé
		 */
		pid = -1;
	}
}

static bool program_execute(bool create)
{
	pid_t wait_pid;
	int status, errno;
	char read_str[MAX_BUF];
	size_t read_size;

	if (pid != -1) {
		wait_pid = waitpid(pid, &status, WNOHANG);
		if (wait_pid == 0)
			return (true);
		pid = -1;
		close(stdout_fd[PIPE_READ]);
		close(stdin_fd[PIPE_WRITE]);
	}

	if (!create) {
		log(LOG_INFO, "program_execute : "
		    "rewrite program is not running, create flags is false");
		return (false);
	}

	if (pipe(stdout_fd) < 0) {
		log(LOG_WARNING, "pipe error : %m");
		return (false);
	}
	if (pipe(stdin_fd) < 0) {
		log(LOG_WARNING, "pipe error : %m");

		close(stdout_fd[PIPE_READ]);
		close(stdout_fd[PIPE_WRITE]);

		return (false);
	}

	pid = fork();
	if (pid < 0) {
		log(LOG_WARNING, "fork error : %m");
		pid = -1;
		close(stdout_fd[PIPE_READ]);
		close(stdout_fd[PIPE_WRITE]);
		close(stdin_fd[PIPE_READ]);
		close(stdin_fd[PIPE_WRITE]);
		return (false);
	}

	if (pid == CHILD) {
		/* on se trouve dans le child */
		char * argv [4] = {"sh", "-c", conf_url_rewrite_program, '\0'};

		close(stdout_fd[PIPE_READ]);
		close(stdin_fd[PIPE_WRITE]);

		/* XXX : changer pour rediriger stderr dans les logs */
		dup2(stdout_fd[PIPE_WRITE], STDOUT_FILENO);
		/*dup2(stdout_fd[PIPE_WRITE], STDERR_FILENO);*/
		dup2(stdin_fd[PIPE_READ], STDIN_FILENO);

		if (write(STDOUT_FILENO, hello_string, strlen(hello_string) + 1)
		    < 0) {
			log(LOG_INFO, "write hello string failed : %m");
			exit(1);
		}

		/* si le lancement se déroule bien,
		 * le programme ne sors pas de execve
		 */
		execv("/bin/sh", argv);

		log(LOG_WARNING, "failed to exec '%s' : %s\n",
		    conf_url_rewrite_program, strerror(errno));

		exit (1);
	}

	/* on se trouve dans le parent */
	close(stdout_fd[PIPE_WRITE]);
	close(stdin_fd[PIPE_READ]);

	/* on vérifie que le process s'est bien lancé */
	wait_pid = waitpid(pid, &status, WNOHANG);
	if (wait_pid == 0) {
		size_t x;
		x = read(stdout_fd[PIPE_READ], hello_buf, HELLO_BUF_SZ - 1);

		if (x < 0) {
			log(LOG_INFO, "hello read test failed : %m");

			pid = -1;
			close(stdout_fd[PIPE_READ]);
			close(stdin_fd[PIPE_WRITE]);

			return (false);
		}
		else if (strcmp(hello_buf, hello_string)) {
			log(LOG_INFO, "hello read test failed : '%s' != '%s'",
			    hello_buf, hello_string);

			pid = -1;
			close(stdout_fd[PIPE_READ]);
			close(stdin_fd[PIPE_WRITE]);

			return (false);
		}

		return (true);
	}

	if (wait_pid < 0) {
		log(LOG_INFO, "waitpid error on pid %d : %m", pid);
	}
	else if (WCOREDUMP(status)) {
		log(LOG_INFO, "unexpected end of '%s' with core dump",
		    conf_url_rewrite_program);
	}
	else {
		int return_code = 0;

		/* le programme s'est terminé sur une erreur */
		if ((return_code = WEXITSTATUS(status)) != 0) {
			log(LOG_INFO, "unexpected end of '%s' "
			    "with return code %d\n", conf_url_rewrite_program,
			    return_code);
		}

		log(LOG_INFO, "program '%s' exited imediatly",
		    conf_url_rewrite_program);

		/* XXX : ce while est il pertinent ? */
		while ((read_size = read(stdout_fd[PIPE_READ], read_str,
		    MAX_BUF)) != 0) {
			if (read_size == -1) {
				log(LOG_INFO, "read error : %m");
				program_engine_quit();
				return (false);
			}
			read_str[read_size] = '\0';
			printf("%s", read_str);
		}
	}

	pid = -1;
	close(stdout_fd[PIPE_READ]);
	close(stdin_fd[PIPE_WRITE]);
	return (false);
}
