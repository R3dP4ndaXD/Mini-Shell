// SPDX-License-Identifier: BSD-3-Clause

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>

#include <fcntl.h>
#include <unistd.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "cmd.h"
#include "utils.h"

#define READ		0
#define WRITE		1

/**
 * Internal change-directory command.
 */
static bool shell_cd(word_t *dir)
{
	/* TODO: Execute cd. */
	if (dir == NULL)
		return 0;

	int rc;
	char path[1024];

	getcwd(path, 1024);
	char *dirrectory = get_word(dir);

	if (!strncmp(dirrectory, "/", 1)) {
		memcpy(path, dirrectory, strlen(dirrectory));
	} else if (!strncmp(dirrectory, "..", 2)) {
		char *pos = strrchr(path, '/');
		*pos = 0;
	} else {
		strcat(path, "/");
		strcat(path, dirrectory);
	}
	free(dirrectory);
	rc = chdir(path);
	return rc;
}

/**
 * Internal exit/quit command.
 */
static int shell_exit(void)
{
	/* TODO: Execute exit/quit. */
	return SHELL_EXIT; /* TODO: Replace with actual exit code. */
}

/**
 * Parse a simple command (internal, environment variable assignment,
 * external command).
 */
static int parse_simple(simple_command_t *s, int level, command_t *father)
{
	/* TODO: Sanity checks. */
	if (!s)
		return 1;

	int size, i;
	char **argv = get_argv(s, &size);
	char *in, *out, *err;
	int fd_in, fd_out, fd_err;

	in = get_word(s->in);
	out = get_word(s->out);
	err = get_word(s->err);

	pid_t ret_pid;
	pid_t pid;
	int status;
	int rc;
	/* TODO: If builtin command, execute the command. */
	if (!strcmp(argv[0], "exit") || !strcmp(argv[0], "quit")) {
		free(in);
		free(out);
		free(err);
		for (i = 0; i < size; i++)
			free(argv[i]);

		free(argv);

		return shell_exit();
	} else if (!strcmp(argv[0], "cd")) {
		if (in) {
			fd_in = open(in, O_RDONLY);
			DIE(fd_in < 0, "open");
			rc = close(fd_in);
			DIE(rc < 0, "close");
		}
		if (out) {
			if (s->io_flags == IO_OUT_APPEND || err)
				fd_out = open(out, O_WRONLY | O_CREAT | O_APPEND, 0644);
			else
				fd_out = open(out, O_WRONLY | O_CREAT | O_TRUNC, 0644);

			DIE(fd_out < 0, "open");
			rc = close(fd_out);
			DIE(rc < 0, "close");
		}
		if (err) {
			if (s->io_flags == IO_ERR_APPEND)
				fd_err = open(err, O_WRONLY | O_CREAT | O_APPEND, 0644);
			else
				fd_err = open(err, O_WRONLY | O_CREAT | O_TRUNC, 0644);

			DIE(fd_err < 0, "open");
			rc = close(fd_err);
			DIE(rc < 0, "close");
		}
		free(in);
		free(out);
		free(err);
		for (i = 0; i < size; i++)
			free(argv[i]);

		free(argv);

		return shell_cd(s->params);
	} else if (strchr(argv[0], '=')) {
	/* TODO: If variable assignment, execute the assignment and return
	 * the exit status.
	 */
		rc = putenv(argv[0]);
		DIE(rc < 0, "putenv");

		free(in);
		free(out);
		free(err);
		for (i = 0; i < size; i++)
			free(argv[i]);

		free(argv);
		return rc;
	}


	/* TODO: If external command:
	 *   1. Fork new process
	 *     2c. Perform redirections in child
	 *     3c. Load executable in child
	 *   2. Wait for child
	 *   3. Return exit status
	 */
	char path[1024];

	pid = fork();
	switch (pid) {
	case -1:
		/* `fork()` has encountered an error. */
		DIE(1, "fork");
		break;

	case 0:
		if (!strncmp(argv[0], ".", 1) || !strncmp(argv[0], "/", 1)) {
			memcpy(path, argv[0], strlen(argv[0]) + 1);
		} else {
			memcpy(path, "/bin/", 6);
			strcat(path, argv[0]);
		}
		if (in) {
			fd_in = open(in, O_RDONLY);
			DIE(fd_in < 0, "open");
			dup2(fd_in, 0);
			rc = close(fd_in);
			DIE(rc < 0, "close");
		}
		if (out) {
			if (s->io_flags == IO_OUT_APPEND || err)
				fd_out = open(out, O_WRONLY | O_CREAT | O_APPEND, 0644);
			else
				fd_out = open(out, O_WRONLY | O_CREAT | O_TRUNC, 0644);

			DIE(fd_out < 0, "open");
			dup2(fd_out, 1);
			rc = close(fd_out);
			DIE(rc < 0, "close");
		}
		if (err) {
			if (s->io_flags == IO_ERR_APPEND)
				fd_err = open(err, O_WRONLY | O_CREAT | O_APPEND, 0644);
			else
				fd_err = open(err, O_WRONLY | O_CREAT | O_TRUNC, 0644);

			DIE(fd_err < 0, "open");
			dup2(fd_err, 2);
			rc = close(fd_err);
			DIE(rc < 0, "close");
		}
		rc = execv(path, argv);
		if (rc < 0) {
			printf("Execution failed for '%s'\n", argv[0]);
			exit(1);
		}

	default:
		/* Parent process */
		do {
			ret_pid = waitpid(pid, &status, 0);
			DIE(ret_pid < 0, "waitpid parent");
			if (WIFEXITED(status)) {
				free(in);
				free(out);
				free(err);
				for (i = 0; i < size; i++)
					free(argv[i]);

				free(argv);
				return WEXITSTATUS(status);
			}
		} while (!WIFEXITED(status) && !WIFSIGNALED(status));
		break;
	}
	return 0; /* TODO: Replace with actual exit status. */
}

/**
 * Process two commands in parallel, by creating two children.
 */
static bool run_in_parallel(command_t *cmd1, command_t *cmd2, int level,
		command_t *father)
{
	/* TODO: Execute cmd1 and cmd2 simultaneously. */
	pid_t pid1, pid2, ret_pid1, ret_pid2;
	int status1, status2;

	pid1 = fork();
	switch (pid1) {
	case -1:
		DIE(1, "fork");
		break;
	case 0:
		exit(parse_command(cmd1, level, father));
		break;

	default:
		pid2 = fork();
		switch (pid2) {
		case -1:
			DIE(1, "fork");
			break;

		case 0:
			exit(parse_command(cmd2, level, father));
			break;

		default:
			//do{
				ret_pid1 = waitpid(pid1, &status1, 0);
				ret_pid2 = waitpid(pid2, &status2, 0);
				DIE(ret_pid1 < 0 || ret_pid2 < 0, "waitpid parent");
				if (WIFEXITED(status1) && WIFEXITED(status2))
					return WEXITSTATUS(status1) & WIFEXITED(status2);

			//} while (!WIFEXITED(status1) && !WIFSIGNALED(status1) && !WIFEXITED(status2) && !WIFSIGNALED(status2));
			break;
		}
		break;
	}
	return true; /* TODO: Replace with actual exit status. */
}

/**
 * Run commands by creating an anonymous pipe (cmd1 | cmd2).
 */
static bool run_on_pipe(command_t *cmd1, command_t *cmd2, int level,
		command_t *father)
{
	/* TODO: Redirect the output of cmd1 to the input of cmd2. */
	pid_t pid1, pid2, ret_pid1;
	int rc;
	int pipe_des[2];
	int status1;

	pid1 = fork();
	switch (pid1) {
	case -1:
		DIE(1, "fork");
		break;

	case 0:
		rc = pipe(pipe_des);
		DIE(rc < 0, "pipe");
		pid2 = fork();
		switch (pid2) {
		case -1:
			rc = close(pipe_des[0]);
			DIE(rc < 0, "close");
			rc = close(pipe_des[1]);
			DIE(rc < 0, "close");
			DIE(1, "fork");
			break;

		case 0:
			rc = close(pipe_des[0]);
			DIE(rc < 0, "close");
			dup2(pipe_des[1], 1);
			rc = close(pipe_des[1]);
			DIE(rc < 0, "close");
			exit(parse_command(cmd1, level, father));

		default:
			rc = close(pipe_des[1]);
			DIE(rc < 0, "close");
			dup2(pipe_des[0], 0);
			rc = close(pipe_des[0]);
			DIE(rc < 0, "close");
			exit(parse_command(cmd2, level, father));
		}
		break;

	default:
		do {
			ret_pid1 = waitpid(pid1, &status1, 0);
			DIE(ret_pid1 < 0, "waitpid parent");
			if (WIFEXITED(status1))
				return WEXITSTATUS(status1);
		} while (!WIFEXITED(status1) && !WIFSIGNALED(status1));
	}

	return true; /* TODO: Replace with actual exit status. */
}

/**
 * Parse and execute a command.
 */
int parse_command(command_t *c, int level, command_t *father)
{
	/* TODO: sanity checks */
	if (!c)
		return 1;

	if (c->op == OP_NONE) {
		/* TODO: Execute a simple command. */
		return parse_simple(c->scmd, level, c->up);; /* TODO: Replace with actual exit code of command. */
	}

	switch (c->op) {
	case OP_SEQUENTIAL:
		/* TODO: Execute the commands one after the other. */
		parse_command(c->cmd1, level + 1, c);
		parse_command(c->cmd2, level + 1, c);
		break;

	case OP_PARALLEL:
		/* TODO: Execute the commands simultaneously. */
		return run_in_parallel(c->cmd1, c->cmd2, level + 1, c);

	case OP_CONDITIONAL_NZERO:
		/* TODO: Execute the second command only if the first one
		 * returns non zero.
		 */
		if (parse_command(c->cmd1, level + 1, c) != 0)
			return parse_command(c->cmd2, level + 1, c);

		break;

	case OP_CONDITIONAL_ZERO:
		/* TODO: Execute the second command only if the first one
		 * returns zero.
		 */
		if (parse_command(c->cmd1, level + 1, c) == 0)
			return parse_command(c->cmd2, level + 1, c);
		else
			return 1;


	case OP_PIPE:
		/* TODO: Redirect the output of the first command to the
		 * input of the second.
		 */
		return run_on_pipe(c->cmd1, c->cmd2, level + 1, c);

	default:
		return SHELL_EXIT;
	}

	return 0; /* TODO: Replace with actual exit code of command. */
}
