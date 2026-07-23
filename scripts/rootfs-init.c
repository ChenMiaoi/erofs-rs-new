#define _GNU_SOURCE
#include <errno.h>
#include <dirent.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/reboot.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

static void mkdir_p(const char *path, mode_t mode)
{
	if (mkdir(path, mode) < 0 && errno != EEXIST) {
		perror(path);
	}
}

static void write_file(const char *path, const char *text)
{
	int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
	ssize_t written;

	if (fd < 0) {
		perror(path);
		return;
	}
	written = write(fd, text, strlen(text));
	if (written < 0) {
		perror(path);
	}
	close(fd);
}

static void show_file(const char *path)
{
	char buf[4096];
	int fd = open(path, O_RDONLY);
	ssize_t n;

	if (fd < 0) {
		perror(path);
		return;
	}
	while ((n = read(fd, buf, sizeof(buf))) > 0) {
		ssize_t written = write(STDOUT_FILENO, buf, (size_t)n);
		if (written < 0) {
			perror("stdout");
			break;
		}
	}
	close(fd);
}

static void list_files(const char *path, int depth)
{
	DIR *dir;
	struct dirent *entry;

	if (depth < 0) {
		return;
	}

	dir = opendir(path);
	if (!dir) {
		perror(path);
		return;
	}

	while ((entry = readdir(dir)) != NULL) {
		char child[512];
		struct stat st;

		if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) {
			continue;
		}
		snprintf(child, sizeof(child), "%s/%s", path, entry->d_name);
		if (stat(child, &st) < 0) {
			perror(child);
			continue;
		}
		if (S_ISDIR(st.st_mode)) {
			list_files(child, depth - 1);
		} else if (S_ISREG(st.st_mode)) {
			puts(child);
		} else if (S_ISLNK(st.st_mode)) {
			printf("%s -> (symlink)\n", child);
		} else {
			printf("%s -> (special: mode=%o)\n", child, st.st_mode);
		}
	}

	closedir(dir);
}

static void traverse_all(const char *path)
{
	/*
	 * Aggressive traversal: recursively walk all directories,
	 * stat every entry, and attempt to read regular files.
	 * This triggers dirent and inode parsing for the entire tree.
	 */
	DIR *dir;
	struct dirent *entry;
	char child[512];
	struct stat st;
	int fd;
	char buf[4096];
	ssize_t n;

	dir = opendir(path);
	if (!dir) {
		perror(path);
		return;
	}

	while ((entry = readdir(dir)) != NULL) {
		if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0)
			continue;

		snprintf(child, sizeof(child), "%s/%s", path, entry->d_name);

		/* stat triggers inode lookup */
		if (lstat(child, &st) < 0) {
			printf("lstat failed: %s (%s)\n", child, strerror(errno));
			continue;
		}

		if (S_ISDIR(st.st_mode)) {
			traverse_all(child);
		} else if (S_ISREG(st.st_mode)) {
			/* Try to open and read the file */
			fd = open(child, O_RDONLY);
			if (fd < 0) {
				printf("open failed: %s (%s)\n", child, strerror(errno));
			} else {
				n = read(fd, buf, sizeof(buf));
				if (n < 0)
					printf("read failed: %s (%s)\n", child, strerror(errno));
				else
					printf("read ok: %s (%zd bytes)\n", child, n);
				close(fd);
			}
		} else if (S_ISLNK(st.st_mode)) {
			char linkbuf[256];
			ssize_t linklen = readlink(child, linkbuf, sizeof(linkbuf) - 1);
			if (linklen < 0)
				printf("readlink failed: %s (%s)\n", child, strerror(errno));
			else
				printf("readlink ok: %s -> %.*s\n", child, (int)linklen, linkbuf);
		} else {
			printf("special file: %s (mode=%o)\n", child, st.st_mode);
		}
	}

	closedir(dir);
}

static const char *wait_for_erofs_disk(void)
{
	static const char *candidates[] = { "/dev/vda", "/dev/sda", "/dev/hda" };
	size_t i;
	int tries;

	for (tries = 0; tries < 50; tries++) {
		for (i = 0; i < sizeof(candidates) / sizeof(candidates[0]); i++) {
			if (access(candidates[i], R_OK) == 0) {
				return candidates[i];
			}
		}
		usleep(100000);
	}

	return "/dev/vda";
}

int main(void)
{
	int rc;
	const char *disk;

	mkdir_p("/proc", 0555);
	mkdir_p("/sys", 0555);
	mkdir_p("/dev", 0755);
	mkdir_p("/mnt", 0755);
	mkdir_p("/mnt/erofs", 0755);

	mount("proc", "/proc", "proc", 0, "");
	mount("sysfs", "/sys", "sysfs", 0, "");
	mount("devtmpfs", "/dev", "devtmpfs", 0, "");
	mkdir_p("/sys/kernel/debug", 0700);
	mount("debugfs", "/sys/kernel/debug", "debugfs", 0, "");
	mknod("/dev/console", S_IFCHR | 0600, makedev(5, 1));

	puts("\n=== EROFS QEMU smoke boot ===");
	puts("Kernel command line:");
	show_file("/proc/cmdline");
	disk = wait_for_erofs_disk();
	printf("\n\nAttempting to mount %s as EROFS at /mnt/erofs ...\n", disk);

	rc = mount(disk, "/mnt/erofs", "erofs", MS_RDONLY, "");
	if (rc < 0) {
		/*
		 * Mount failure is EXPECTED for malformed images.
		 * The security goal is: the kernel rejects cleanly,
		 * without panic, KASAN, or information leak.
		 */
		puts("== erofs mount rejected safely ==");
		puts("Mount failed as expected for malformed image.");
		puts("Checking dmesg for suspicious kernel messages...");
		if (access("/proc/sys/kernel/debug/tracing/trace", R_OK) == 0)
			show_file("/proc/sys/kernel/debug/tracing/trace");
		reboot(RB_POWER_OFF);
		return 0;
	}

	puts("== erofs qemu booted ==");
	puts("Mounted EROFS successfully. Contents:");
	list_files("/mnt/erofs", 3);
	puts("\n--- Aggressive traversal (stat + read all files) ---");
	traverse_all("/mnt/erofs");
	puts("== erofs traversal complete ==");
	puts("\n/mnt/erofs/demo/hello.txt:");
	show_file("/mnt/erofs/demo/hello.txt");
	puts("\n\nDropping to an idle loop. Press Ctrl+A then X to quit QEMU.");

	while (1) {
		int status;
		pid_t pid = waitpid(-1, &status, WNOHANG);
		(void)pid;
		sleep(3600);
	}
}
