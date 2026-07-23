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


struct traversal_stats {
	unsigned long nodes;
	unsigned long regular_files;
	unsigned long symlinks;
	unsigned long long bytes_read;
	int failed;
};

#define ORACLE_MAX_NODES 100000UL
#define ORACLE_MAX_DEPTH 256U
#define ORACLE_MAX_BYTES (1ULL << 30)

static void traverse_all(const char *path, struct traversal_stats *stats, unsigned int depth)
{
	DIR *dir;
	struct dirent *entry;
	char child[512];
	struct stat st;
	if (depth > ORACLE_MAX_DEPTH) {
		puts("EROFS_ORACLE phase=traverse status=resource_exhausted reason=depth_limit");
		stats->failed = 1;
		return;
	}

	dir = opendir(path);
	if (!dir) {
		printf("EROFS_ORACLE phase=readdir status=rejected path=%s errno=%d\n",
		       path, errno);
		stats->failed = 1;
		return;
	}

	while ((entry = readdir(dir)) != NULL) {
		int length;

		if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0)
			continue;

		length = snprintf(child, sizeof(child), "%s/%s", path, entry->d_name);
		if (length < 0 || (size_t)length >= sizeof(child)) {
			printf("EROFS_ORACLE phase=traverse status=resource_exhausted reason=path_limit\n");
			stats->failed = 1;
			continue;
		}

		if (lstat(child, &st) < 0) {
			printf("EROFS_ORACLE phase=inode status=rejected path=%s errno=%d\n",
			       child, errno);
			stats->failed = 1;
			continue;
		}
		stats->nodes++;
		if (stats->nodes > ORACLE_MAX_NODES) {
			puts("EROFS_ORACLE phase=traverse status=resource_exhausted reason=node_limit");
			stats->failed = 1;
			break;
		}

		if (S_ISDIR(st.st_mode)) {
			traverse_all(child, stats, depth + 1);
		} else if (S_ISREG(st.st_mode)) {
			char buf[4096];
			ssize_t n;
			int fd = open(child, O_RDONLY);

			if (fd < 0) {
				printf("EROFS_ORACLE phase=read_data status=rejected path=%s errno=%d\n",
				       child, errno);
				stats->failed = 1;
				continue;
			}
			stats->regular_files++;
			while ((n = read(fd, buf, sizeof(buf))) > 0) {
				stats->bytes_read += (unsigned long long)n;
				if (stats->bytes_read > ORACLE_MAX_BYTES) {
					puts("EROFS_ORACLE phase=read_data status=resource_exhausted reason=byte_limit");
					stats->failed = 1;
					break;
				}
			}
			if (n < 0) {
				printf("EROFS_ORACLE phase=read_data status=rejected path=%s errno=%d\n",
				       child, errno);
				stats->failed = 1;
			}
			close(fd);
		} else if (S_ISLNK(st.st_mode)) {
			char linkbuf[256];

			stats->symlinks++;
			if (readlink(child, linkbuf, sizeof(linkbuf)) < 0) {
				printf("EROFS_ORACLE phase=read_data status=rejected path=%s errno=%d\n",
				       child, errno);
				stats->failed = 1;
			}
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
	struct traversal_stats stats = { 0 };
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

	puts("EROFS_ORACLE phase=boot status=started");
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
		printf("EROFS_ORACLE phase=mount status=rejected errno=%d\n", errno);
		reboot(RB_POWER_OFF);
		return 0;
	}

	puts("EROFS_ORACLE phase=mount status=accepted");
	traverse_all("/mnt/erofs", &stats, 0);
	printf("EROFS_ORACLE phase=traverse status=%s nodes=%lu regular_files=%lu symlinks=%lu bytes_read=%llu\n",
	       stats.failed ? "rejected" : "accepted", stats.nodes,
	       stats.regular_files, stats.symlinks, stats.bytes_read);
	if (!stats.failed)
		puts("EROFS_ORACLE phase=complete status=accepted");
	reboot(RB_POWER_OFF);
	return stats.failed ? 1 : 0;
}
