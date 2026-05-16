/*
 * SPDX-License-Identifier: LGPL-2.1+
 */

#include "config.h"

#include <stddef.h>
#include <stdint.h>
#include <unistd.h>

#include "conf.h"
#include "confile.h"
#include "lxccontainer.h"
#include "lxctest.h"
#include "utils.h"

static const char * const subkeys[] = {
	NULL,
	"lxc.apparmor",
	"lxc.cgroup",
	"lxc.selinux",
	"lxc.mount",
	"lxc.rootfs",
	"lxc.uts",
	"lxc.hook",
	"lxc.cap",
	"lxc.console",
	"lxc.environment",
	"lxc.seccomp",
	"lxc.signal",
	"lxc.start",
	"lxc.monitor",
	"lxc.keyring",
	"lxc.net.0",
	"lxc.net.1",
};

static const char * const clear_keys[] = {
	"lxc.environment",
	"lxc.environment.runtime",
	"lxc.environment.hooks",
	"lxc.idmap",
	"lxc.cgroup",
	"lxc.cgroup2",
	"lxc.hook",
	"lxc.mount.entry",
	"lxc.prlimit",
	"lxc.sysctl",
	"lxc.proc",
	"lxc.cap.drop",
	"lxc.cap.keep",
	"lxc.apparmor.raw",
	"lxc.namespace.share",
	"lxc.net",
};

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
	int fd = -1;
	char tmpf[] = "/tmp/fuzz-lxc-api-XXXXXX";
	char savef[] = "/tmp/fuzz-lxc-api-save-XXXXXX";
	struct lxc_container *c = NULL;
	char buf[8192];
	size_t i;

	if (size > 102400)
		return 0;

	fd = lxc_make_tmpfile(tmpf, false);
	lxc_test_assert_abort(fd >= 0);
	lxc_write_nointr(fd, data, size);
	close(fd);

	c = lxc_container_new("FUZZ", "/tmp");
	lxc_test_assert_abort(c);

	if (!c->load_config(c, tmpf))
		goto out;

	for (i = 0; i < sizeof(subkeys) / sizeof(subkeys[0]); i++)
		c->get_keys(c, subkeys[i], buf, sizeof(buf));

	for (i = 1; i < sizeof(subkeys) / sizeof(subkeys[0]); i++)
		c->get_config_item(c, subkeys[i], buf, sizeof(buf));

	fd = lxc_make_tmpfile(savef, false);
	if (fd >= 0) {
		close(fd);
		c->save_config(c, savef);
		(void) unlink(savef);
	}

	for (i = 0; i < sizeof(clear_keys) / sizeof(clear_keys[0]); i++)
		c->clear_config_item(c, clear_keys[i]);

out:
	lxc_container_put(c);
	(void) unlink(tmpf);
	(void) rmdir("/tmp/FUZZ");
	return 0;
}
