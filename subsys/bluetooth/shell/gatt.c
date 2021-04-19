/** @file
 * @brief Bluetooth GATT shell functions
 *
 */

/*
 * Copyright (c) 2017 Intel Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <errno.h>
#include <zephyr/types.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <sys/byteorder.h>
#include <zephyr.h>

#include <bluetooth/bluetooth.h>
#include <bluetooth/conn.h>
#include <bluetooth/gatt.h>

#include <shell/shell.h>

#include "bt.h"

#define CHAR_SIZE_MAX           512

extern uint8_t selected_id;

#if defined(CONFIG_BT_GATT_CLIENT)
static void exchange_func(struct bt_conn *conn, uint8_t err,
			  struct bt_gatt_exchange_params *params)
{
	shell_print(ctx_shell, "Exchange %s", err == 0U ? "successful" :
		    "failed");

	(void)memset(params, 0, sizeof(*params));
}

static struct bt_gatt_exchange_params exchange_params;

static int cmd_exchange_mtu(const struct shell *shell,
			     size_t argc, char *argv[])
{
	int err;

	if (!default_conn) {
		shell_print(shell, "Not connected");
		return -ENOEXEC;
	}

	if (exchange_params.func) {
		shell_print(shell, "MTU Exchange ongoing");
		return -ENOEXEC;
	}

	exchange_params.func = exchange_func;

	err = bt_gatt_exchange_mtu(default_conn, &exchange_params);
	if (err) {
		shell_print(shell, "Exchange failed (err %d)", err);
	} else {
		shell_print(shell, "Exchange pending");
	}

	return err;
}

static struct bt_gatt_discover_params discover_params;
static struct bt_uuid_16 uuid = BT_UUID_INIT_16(0);

static void print_chrc_props(const struct shell *shell, uint8_t properties)
{
	shell_print(shell, "Properties: ");

	if (properties & BT_GATT_CHRC_BROADCAST) {
		shell_print(shell, "[bcast]");
	}

	if (properties & BT_GATT_CHRC_READ) {
		shell_print(shell, "[read]");
	}

	if (properties & BT_GATT_CHRC_WRITE) {
		shell_print(shell, "[write]");
	}

	if (properties & BT_GATT_CHRC_WRITE_WITHOUT_RESP) {
		shell_print(shell, "[write w/w rsp]");
	}

	if (properties & BT_GATT_CHRC_NOTIFY) {
		shell_print(shell, "[notify]");
	}

	if (properties & BT_GATT_CHRC_INDICATE) {
		shell_print(shell, "[indicate]");
	}

	if (properties & BT_GATT_CHRC_AUTH) {
		shell_print(shell, "[auth]");
	}

	if (properties & BT_GATT_CHRC_EXT_PROP) {
		shell_print(shell, "[ext prop]");
	}

	shell_print(shell, "");
}

static uint8_t discover_func(struct bt_conn *conn,
			     const struct bt_gatt_attr *attr,
			     struct bt_gatt_discover_params *params)
{
	struct bt_gatt_service_val *gatt_service;
	struct bt_gatt_chrc *gatt_chrc;
	struct bt_gatt_include *gatt_include;
	char str[BT_UUID_STR_LEN];

	if (!attr) {
		shell_print(ctx_shell, "Discover complete");
		(void)memset(params, 0, sizeof(*params));
		return BT_GATT_ITER_STOP;
	}

	switch (params->type) {
	case BT_GATT_DISCOVER_SECONDARY:
	case BT_GATT_DISCOVER_PRIMARY:
		gatt_service = attr->user_data;
		bt_uuid_to_str(gatt_service->uuid, str, sizeof(str));
		shell_print(ctx_shell, "Service %s found: start handle %x, "
			    "end_handle %x", str, attr->handle,
			    gatt_service->end_handle);
		break;
	case BT_GATT_DISCOVER_CHARACTERISTIC:
		gatt_chrc = attr->user_data;
		bt_uuid_to_str(gatt_chrc->uuid, str, sizeof(str));
		shell_print(ctx_shell, "Characteristic %s found: handle %x",
			    str, attr->handle);
		print_chrc_props(ctx_shell, gatt_chrc->properties);
		break;
	case BT_GATT_DISCOVER_INCLUDE:
		gatt_include = attr->user_data;
		bt_uuid_to_str(gatt_include->uuid, str, sizeof(str));
		shell_print(ctx_shell, "Include %s found: handle %x, start %x, "
			    "end %x", str, attr->handle,
			    gatt_include->start_handle,
			    gatt_include->end_handle);
		break;
	default:
		bt_uuid_to_str(attr->uuid, str, sizeof(str));
		shell_print(ctx_shell, "Descriptor %s found: handle %x", str,
			    attr->handle);
		break;
	}

	return BT_GATT_ITER_CONTINUE;
}

static int cmd_discover(const struct shell *shell, size_t argc, char *argv[])
{
	int err;

	if (!default_conn) {
		shell_error(shell, "Not connected");
		return -ENOEXEC;
	}

	if (discover_params.func) {
		shell_print(shell, "Discover ongoing");
		return -ENOEXEC;
	}

	discover_params.func = discover_func;
	discover_params.start_handle = 0x0001;
	discover_params.end_handle = 0xffff;

	if (argc > 1) {
		/* Only set the UUID if the value is valid (non zero) */
		uuid.val = strtoul(argv[1], NULL, 16);
		if (uuid.val) {
			discover_params.uuid = &uuid.uuid;
		}
	}

	if (argc > 2) {
		discover_params.start_handle = strtoul(argv[2], NULL, 16);
		if (argc > 3) {
			discover_params.end_handle = strtoul(argv[3], NULL, 16);
		}
	}

	if (!strcmp(argv[0], "discover")) {
		discover_params.type = BT_GATT_DISCOVER_ATTRIBUTE;
	} else if (!strcmp(argv[0], "discover-secondary")) {
		discover_params.type = BT_GATT_DISCOVER_SECONDARY;
	} else if (!strcmp(argv[0], "discover-include")) {
		discover_params.type = BT_GATT_DISCOVER_INCLUDE;
	} else if (!strcmp(argv[0], "discover-characteristic")) {
		discover_params.type = BT_GATT_DISCOVER_CHARACTERISTIC;
	} else if (!strcmp(argv[0], "discover-descriptor")) {
		discover_params.type = BT_GATT_DISCOVER_DESCRIPTOR;
	} else {
		discover_params.type = BT_GATT_DISCOVER_PRIMARY;
	}

	err = bt_gatt_discover(default_conn, &discover_params);
	if (err) {
		shell_error(shell, "Discover failed (err %d)", err);
	} else {
		shell_print(shell, "Discover pending");
	}

	return err;
}

static struct bt_gatt_read_params read_params;

static uint8_t read_func(struct bt_conn *conn, uint8_t err,
			 struct bt_gatt_read_params *params,
			 const void *data, uint16_t length)
{
	shell_print(ctx_shell, "Read complete: err 0x%02x length %u", err, length);

	if (!data) {
		(void)memset(params, 0, sizeof(*params));
		return BT_GATT_ITER_STOP;
	}

	return BT_GATT_ITER_CONTINUE;
}

static int cmd_read(const struct shell *shell, size_t argc, char *argv[])
{
	int err;

	if (!default_conn) {
		shell_error(shell, "Not connected");
		return -ENOEXEC;
	}

	if (read_params.func) {
		shell_print(shell, "Read ongoing");
		return -ENOEXEC;
	}

	read_params.func = read_func;
	read_params.handle_count = 1;
	read_params.single.handle = strtoul(argv[1], NULL, 16);
	read_params.single.offset = 0U;

	if (argc > 2) {
		read_params.single.offset = strtoul(argv[2], NULL, 16);
	}

	err = bt_gatt_read(default_conn, &read_params);
	if (err) {
		shell_error(shell, "Read failed (err %d)", err);
	} else {
		shell_print(shell, "Read pending");
	}

	return err;
}

static int cmd_mread(const struct shell *shell, size_t argc, char *argv[])
{
	uint16_t h[8];
	size_t i;
	int err;

	if (!default_conn) {
		shell_error(shell, "Not connected");
		return -ENOEXEC;
	}

	if (read_params.func) {
		shell_print(shell, "Read ongoing");
		return -ENOEXEC;
	}

	if ((argc - 1) >  ARRAY_SIZE(h)) {
		shell_print(shell, "Enter max %lu handle items to read",
			    ARRAY_SIZE(h));
		return -EINVAL;
	}

	for (i = 0; i < argc - 1; i++) {
		h[i] = strtoul(argv[i + 1], NULL, 16);
	}

	read_params.func = read_func;
	read_params.handle_count = i;
	read_params.handles = h; /* not used in read func */

	err = bt_gatt_read(default_conn, &read_params);
	if (err) {
		shell_error(shell, "GATT multiple read request failed (err %d)",
			    err);
	}

	return err;
}

static int cmd_read_uuid(const struct shell *shell, size_t argc, char *argv[])
{
	int err;

	if (!default_conn) {
		shell_error(shell, "Not connected");
		return -ENOEXEC;
	}

	if (read_params.func) {
		shell_print(shell, "Read ongoing");
		return -ENOEXEC;
	}

	read_params.func = read_func;
	read_params.handle_count = 0;
	read_params.by_uuid.start_handle = 0x0001;
	read_params.by_uuid.end_handle = 0xffff;

	if (argc > 1) {
		uuid.val = strtoul(argv[1], NULL, 16);
		if (uuid.val) {
			read_params.by_uuid.uuid = &uuid.uuid;
		}
	}

	if (argc > 2) {
		read_params.by_uuid.start_handle = strtoul(argv[2], NULL, 16);
		if (argc > 3) {
			read_params.by_uuid.end_handle = strtoul(argv[3],
								 NULL, 16);
		}
	}

	err = bt_gatt_read(default_conn, &read_params);
	if (err) {
		shell_error(shell, "Read failed (err %d)", err);
	} else {
		shell_print(shell, "Read pending");
	}

	return err;
}

static struct bt_gatt_write_params write_params;
static uint8_t gatt_write_buf[CHAR_SIZE_MAX];

static void write_func(struct bt_conn *conn, uint8_t err,
		       struct bt_gatt_write_params *params)
{
	shell_print(ctx_shell, "Write complete: err 0x%02x", err);

	(void)memset(&write_params, 0, sizeof(write_params));
}

static int cmd_write(const struct shell *shell, size_t argc, char *argv[])
{
	int err;
	uint16_t handle, offset;

	if (!default_conn) {
		shell_error(shell, "Not connected");
		return -ENOEXEC;
	}

	if (write_params.func) {
		shell_error(shell, "Write ongoing");
		return -ENOEXEC;
	}

	handle = strtoul(argv[1], NULL, 16);
	offset = strtoul(argv[2], NULL, 16);

	write_params.length = hex2bin(argv[3], strlen(argv[3]),
				      gatt_write_buf, sizeof(gatt_write_buf));
	if (write_params.length == 0) {
		shell_error(shell, "No data set");
		return -ENOEXEC;
	}

	write_params.data = gatt_write_buf;
	write_params.handle = handle;
	write_params.offset = offset;
	write_params.func = write_func;

	err = bt_gatt_write(default_conn, &write_params);
	if (err) {
		write_params.func = NULL;
		shell_error(shell, "Write failed (err %d)", err);
	} else {
		shell_print(shell, "Write pending");
	}

	return err;
}

static struct write_stats {
	uint32_t count;
	uint32_t len;
	uint32_t total;
	uint32_t rate;
} write_stats;

static void update_write_stats(uint16_t len)
{
	static uint32_t cycle_stamp;
	uint32_t delta;

	delta = k_cycle_get_32() - cycle_stamp;
	delta = (uint32_t)k_cyc_to_ns_floor64(delta);

	if (!delta) {
		delta = 1;
	}

	write_stats.count++;
	write_stats.total += len;

	/* if last data rx-ed was greater than 1 second in the past,
	 * reset the metrics.
	 */
	if (delta > 1000000000) {
		write_stats.len = 0U;
		write_stats.rate = 0U;
		cycle_stamp = k_cycle_get_32();
	} else {
		write_stats.len += len;
		write_stats.rate = ((uint64_t)write_stats.len << 3) *
				   1000000000U / delta;
	}
}

static void reset_write_stats(void)
{
	memset(&write_stats, 0, sizeof(write_stats));
}

static void print_write_stats(void)
{
	shell_print(ctx_shell, "Write #%u: %u bytes (%u bps)",
		    write_stats.count, write_stats.total, write_stats.rate);
}

static void write_without_rsp_cb(struct bt_conn *conn, void *user_data)
{
	uint16_t len = POINTER_TO_UINT(user_data);

	update_write_stats(len);

	print_write_stats();
}

static int cmd_write_without_rsp(const struct shell *shell,
				 size_t argc, char *argv[])
{
	uint16_t handle;
	uint16_t repeat;
	int err;
	uint16_t len;
	bool sign;
	bt_gatt_complete_func_t func = NULL;

	if (!default_conn) {
		shell_error(shell, "Not connected");
		return -ENOEXEC;
	}

	sign = !strcmp(argv[0], "signed-write");
	if (!sign) {
		if (!strcmp(argv[0], "write-without-response-cb")) {
			func = write_without_rsp_cb;
			reset_write_stats();
		}
	}

	handle = strtoul(argv[1], NULL, 16);
	gatt_write_buf[0] = strtoul(argv[2], NULL, 16);
	len = 1U;

	if (argc > 3) {
		int i;

		len = MIN(strtoul(argv[3], NULL, 16), sizeof(gatt_write_buf));

		for (i = 1; i < len; i++) {
			gatt_write_buf[i] = gatt_write_buf[0];
		}
	}

	repeat = 0U;

	if (argc > 4) {
		repeat = strtoul(argv[4], NULL, 16);
	}

	if (!repeat) {
		repeat = 1U;
	}

	while (repeat--) {
		err = bt_gatt_write_without_response_cb(default_conn, handle,
							gatt_write_buf, len,
							sign, func,
							UINT_TO_POINTER(len));
		if (err) {
			break;
		}

		k_yield();

	}

	shell_print(shell, "Write Complete (err %d)", err);
	return err;
}

static struct bt_gatt_subscribe_params subscribe_params;

static uint8_t notify_func(struct bt_conn *conn,
			struct bt_gatt_subscribe_params *params,
			const void *data, uint16_t length)
{
	if (!data) {
		shell_print(ctx_shell, "Unsubscribed");
		params->value_handle = 0U;
		return BT_GATT_ITER_STOP;
	}

	shell_print(ctx_shell, "Notification: data %p length %u", data, length);

	return BT_GATT_ITER_CONTINUE;
}

static int cmd_subscribe(const struct shell *shell, size_t argc, char *argv[])
{
	int err;

	if (subscribe_params.value_handle) {
		shell_error(shell, "Cannot subscribe: subscription to %x "
			    "already exists", subscribe_params.value_handle);
		return -ENOEXEC;
	}

	if (!default_conn) {
		shell_error(shell, "Not connected");
		return -ENOEXEC;
	}

	subscribe_params.ccc_handle = strtoul(argv[1], NULL, 16);
	subscribe_params.value_handle = strtoul(argv[2], NULL, 16);
	subscribe_params.value = BT_GATT_CCC_NOTIFY;
	subscribe_params.notify = notify_func;

#if defined(CONFIG_BT_GATT_AUTO_DISCOVER_CCC)
	if (subscribe_params.ccc_handle == 0) {
		static struct bt_gatt_discover_params disc_params;

		subscribe_params.disc_params = &disc_params;
		subscribe_params.end_handle = 0xFFFF;
	}
#endif /* CONFIG_BT_GATT_AUTO_DISCOVER_CCC */


	if (argc > 3 && !strcmp(argv[3], "ind")) {
		subscribe_params.value = BT_GATT_CCC_INDICATE;
	}

	err = bt_gatt_subscribe(default_conn, &subscribe_params);
	if (err) {
		subscribe_params.value_handle = 0U;
		shell_error(shell, "Subscribe failed (err %d)", err);
	} else {
		shell_print(shell, "Subscribed");
	}

	return err;
}

static int cmd_resubscribe(const struct shell *shell, size_t argc,
				char *argv[])
{
	bt_addr_le_t addr;
	int err;

	if (subscribe_params.value_handle) {
		shell_error(shell, "Cannot resubscribe: subscription to %x"
			    " already exists", subscribe_params.value_handle);
		return -ENOEXEC;
	}

	err = bt_addr_le_from_str(argv[1], argv[2], &addr);
	if (err) {
		shell_error(shell, "Invalid peer address (err %d)", err);
		return -ENOEXEC;
	}

	subscribe_params.ccc_handle = strtoul(argv[3], NULL, 16);
	subscribe_params.value_handle = strtoul(argv[4], NULL, 16);
	subscribe_params.value = BT_GATT_CCC_NOTIFY;
	subscribe_params.notify = notify_func;

	if (argc > 5 && !strcmp(argv[5], "ind")) {
		subscribe_params.value = BT_GATT_CCC_INDICATE;
	}

	err = bt_gatt_resubscribe(selected_id, &addr, &subscribe_params);
	if (err) {
		subscribe_params.value_handle = 0U;
		shell_error(shell, "Resubscribe failed (err %d)", err);
	} else {
		shell_print(shell, "Resubscribed");
	}

	return err;
}

static int cmd_unsubscribe(const struct shell *shell,
			   size_t argc, char *argv[])
{
	int err;

	if (!default_conn) {
		shell_error(shell, "Not connected");
		return -ENOEXEC;
	}

	if (!subscribe_params.value_handle) {
		shell_error(shell, "No subscription found");
		return -ENOEXEC;
	}

	err = bt_gatt_unsubscribe(default_conn, &subscribe_params);
	if (err) {
		shell_error(shell, "Unsubscribe failed (err %d)", err);
	} else {
		shell_print(shell, "Unsubscribe success");
	}

	return err;
}
#endif /* CONFIG_BT_GATT_CLIENT */

static struct db_stats {
	uint16_t svc_count;
	uint16_t attr_count;
	uint16_t chrc_count;
	uint16_t ccc_count;
} stats;

static uint8_t print_attr(const struct bt_gatt_attr *attr, uint16_t handle,
			  void *user_data)
{
	const struct shell *shell = user_data;
	char str[BT_UUID_STR_LEN];

	stats.attr_count++;

	if (!bt_uuid_cmp(attr->uuid, BT_UUID_GATT_PRIMARY) ||
	    !bt_uuid_cmp(attr->uuid, BT_UUID_GATT_SECONDARY)) {
		stats.svc_count++;
	}

	if (!bt_uuid_cmp(attr->uuid, BT_UUID_GATT_CHRC)) {
		stats.chrc_count++;
	}

	if (!bt_uuid_cmp(attr->uuid, BT_UUID_GATT_CCC) &&
	    attr->write == bt_gatt_attr_write_ccc) {
		stats.ccc_count++;
	}

	bt_uuid_to_str(attr->uuid, str, sizeof(str));
	shell_print(shell, "attr %p handle 0x%04x uuid %s perm 0x%02x",
		    attr, handle, str, attr->perm);

	return BT_GATT_ITER_CONTINUE;
}

static int cmd_show_db(const struct shell *shell, size_t argc, char *argv[])
{
	struct bt_uuid_16 uuid;
	size_t total_len;

	memset(&stats, 0, sizeof(stats));

	if (argc > 1) {
		uint16_t num_matches = 0;

		uuid.uuid.type = BT_UUID_TYPE_16;
		uuid.val = strtoul(argv[1], NULL, 16);

		if (argc > 2) {
			num_matches = strtoul(argv[2], NULL, 10);
		}

		bt_gatt_foreach_attr_type(0x0001, 0xffff, &uuid.uuid, NULL,
					  num_matches, print_attr,
					  (void *)shell);
		return 0;
	}

	bt_gatt_foreach_attr(0x0001, 0xffff, print_attr, (void *)shell);

	if (!stats.attr_count) {
		shell_print(shell, "No attribute found");
		return 0;
	}

	total_len = stats.svc_count * sizeof(struct bt_gatt_service);
	total_len += stats.chrc_count * sizeof(struct bt_gatt_chrc);
	total_len += stats.attr_count * sizeof(struct bt_gatt_attr);
	total_len += stats.ccc_count * sizeof(struct _bt_gatt_ccc);

	shell_print(shell, "=================================================");
	shell_print(shell, "Total: %u services %u attributes (%u bytes)",
		    stats.svc_count, stats.attr_count, total_len);

	return 0;
}

#if defined(CONFIG_BT_GATT_DYNAMIC_DB)
/* Custom Service Variables */
static struct bt_uuid_128 vnd_uuid = BT_UUID_INIT_128(
	0xf0, 0xde, 0xbc, 0x9a, 0x78, 0x56, 0x34, 0x12,
	0x78, 0x56, 0x34, 0x12, 0x78, 0x56, 0x34, 0x12);
static struct bt_uuid_128 vnd_auth_uuid = BT_UUID_INIT_128(
	0xf2, 0xde, 0xbc, 0x9a, 0x78, 0x56, 0x34, 0x12,
	0x78, 0x56, 0x34, 0x12, 0x78, 0x56, 0x34, 0x12);
static const struct bt_uuid_128 vnd_long_uuid1 = BT_UUID_INIT_128(
	0xf3, 0xde, 0xbc, 0x9a, 0x78, 0x56, 0x34, 0x12,
	0x78, 0x56, 0x34, 0x12, 0x78, 0x56, 0x34, 0x12);
static const struct bt_uuid_128 vnd_long_uuid2 = BT_UUID_INIT_128(
	0xde, 0xad, 0xfa, 0xce, 0x78, 0x56, 0x34, 0x12,
	0x78, 0x56, 0x34, 0x12, 0x78, 0x56, 0x34, 0x12);

static uint8_t vnd_value[] = { 'V', 'e', 'n', 'd', 'o', 'r' };

static struct bt_uuid_128 vnd1_uuid = BT_UUID_INIT_128(
	0xf4, 0xde, 0xbc, 0x9a, 0x78, 0x56, 0x34, 0x12,
	0x78, 0x56, 0x34, 0x12, 0x78, 0x56, 0x34, 0x12);

static const struct bt_uuid_128 vnd1_echo_uuid = BT_UUID_INIT_128(
	0xf5, 0xde, 0xbc, 0x9a, 0x78, 0x56, 0x34, 0x12,
	0x78, 0x56, 0x34, 0x12, 0x78, 0x56, 0x34, 0x12);

static uint8_t echo_enabled;

static void vnd1_ccc_cfg_changed(const struct bt_gatt_attr *attr, uint16_t value)
{
	echo_enabled = (value == BT_GATT_CCC_NOTIFY) ? 1 : 0;
}

static ssize_t write_vnd1(struct bt_conn *conn, const struct bt_gatt_attr *attr,
			  const void *buf, uint16_t len, uint16_t offset,
			  uint8_t flags)
{
	if (echo_enabled) {
		shell_print(ctx_shell, "Echo attr len %u", len);
		bt_gatt_notify(conn, attr, buf, len);
	}

	return len;
}

static ssize_t read_vnd(struct bt_conn *conn, const struct bt_gatt_attr *attr,
			void *buf, uint16_t len, uint16_t offset)
{
	const char *value = attr->user_data;

	return bt_gatt_attr_read(conn, attr, buf, len, offset, value,
				 strlen(value));
}

static ssize_t write_vnd(struct bt_conn *conn, const struct bt_gatt_attr *attr,
			 const void *buf, uint16_t len, uint16_t offset,
			 uint8_t flags)
{
	uint8_t *value = attr->user_data;

	if (offset + len > sizeof(vnd_value)) {
		return BT_GATT_ERR(BT_ATT_ERR_INVALID_OFFSET);
	}

	memcpy(value + offset, buf, len);

	return len;
}

#define MAX_DATA 30
static uint8_t vnd_long_value1[MAX_DATA] = { 'V', 'e', 'n', 'd', 'o', 'r' };
static uint8_t vnd_long_value2[MAX_DATA] = { 'S', 't', 'r', 'i', 'n', 'g' };

static ssize_t read_long_vnd(struct bt_conn *conn,
			     const struct bt_gatt_attr *attr, void *buf,
			     uint16_t len, uint16_t offset)
{
	uint8_t *value = attr->user_data;

	return bt_gatt_attr_read(conn, attr, buf, len, offset, value,
				 sizeof(vnd_long_value1));
}

static ssize_t write_long_vnd(struct bt_conn *conn,
			      const struct bt_gatt_attr *attr, const void *buf,
			      uint16_t len, uint16_t offset, uint8_t flags)
{
	uint8_t *value = attr->user_data;

	if (flags & BT_GATT_WRITE_FLAG_PREPARE) {
		return 0;
	}

	if (offset + len > sizeof(vnd_long_value1)) {
		return BT_GATT_ERR(BT_ATT_ERR_INVALID_OFFSET);
	}

	/* Copy to buffer */
	memcpy(value + offset, buf, len);

	return len;
}

static struct bt_gatt_attr vnd_attrs[] = {
	/* Vendor Primary Service Declaration */
	BT_GATT_PRIMARY_SERVICE(&vnd_uuid),

	BT_GATT_CHARACTERISTIC(&vnd_auth_uuid.uuid,
			       BT_GATT_CHRC_READ | BT_GATT_CHRC_WRITE,
			       BT_GATT_PERM_READ_AUTHEN |
			       BT_GATT_PERM_WRITE_AUTHEN,
			       read_vnd, write_vnd, vnd_value),

	BT_GATT_CHARACTERISTIC(&vnd_long_uuid1.uuid, BT_GATT_CHRC_READ |
			       BT_GATT_CHRC_WRITE | BT_GATT_CHRC_EXT_PROP,
			       BT_GATT_PERM_READ | BT_GATT_PERM_WRITE |
			       BT_GATT_PERM_PREPARE_WRITE,
			       read_long_vnd, write_long_vnd,
			       &vnd_long_value1),

	BT_GATT_CHARACTERISTIC(&vnd_long_uuid2.uuid, BT_GATT_CHRC_READ |
			       BT_GATT_CHRC_WRITE | BT_GATT_CHRC_EXT_PROP,
			       BT_GATT_PERM_READ | BT_GATT_PERM_WRITE |
			       BT_GATT_PERM_PREPARE_WRITE,
			       read_long_vnd, write_long_vnd,
			       &vnd_long_value2),
};

static struct bt_gatt_service vnd_svc = BT_GATT_SERVICE(vnd_attrs);

static struct bt_gatt_attr vnd1_attrs[] = {
	/* Vendor Primary Service Declaration */
	BT_GATT_PRIMARY_SERVICE(&vnd1_uuid),

	BT_GATT_CHARACTERISTIC(&vnd1_echo_uuid.uuid,
			       BT_GATT_CHRC_WRITE_WITHOUT_RESP |
			       BT_GATT_CHRC_NOTIFY,
			       BT_GATT_PERM_WRITE, NULL, write_vnd1, NULL),
	BT_GATT_CCC(vnd1_ccc_cfg_changed,
		    BT_GATT_PERM_READ | BT_GATT_PERM_WRITE),
};

static struct bt_gatt_service vnd1_svc = BT_GATT_SERVICE(vnd1_attrs);

static int cmd_register_test_svc(const struct shell *shell,
				  size_t argc, char *argv[])
{
	bt_gatt_service_register(&vnd_svc);
	bt_gatt_service_register(&vnd1_svc);

	shell_print(shell, "Registering test vendor services");
	return 0;
}

static int cmd_unregister_test_svc(const struct shell *shell,
				    size_t argc, char *argv[])
{
	bt_gatt_service_unregister(&vnd_svc);
	bt_gatt_service_unregister(&vnd1_svc);

	shell_print(shell, "Unregistering test vendor services");
	return 0;
}

static void notify_cb(struct bt_conn *conn, void *user_data)
{
	const struct shell *shell = user_data;

	shell_print(shell, "Nofication sent to conn %p", conn);
}

static int cmd_notify(const struct shell *shell, size_t argc, char *argv[])
{
	struct bt_gatt_notify_params params;
	uint8_t data = 0;

	if (!echo_enabled) {
		shell_error(shell, "Nofication not enabled");
		return -ENOEXEC;
	}

	if (argc > 1) {
		data = strtoul(argv[1], NULL, 16);
	}

	memset(&params, 0, sizeof(params));

	params.uuid = &vnd1_echo_uuid.uuid;
	params.attr = vnd1_attrs;
	params.data = &data;
	params.len = sizeof(data);
	params.func = notify_cb;
	params.user_data = (void *)shell;

	bt_gatt_notify_cb(NULL, &params);

	return 0;
}

static struct bt_uuid_128 met_svc_uuid = BT_UUID_INIT_128(
	0x01, 0xde, 0xbc, 0x9a, 0x78, 0x56, 0x34, 0x12,
	0x78, 0x56, 0x34, 0x12, 0x78, 0x56, 0x34, 0x12);

static const struct bt_uuid_128 met_char_uuid = BT_UUID_INIT_128(
	0x02, 0xde, 0xbc, 0x9a, 0x78, 0x56, 0x34, 0x12,
	0x78, 0x56, 0x34, 0x12, 0x78, 0x56, 0x34, 0x12);

static uint8_t met_char_value[CHAR_SIZE_MAX] = {
	'M', 'e', 't', 'r', 'i', 'c', 's' };

static ssize_t read_met(struct bt_conn *conn, const struct bt_gatt_attr *attr,
			void *buf, uint16_t len, uint16_t offset)
{
	const char *value = attr->user_data;
	uint16_t value_len;

	value_len = MIN(strlen(value), CHAR_SIZE_MAX);

	return bt_gatt_attr_read(conn, attr, buf, len, offset, value,
				 value_len);
}

//*** start of advertiser part ***/
#define P_ADV_INT 0x0800
#define PER_PARAM BT_LE_PER_ADV_PARAM(P_ADV_INT, \
						  P_ADV_INT, \
						  BT_LE_PER_ADV_OPT_NONE)
#define EXT_ADV_START_PARAM BT_LE_EXT_ADV_START_PARAM(0, 0)
//(timeout, num_events) 0=forever (scanner can find it anytime)

int order, num_advtisers, adv_int, adv_t;

static uint8_t mfg_data[] = { 0xff, 0xff, 0x00 };

static const struct bt_data ad[] = {
	BT_DATA(BT_DATA_MANUFACTURER_DATA, mfg_data, 3),
};

void periodic_adv()
{
	struct bt_le_ext_adv *adv;
	int err;
	
	mfg_data[0] = order;
	
	printk("Starting Periodic Advertising\n");
	
	//TODO: wait
	
	/* Create a non-connectable non-scannable advertising set */
	err = bt_le_ext_adv_create(BT_LE_EXT_ADV_NCONN_NAME, NULL, &adv);
	if (err) {
		printk("Failed to create advertising set (err %d)\n", err);
		return;
	}

	/* Set periodic advertising parameters */
	err = bt_le_per_adv_set_param(adv, PER_PARAM);
	if (err) {
		printk("Failed to set periodic advertising parameters"
		       " (err %d)\n", err);
		return;
	}

	/* Enable Periodic Advertising */
	err = bt_le_per_adv_start(adv);
	if (err) {
		printk("Failed to enable periodic advertising (err %d)\n", err);
		return;
	}

	/* Start extended advertising */
	err = bt_le_ext_adv_start(adv, EXT_ADV_START_PARAM);
	if (err) {
		printk("Failed to start extended advertising (err %d)\n", err);
		return;
	}
	
	//TODO: advertising for certain time
	//TODO: stop advertising after certain time
	
	while (true) {
		k_sleep(K_SECONDS(1));

		mfg_data[2]++;

		printk("Set Periodic Advertising Data...");
		err = bt_le_per_adv_set_data(adv, ad, ARRAY_SIZE(ad));
		if (err) {
			printk("Failed (err %d)\n", err);
			return;
		}
		printk("done.\n");
	}
}

static ssize_t write_met(struct bt_conn *conn, const struct bt_gatt_attr *attr,
			 const void *buf, uint16_t len, uint16_t offset,
			 uint8_t flags)
{
	uint8_t *value = attr->user_data;
	
	if (offset + len > sizeof(met_char_value)) {
		return BT_GATT_ERR(BT_ATT_ERR_INVALID_OFFSET);
	}

	memcpy(value + offset, buf, len);
	
	update_write_stats(len);
	
	uint8_t data[256];
	attr->read(NULL, attr, (void *)data, sizeof(data), 0);
	
	order = data[0];
	num_advtisers = data[1];
	adv_int = data[2];
	adv_t = data[3];
	
	printk("\nMy periodic advertising order: %d,\n", order);
	printk("Periodic advertising interval: %d units,\n", adv_int);
	printk("Advertising time: %d ms,\n", adv_t);
	printk("Num of advertisers: %d\n\n", num_advtisers);
	printk("Ready to start periodic advertising after disconnected.\n\n");
	
	int err = bt_conn_disconnect(conn, BT_HCI_ERR_REMOTE_USER_TERM_CONN);
	if (err) {
		printk("bt_conn_disconnect ERR: %d", err);
	}
	
	err = bt_le_adv_stop();
	if (err) {
		printk("bt_le_adv_stop ERR: %d", err);
	}
	
	periodic_adv();

	return len;
}
//*** end of advertiser part ***/

//*** start of scanner part ***/
#define TIMEOUT_SYNC_CREATE K_SECONDS(10)
#define NAME_LEN            30

static bool         per_adv_found;
static bt_addr_le_t per_addr;
static uint8_t      per_sid;

static K_SEM_DEFINE(sem_per_adv, 0, 1);
static K_SEM_DEFINE(sem_per_sync, 0, 1);
static K_SEM_DEFINE(sem_per_sync_lost, 0, 1);

static bool data_cb(struct bt_data *data, void *user_data)
{
	char *name = user_data;
	uint8_t len;

	switch (data->type) {
	case BT_DATA_NAME_SHORTENED:
	case BT_DATA_NAME_COMPLETE:
		len = MIN(data->data_len, NAME_LEN - 1);
		memcpy(name, data->data, len);
		name[len] = '\0';
		return false;
	default:
		return true;
	}
}

static const char *phy2str(uint8_t phy)
{
	switch (phy) {
	case 0: return "No packets";
	case BT_GAP_LE_PHY_1M: return "LE 1M";
	case BT_GAP_LE_PHY_2M: return "LE 2M";
	case BT_GAP_LE_PHY_CODED: return "LE Coded";
	default: return "Unknown";
	}
}

static void scan_recv(const struct bt_le_scan_recv_info *info,
		      struct net_buf_simple *buf)
{
	char le_addr[BT_ADDR_LE_STR_LEN];
	char name[NAME_LEN];

	(void)memset(name, 0, sizeof(name));

	bt_data_parse(buf, data_cb, name);

	bt_addr_le_to_str(info->addr, le_addr, sizeof(le_addr));
	
	printk("[DEVICE]: %s, AD evt type %u, Tx Pwr: %i, RSSI %i %s "
	       "C:%u S:%u D:%u SR:%u E:%u Prim: %s, Secn: %s, "
	       "Interval: 0x%04x (%u ms), SID: %u\n",
	       le_addr, info->adv_type, info->tx_power, info->rssi, name,
	       (info->adv_props & BT_GAP_ADV_PROP_CONNECTABLE) != 0,
	       (info->adv_props & BT_GAP_ADV_PROP_SCANNABLE) != 0,
	       (info->adv_props & BT_GAP_ADV_PROP_DIRECTED) != 0,
	       (info->adv_props & BT_GAP_ADV_PROP_SCAN_RESPONSE) != 0,
	       (info->adv_props & BT_GAP_ADV_PROP_EXT_ADV) != 0,
	       phy2str(info->primary_phy), phy2str(info->secondary_phy),
	       info->interval, info->interval * 5 / 4, info->sid);
		   
	if (!per_adv_found && info->interval) {
		per_adv_found = true;

		per_sid = info->sid;
		bt_addr_le_copy(&per_addr, info->addr);

		k_sem_give(&sem_per_adv);
	}
}

static struct bt_le_scan_cb scan_callbacks = {
	.recv = scan_recv,
};

static void sync_cb(struct bt_le_per_adv_sync *sync,
		    struct bt_le_per_adv_sync_synced_info *info)
{
	char le_addr[BT_ADDR_LE_STR_LEN];

	bt_addr_le_to_str(info->addr, le_addr, sizeof(le_addr));

	printk("PER_ADV_SYNC[%u]: [DEVICE]: %s synced, "
	       "Interval 0x%04x (%u ms), PHY %s\n",
	       bt_le_per_adv_sync_get_index(sync), le_addr,
	       info->interval, info->interval * 5 / 4, phy2str(info->phy));

	k_sem_give(&sem_per_sync);
}

static void term_cb(struct bt_le_per_adv_sync *sync,
		    const struct bt_le_per_adv_sync_term_info *info)
{
	char le_addr[BT_ADDR_LE_STR_LEN];

	bt_addr_le_to_str(info->addr, le_addr, sizeof(le_addr));

	printk("PER_ADV_SYNC[%u]: [DEVICE]: %s sync terminated\n",
	       bt_le_per_adv_sync_get_index(sync), le_addr);

	k_sem_give(&sem_per_sync_lost);
}

static void recv_cb(struct bt_le_per_adv_sync *sync,
		    const struct bt_le_per_adv_sync_recv_info *info,
		    struct net_buf_simple *buf)
{
	char le_addr[BT_ADDR_LE_STR_LEN];
	char data_str[129];

	bt_addr_le_to_str(info->addr, le_addr, sizeof(le_addr));
	bin2hex(buf->data, buf->len, data_str, sizeof(data_str));

	printk("PER_ADV_SYNC[%u]: [DEVICE]: %s, tx_power %i, "
	       "RSSI %i, CTE %u, data length %u, data: %s\n",
	       bt_le_per_adv_sync_get_index(sync), le_addr, info->tx_power,
	       info->rssi, info->cte_type, buf->len, data_str);
}

static struct bt_le_per_adv_sync_cb sync_callbacks = {
	.synced = sync_cb,
	.term = term_cb,
	.recv = recv_cb
};

void periodic_adv_sync()
{
	struct bt_le_per_adv_sync_param sync_create_param;
	struct bt_le_per_adv_sync *sync;
	int err;

	printk("Starting Periodic Advertising Synchronization\n");

	printk("Scan callbacks register...");
	bt_le_scan_cb_register(&scan_callbacks);
	printk("success.\n");

	printk("Periodic Advertising callbacks register...");
	bt_le_per_adv_sync_cb_register(&sync_callbacks);
	printk("Success.\n");

	printk("Start scanning...");
	err = bt_le_scan_start(BT_LE_SCAN_ACTIVE, NULL);
	if (err) {
		printk("failed (err %d)\n", err);
		return;
	}
	printk("success.\n");

	do {
		printk("Waiting for periodic advertising...\n");
		per_adv_found = false;
		err = k_sem_take(&sem_per_adv, K_FOREVER);
		if (err) {
			printk("failed (err %d)\n", err);
			return;
		}
		printk("Found periodic advertising.\n");

		printk("Creating Periodic Advertising Sync...");
		bt_addr_le_copy(&sync_create_param.addr, &per_addr);
		sync_create_param.options = 0;
		sync_create_param.sid = per_sid;
		sync_create_param.skip = 0;
		sync_create_param.timeout = 0xa;
		err = bt_le_per_adv_sync_create(&sync_create_param, &sync);
		if (err) {
			printk("failed (err %d)\n", err);
			return;
		}
		printk("success.\n");

		printk("Waiting for periodic sync...\n");
		err = k_sem_take(&sem_per_sync, TIMEOUT_SYNC_CREATE);
		if (err) {
			printk("failed (err %d)\n", err);

			printk("Deleting Periodic Advertising Sync...");
			err = bt_le_per_adv_sync_delete(sync);
			if (err) {
				printk("failed (err %d)\n", err);
				return;
			}
			continue;
		}
		printk("Periodic sync established.\n");

		printk("Waiting for periodic sync lost...\n");
		err = k_sem_take(&sem_per_sync_lost, K_FOREVER);
		if (err) {
			printk("failed (err %d)\n", err);
			return;
		}
		printk("Periodic sync lost.\n");
	} while (true);
}

static int cmd_periodic_adv_sync_start(const struct shell *shell, size_t argc, char *argv[])
{
	periodic_adv_sync();
	return 0;
}

//<num_advtisers> <adv_int> <adv_t>", cmd_periodic_adv_setup
static int cmd_periodic_adv_setup(const struct shell *shell,
				 size_t argc, char *argv[])
{
	uint16_t handle = 0x1e;
	int err;
	uint16_t len;
	bool sign;
	bt_gatt_complete_func_t func = NULL;

	if (!default_conn) {
		shell_error(shell, "Not connected");
		return -ENOEXEC;
	}

	sign = !strcmp(argv[0], "signed-write");
	if (!sign) {
		if (!strcmp(argv[0], "write-without-response-cb")) {
			func = write_without_rsp_cb;
			reset_write_stats();
		}
	}
	
	//TODO: update CI 7.5

	num_advtisers = strtoul(argv[1], NULL, 16);
	adv_int = strtoul(argv[2], NULL, 16);
	adv_t = strtoul(argv[3], NULL, 16);
	
	gatt_write_buf[1] = num_advtisers;
	gatt_write_buf[2] = adv_int;
	gatt_write_buf[3] = adv_t;
	
	len = 4;
	
	for(int i = 0; i < CONFIG_BT_MAX_CONN; i++)
	{
		order = i;
		gatt_write_buf[0] = order + 1;
		err = bt_gatt_write_without_response_cb(index_get_conn(i), handle,
								gatt_write_buf, len,
								sign, func,
								UINT_TO_POINTER(len));
		if (err) {
			printk("gatt_write_without_response ERR: %d", err);
		}
		printk("Conn: %d\n", bt_conn_index(index_get_conn(i)));
	}

	shell_print(shell, "Write Complete (err %d)", err);
	printk("\nPeriodic advertising interval: %d units,\n", adv_int);
	printk("Advertising time: %d ms,\n ", adv_t);
	printk("Num of advertisers: %d\n", num_advtisers);
	printk("\nReady to diconnect from %d advertisers\n", num_advtisers);
	
	// start periodic advertising sync
	
	periodic_adv_sync();
	
	return err;
}
//*** end of scanner part ***/


static struct bt_gatt_attr met_attrs[] = {
	BT_GATT_PRIMARY_SERVICE(&met_svc_uuid),

	BT_GATT_CHARACTERISTIC(&met_char_uuid.uuid,
			       BT_GATT_CHRC_READ | BT_GATT_CHRC_WRITE,
			       BT_GATT_PERM_READ | BT_GATT_PERM_WRITE,
			       read_met, write_met, met_char_value),
};

static struct bt_gatt_service met_svc = BT_GATT_SERVICE(met_attrs);

static int cmd_metrics(const struct shell *shell, size_t argc, char *argv[])
{
	int err = 0;

	if (argc < 2) {
		print_write_stats();
		return 0;
	}

	if (!strcmp(argv[1], "on")) {
		shell_print(shell, "Registering GATT metrics test Service.");
		err = bt_gatt_service_register(&met_svc);
	} else if (!strcmp(argv[1], "off")) {
		shell_print(shell, "Unregistering GATT metrics test Service.");
		err = bt_gatt_service_unregister(&met_svc);
	} else {
		shell_error(shell, "Incorrect value: %s", argv[1]);
		shell_help(shell);
		return -ENOEXEC;
	}

	if (!err) {
		shell_print(shell, "GATT write cmd metrics %s.", argv[1]);
	}

	return err;
}
#endif /* CONFIG_BT_GATT_DYNAMIC_DB */

static uint8_t get_cb(const struct bt_gatt_attr *attr, uint16_t handle,
		      void *user_data)
{
	struct shell *shell = user_data;
	uint8_t buf[256];
	ssize_t ret;
	char str[BT_UUID_STR_LEN];

	bt_uuid_to_str(attr->uuid, str, sizeof(str));
	shell_print(shell, "attr %p uuid %s perm 0x%02x", attr, str,
		    attr->perm);

	if (!attr->read) {
		return BT_GATT_ITER_CONTINUE;
	}

	ret = attr->read(NULL, attr, (void *)buf, sizeof(buf), 0);
	if (ret < 0) {
		shell_print(shell, "Failed to read: %d", ret);
		return BT_GATT_ITER_STOP;
	}

	shell_hexdump(shell, buf, ret);

	return BT_GATT_ITER_CONTINUE;
}

static int cmd_get(const struct shell *shell, size_t argc, char *argv[])
{
	uint16_t start, end;

	start = strtoul(argv[1], NULL, 16);
	end = start;

	if (argc > 2) {
		end = strtoul(argv[2], NULL, 16);
	}

	bt_gatt_foreach_attr(start, end, get_cb, (void *)shell);

	return 0;
}

struct set_data {
	const struct shell *shell;
	size_t argc;
	char **argv;
	int err;
};

static uint8_t set_cb(const struct bt_gatt_attr *attr, uint16_t handle,
		      void *user_data)
{
	struct set_data *data = user_data;
	uint8_t buf[256];
	size_t i;
	ssize_t ret;

	if (!attr->write) {
		shell_error(data->shell, "Write not supported");
		data->err = -ENOENT;
		return BT_GATT_ITER_CONTINUE;
	}

	for (i = 0; i < data->argc; i++) {
		buf[i] = strtoul(data->argv[i], NULL, 16);
	}

	ret = attr->write(NULL, attr, (void *)buf, i, 0, 0);
	if (ret < 0) {
		data->err = ret;
		shell_error(data->shell, "Failed to write: %d", ret);
		return BT_GATT_ITER_STOP;
	}

	return BT_GATT_ITER_CONTINUE;
}

static int cmd_set(const struct shell *shell, size_t argc, char *argv[])
{
	uint16_t handle;
	struct set_data data;

	handle = strtoul(argv[1], NULL, 16);

	data.shell = shell;
	data.argc = argc - 2;
	data.argv = argv + 2;
	data.err = 0;

	bt_gatt_foreach_attr(handle, handle, set_cb, &data);

	if (data.err < 0) {
		return -ENOEXEC;
	}

	bt_gatt_foreach_attr(handle, handle, get_cb, (void *)shell);

	return 0;
}

int cmd_att_mtu(const struct shell *shell, size_t argc, char *argv[])
{
	uint16_t mtu;

	if (default_conn) {
		mtu = bt_gatt_get_mtu(default_conn);
		shell_print(shell, "MTU size: %d", mtu);
	} else {
		shell_print(shell, "No default connection");
	}

	return 0;
}

#define HELP_NONE "[none]"
#define HELP_ADDR_LE "<address: XX:XX:XX:XX:XX:XX> <type: (public|random)>"

SHELL_STATIC_SUBCMD_SET_CREATE(gatt_cmds,
#if defined(CONFIG_BT_GATT_CLIENT)
	SHELL_CMD_ARG(discover, NULL,
		      "[UUID] [start handle] [end handle]", cmd_discover, 1, 3),
	SHELL_CMD_ARG(discover-characteristic, NULL,
		      "[UUID] [start handle] [end handle]", cmd_discover, 1, 3),
	SHELL_CMD_ARG(discover-descriptor, NULL,
		      "[UUID] [start handle] [end handle]", cmd_discover, 1, 3),
	SHELL_CMD_ARG(discover-include, NULL,
		      "[UUID] [start handle] [end handle]", cmd_discover, 1, 3),
	SHELL_CMD_ARG(discover-primary, NULL,
		      "[UUID] [start handle] [end handle]", cmd_discover, 1, 3),
	SHELL_CMD_ARG(discover-secondary, NULL,
		      "[UUID] [start handle] [end handle]", cmd_discover, 1, 3),
	SHELL_CMD_ARG(exchange-mtu, NULL, HELP_NONE, cmd_exchange_mtu, 1, 0),
	SHELL_CMD_ARG(per-adv-start, NULL, HELP_NONE, cmd_periodic_adv_sync_start, 1, 0),
	SHELL_CMD_ARG(read, NULL, "<handle> [offset]", cmd_read, 2, 1),
	SHELL_CMD_ARG(read-uuid, NULL, "<UUID> [start handle] [end handle]",
		      cmd_read_uuid, 2, 2),
	SHELL_CMD_ARG(read-multiple, NULL, "<handle 1> <handle 2> ...",
		      cmd_mread, 2, -1),
	SHELL_CMD_ARG(signed-write, NULL, "<handle> <data> [length] [repeat]",
		      cmd_write_without_rsp, 3, 2),
	SHELL_CMD_ARG(subscribe, NULL, "<CCC handle> <value handle> [ind]",
		      cmd_subscribe, 3, 1),
	SHELL_CMD_ARG(resubscribe, NULL, HELP_ADDR_LE" <CCC handle> "
		      "<value handle> [ind]", cmd_resubscribe, 5, 1),
	SHELL_CMD_ARG(write, NULL, "<handle> <offset> <data>", cmd_write, 4, 0),
	SHELL_CMD_ARG(periodic-adv-setup, NULL, 
		"<num_advtisers> <adv_int> <adv_t>", cmd_periodic_adv_setup, 4, 0),
	SHELL_CMD_ARG(write-without-response, NULL,
		      "<handle> <data> [length] [repeat]",
		      cmd_write_without_rsp, 3, 2),
	SHELL_CMD_ARG(write-without-response-cb, NULL,
		      "<handle> <data> [length] [repeat]",
		      cmd_write_without_rsp, 3, 2),
	SHELL_CMD_ARG(unsubscribe, NULL, HELP_NONE, cmd_unsubscribe, 1, 0),
#endif /* CONFIG_BT_GATT_CLIENT */
	SHELL_CMD_ARG(get, NULL, "<start handle> [end handle]", cmd_get, 2, 1),
	SHELL_CMD_ARG(set, NULL, "<handle> [data...]", cmd_set, 2, 255),
	SHELL_CMD_ARG(show-db, NULL, "[uuid] [num_matches]", cmd_show_db, 1, 2),
	SHELL_CMD_ARG(att_mtu, NULL, "Output ATT MTU size", cmd_att_mtu, 1, 0),
#if defined(CONFIG_BT_GATT_DYNAMIC_DB)
	SHELL_CMD_ARG(metrics, NULL, "[value: on, off]", cmd_metrics, 1, 1),
	SHELL_CMD_ARG(register, NULL,
		      "register pre-predefined test service",
		      cmd_register_test_svc, 1, 0),
	SHELL_CMD_ARG(unregister, NULL,
		      "unregister pre-predefined test service",
		      cmd_unregister_test_svc, 1, 0),
	SHELL_CMD_ARG(notify, NULL, "[data]", cmd_notify, 1, 1),
#endif /* CONFIG_BT_GATT_DYNAMIC_DB */
	SHELL_SUBCMD_SET_END
);

static int cmd_gatt(const struct shell *shell, size_t argc, char **argv)
{
	if (argc == 1) {
		shell_help(shell);
		/* shell returns 1 when help is printed */
		return 1;
	}

	shell_error(shell, "%s unknown parameter: %s", argv[0], argv[1]);

	return -EINVAL;
}

SHELL_CMD_ARG_REGISTER(gatt, &gatt_cmds, "Bluetooth GATT shell commands",
		       cmd_gatt, 1, 1);
