// SPDX-License-Identifier: GPL-2.0-only
/* Resolve the BTF IDs emitted into the final vmlinux image. */

#define _GNU_SOURCE

#include <elf.h>
#include <errno.h>
#include <fcntl.h>
#include <gelf.h>
#include <libelf.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <linux/btf.h>

#ifndef BTF_KIND_FUNC
#define BTF_KIND_FUNC 12
#define BTF_KIND_FUNC_PROTO 13
#define BTF_KIND_VAR 14
#define BTF_KIND_DATASEC 15
#define BTF_KIND_FLOAT 16
#define BTF_KIND_DECL_TAG 17
#define BTF_KIND_TYPE_TAG 18
#define BTF_KIND_ENUM64 19
#endif

#undef BTF_INFO_KIND
#define BTF_INFO_KIND(info) (((info) >> 24) & 0x1f)

#define BTF_IDS_SECTION ".BTF_ids"
#define BTF_SECTION ".BTF"
#define BTF_ID_PREFIX "__BTF_ID__"

enum id_kind {
	ID_STRUCT,
	ID_UNION,
	ID_TYPEDEF,
	ID_FUNC,
};

struct id_entry {
	char *name;
	enum id_kind kind;
	uint32_t id;
	uint64_t *addresses;
	size_t address_count;
	size_t address_capacity;
};

struct id_set {
	uint64_t address;
	uint64_t size;
};

struct object {
	int fd;
	Elf *elf;
	Elf_Data *ids;
	Elf_Data *btf;
	Elf_Data *symbols;
	GElf_Shdr ids_shdr;
	GElf_Shdr symbols_shdr;
	size_t ids_shndx;
	size_t symbols_shndx;
	size_t strtab_shndx;
	struct id_entry *entries;
	size_t entry_count;
	size_t entry_capacity;
	struct id_set *sets;
	size_t set_count;
	size_t set_capacity;
};

static char *copy_string(const char *start, size_t length)
{
	char *copy = malloc(length + 1);

	if (!copy)
		return NULL;
	memcpy(copy, start, length);
	copy[length] = '\0';
	return copy;
}

static int grow_array(void **array, size_t *capacity, size_t item_size,
			     size_t count)
{
	void *new_array;
	size_t new_capacity;

	if (count <= *capacity)
		return 0;
	new_capacity = *capacity ? *capacity * 2 : 32;
	while (new_capacity < count)
		new_capacity *= 2;
	new_array = realloc(*array, new_capacity * item_size);
	if (!new_array)
		return -ENOMEM;
	*array = new_array;
	*capacity = new_capacity;
	return 0;
}

static struct id_entry *find_entry(struct object *obj, enum id_kind kind,
				   const char *name)
{
	size_t i;

	for (i = 0; i < obj->entry_count; i++)
		if (obj->entries[i].kind == kind &&
		    !strcmp(obj->entries[i].name, name))
			return &obj->entries[i];
	return NULL;
}

static struct id_entry *get_entry(struct object *obj, enum id_kind kind,
				  const char *name)
{
	struct id_entry *entry;

	entry = find_entry(obj, kind, name);
	if (entry)
		return entry;
	if (grow_array((void **)&obj->entries, &obj->entry_capacity,
		       sizeof(*obj->entries), obj->entry_count + 1))
		return NULL;
	entry = &obj->entries[obj->entry_count++];
	memset(entry, 0, sizeof(*entry));
	entry->name = strdup(name);
	if (!entry->name) {
		obj->entry_count--;
		return NULL;
	}
	entry->kind = kind;
	return entry;
}

static int add_address(struct id_entry *entry, uint64_t address)
{
	if (grow_array((void **)&entry->addresses, &entry->address_capacity,
		       sizeof(*entry->addresses), entry->address_count + 1))
		return -ENOMEM;
	entry->addresses[entry->address_count++] = address;
	return 0;
}

static int parse_id_name(const char *symbol, enum id_kind *kind,
				char **name)
{
	const char *type;
	const char *type_end;
	const char *name_start;
	const char *name_end;

	if (strncmp(symbol, BTF_ID_PREFIX, strlen(BTF_ID_PREFIX)))
		return 0;
	type = symbol + strlen(BTF_ID_PREFIX);
	type_end = strstr(type, "__");
	if (!type_end)
		return -EINVAL;
	if (!strncmp(type, "struct", type_end - type))
		*kind = ID_STRUCT;
	else if (!strncmp(type, "union", type_end - type))
		*kind = ID_UNION;
	else if (!strncmp(type, "typedef", type_end - type))
		*kind = ID_TYPEDEF;
	else if (!strncmp(type, "func", type_end - type))
		*kind = ID_FUNC;
	else
		return -EINVAL;

	name_start = type_end + 2;
	name_end = strrchr(name_start, '_');
	if (!name_end || name_end == name_start || name_end[-1] != '_')
		return -EINVAL;
	name_end--;
	*name = copy_string(name_start, name_end - name_start);
	return *name ? 1 : -ENOMEM;
}

static int collect_sections(struct object *obj)
{
	Elf_Scn *scn = NULL;
	size_t shstrndx;
	size_t index = 0;

	if (elf_getshdrstrndx(obj->elf, &shstrndx))
		return -EINVAL;
	while ((scn = elf_nextscn(obj->elf, scn))) {
		GElf_Shdr shdr;
		const char *name;
		Elf_Data *data;

		index++;
		if (gelf_getshdr(scn, &shdr) != &shdr)
			return -EINVAL;
		name = elf_strptr(obj->elf, shstrndx, shdr.sh_name);
		data = elf_getdata(scn, NULL);
		if (!name || !data)
			return -EINVAL;
		if (!strcmp(name, BTF_IDS_SECTION)) {
			obj->ids = data;
			obj->ids_shdr = shdr;
			obj->ids_shndx = index;
		} else if (!strcmp(name, BTF_SECTION)) {
			obj->btf = data;
		} else if (shdr.sh_type == SHT_SYMTAB) {
			obj->symbols = data;
			obj->symbols_shdr = shdr;
			obj->symbols_shndx = index;
			obj->strtab_shndx = shdr.sh_link;
		}
	}
	return 0;
}

static int collect_symbols(struct object *obj)
{
	GElf_Sym symbol;
	size_t count;
	size_t i;

	if (!obj->ids || !obj->symbols)
		return 0;
	count = obj->symbols_shdr.sh_size / obj->symbols_shdr.sh_entsize;
	for (i = 0; i < count; i++) {
		const char *name;
		enum id_kind kind;
		char *id_name;
		struct id_entry *entry;
		int parsed;

		if (!gelf_getsym(obj->symbols, i, &symbol))
			return -EINVAL;
		if (symbol.st_shndx != obj->ids_shndx)
			continue;
		name = elf_strptr(obj->elf, obj->strtab_shndx, symbol.st_name);
		if (!name)
			return -EINVAL;
		if (!strncmp(name, BTF_ID_PREFIX "set__", strlen(BTF_ID_PREFIX "set__"))) {
			if (grow_array((void **)&obj->sets, &obj->set_capacity,
				       sizeof(*obj->sets), obj->set_count + 1))
				return -ENOMEM;
			obj->sets[obj->set_count].address =
				symbol.st_value - obj->ids_shdr.sh_addr;
			obj->sets[obj->set_count].size = symbol.st_size;
			obj->set_count++;
			continue;
		}
		parsed = parse_id_name(name, &kind, &id_name);
		if (parsed <= 0)
			continue;
		entry = get_entry(obj, kind, id_name);
		free(id_name);
		if (!entry || add_address(entry,
				symbol.st_value - obj->ids_shdr.sh_addr))
			return -ENOMEM;
	}
	return 0;
}

static size_t btf_extra_size(unsigned int kind, unsigned int vlen)
{
	switch (kind) {
	case BTF_KIND_INT:
		return 4;
	case BTF_KIND_ARRAY:
		return 12;
	case BTF_KIND_STRUCT:
	case BTF_KIND_UNION:
		return (size_t)vlen * 12;
	case BTF_KIND_ENUM:
		return (size_t)vlen * 8;
	case BTF_KIND_FUNC_PROTO:
		return (size_t)vlen * 8;
	case BTF_KIND_VAR:
		return 4;
	case BTF_KIND_DECL_TAG:
		return 4;
	case BTF_KIND_DATASEC:
		return (size_t)vlen * 12;
	case BTF_KIND_ENUM64:
		return (size_t)vlen * 12;
	default:
		return 0;
	}
}

static int btf_kind_for_id(enum id_kind kind)
{
	switch (kind) {
	case ID_STRUCT:
		return BTF_KIND_STRUCT;
	case ID_UNION:
		return BTF_KIND_UNION;
	case ID_TYPEDEF:
		return BTF_KIND_TYPEDEF;
	case ID_FUNC:
		return BTF_KIND_FUNC;
	}
	return -1;
}

static int resolve_btf(struct object *obj)
{
	struct btf_header header;
	const unsigned char *base;
	const char *strings;
	size_t offset;
	size_t type_end;
	uint32_t type_id = 1;
	unsigned int previous_kind = 0, previous_vlen = 0;
	size_t previous_offset = 0;

	if (!obj->btf) {
		fprintf(stderr, "resolve_btfids: no BTF section\n");
		return -EINVAL;
	}
	if (obj->btf->d_size < sizeof(header)) {
		fprintf(stderr, "resolve_btfids: BTF section too small\n");
		return -EINVAL;
	}
	memcpy(&header, obj->btf->d_buf, sizeof(header));
	if (header.magic != BTF_MAGIC ||
	    header.hdr_len + header.type_off + header.type_len > obj->btf->d_size ||
	    header.hdr_len + header.str_off + header.str_len > obj->btf->d_size) {
		fprintf(stderr, "resolve_btfids: invalid BTF header magic=%#x hdr=%u type=%u+%u str=%u+%u size=%zu\n",
			header.magic, header.hdr_len, header.type_off,
			header.type_len, header.str_off, header.str_len,
			obj->btf->d_size);
		return -EINVAL;
	}
	base = (const unsigned char *)obj->btf->d_buf + header.hdr_len;
	strings = (const char *)(base + header.str_off);
	offset = header.type_off;
	type_end = offset + header.type_len;

	while (offset + sizeof(struct btf_type) <= type_end) {
		struct btf_type type;
		unsigned int kind;
		unsigned int vlen;
		const char *name;
		size_t extra;
		size_t i;

		memcpy(&type, base + offset, sizeof(type));
		kind = BTF_INFO_KIND(type.info);
		vlen = BTF_INFO_VLEN(type.info);
		if (type.name_off >= header.str_len) {
			fprintf(stderr, "resolve_btfids: invalid BTF string offset=%u at type=%u offset=%zu kind=%u vlen=%u type=%u previous kind=%u vlen=%u offset=%zu\n",
				type.name_off, type_id, offset, kind, vlen, type.type,
				previous_kind, previous_vlen, previous_offset);
			return -EINVAL;
		}
		name = strings + type.name_off;
		extra = btf_extra_size(kind, vlen);
		if (offset + sizeof(type) + extra > type_end) {
			fprintf(stderr, "resolve_btfids: invalid BTF type layout kind=%u vlen=%u type=%u offset=%zu extra=%zu end=%zu\n",
				kind, vlen, type_id, offset, extra, type_end);
			return -EINVAL;
		}
		for (i = 0; i < obj->entry_count; i++) {
			struct id_entry *entry = &obj->entries[i];

			if (!entry->id && entry->kind != ID_FUNC &&
			    kind == btf_kind_for_id(entry->kind) &&
			    !strcmp(entry->name, name))
				entry->id = type_id;
			else if (!entry->id && entry->kind == ID_FUNC &&
				 kind == BTF_KIND_FUNC && !strcmp(entry->name, name))
				entry->id = type_id;
		}
		offset += sizeof(type) + extra;
		previous_kind = kind;
		previous_vlen = vlen;
		previous_offset = offset;
		type_id++;
	}
	if (offset != type_end) {
		fprintf(stderr, "resolve_btfids: invalid BTF type tail\n");
		return -EINVAL;
	}
	return 0;
}

static int int_compare(const void *left, const void *right)
{
	uint32_t a;
	uint32_t b;

	memcpy(&a, left, sizeof(a));
	memcpy(&b, right, sizeof(b));
	return a > b ? 1 : a < b ? -1 : 0;
}

static int patch_ids(struct object *obj)
{
	unsigned char *data = obj->ids->d_buf;
	size_t i;

	for (i = 0; i < obj->entry_count; i++) {
		struct id_entry *entry = &obj->entries[i];
		size_t j;

		if (!entry->id) {
			fprintf(stderr, "resolve_btfids: warning: unresolved %s, leaving unused\n",
				entry->name);
			continue;
		}
		for (j = 0; j < entry->address_count; j++) {
			uint32_t id = entry->id;
			if (entry->addresses[j] + sizeof(id) > obj->ids->d_size)
				return -EINVAL;
			memcpy(data + entry->addresses[j], &id, sizeof(id));
		}
	}

	for (i = 0; i < obj->set_count; i++) {
		struct id_set *set = &obj->sets[i];
		uint32_t expected = set->size / sizeof(uint32_t) - 1;
		uint32_t *values;

		if (set->address + set->size > obj->ids->d_size || !expected) {
			fprintf(stderr, "resolve_btfids: invalid BTF ID set\n");
			return -EINVAL;
		}
		values = malloc(expected * sizeof(*values));
		if (!values)
			return -ENOMEM;
		memcpy(values, data + set->address + sizeof(uint32_t),
		       expected * sizeof(*values));
		qsort(values, expected, sizeof(*values), int_compare);
		memcpy(data + set->address + sizeof(uint32_t), values,
		       expected * sizeof(*values));
		memcpy(data + set->address, &expected, sizeof(expected));
		free(values);
	}
	elf_flagdata(obj->ids, ELF_C_SET, ELF_F_DIRTY);
	if (elf_update(obj->elf, ELF_C_WRITE) < 0) {
		fprintf(stderr, "resolve_btfids: ELF write failed: %s\n",
			elf_errmsg(-1));
		return -EINVAL;
	}
	return 0;
}

static void cleanup(struct object *obj)
{
	size_t i;

	for (i = 0; i < obj->entry_count; i++) {
		free(obj->entries[i].name);
		free(obj->entries[i].addresses);
	}
	free(obj->entries);
	free(obj->sets);
	if (obj->elf)
		elf_end(obj->elf);
	if (obj->fd >= 0)
		close(obj->fd);
}

int main(int argc, char **argv)
{
	struct object obj;
	int result = 1;

	if (argc != 2) {
		fprintf(stderr, "usage: %s vmlinux\n", argv[0]);
		return 2;
	}
	memset(&obj, 0, sizeof(obj));
	obj.fd = -1;
	if (elf_version(EV_CURRENT) == EV_NONE)
		return 1;
	obj.fd = open(argv[1], O_RDWR);
	if (obj.fd < 0)
		return 1;
	obj.elf = elf_begin(obj.fd, ELF_C_RDWR_MMAP, NULL);
	if (!obj.elf)
		goto out;
	elf_flagelf(obj.elf, ELF_C_SET, ELF_F_LAYOUT);
	if (collect_sections(&obj)) {
		fprintf(stderr, "resolve_btfids: section collection failed\n");
		goto out;
	}
	if (!obj.ids || !obj.symbols || !obj.btf) {
		fprintf(stderr, "resolve_btfids: required ELF section missing\n");
		goto out;
	}
	if (collect_symbols(&obj)) {
		fprintf(stderr, "resolve_btfids: symbol collection failed\n");
		goto out;
	}
	if (resolve_btf(&obj)) {
		fprintf(stderr, "resolve_btfids: BTF resolution failed\n");
		goto out;
	}
	if (patch_ids(&obj)) {
		fprintf(stderr, "resolve_btfids: ID patch failed\n");
		goto out;
	}
	result = 0;
out:
	cleanup(&obj);
	return result;
}
