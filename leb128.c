#include "leb128.h"

// ceil(sizeof(uintptr_t) * 8 / 7)
// = (sizeof(uintptr_t) * 8 + sizeof(uintptr_t) - 1) / 7
#define MAX_CODES ((sizeof(uintptr_t) * 9 - 1) / 7)

uint8_t uleb128_bytes(uintptr_t value) {
	int i = 0;
	for (i = 0; i < MAX_CODES; i++) {
		if (value < 128) {
			i++;
			break;
		} else {
			value = value >> 7;
		}
	}
	return i;
}

uint8_t uleb128_encode(uintptr_t value, uint8_t *data) {
	int i = 0;
	for (i = 0; i < MAX_CODES; i++) {
		if (value < 128) {
			data[i] = value;
			i++;
			break;
		} else {
			data[i] = (value & 127) | 128;
			value = value >> 7;
		}
	}
	return i;
}

uvalue_size uleb128_decode(uint8_t *data) {
	uvalue_size ret = {.value = 0};
	for (ret.size = 0; ret.size < MAX_CODES; ret.size++) {
		uintptr_t shift = 7 * ret.size;
		uintptr_t continue_bit = 128llu << shift;
		ret.value |= (uintptr_t)data[ret.size] << shift;
		if ((ret.value & continue_bit) == 0) {
			ret.size++;
			break;
		} else {
			ret.value &= ~continue_bit;
		}
	}
	return ret;
}

uint8_t leb128_bytes(intptr_t value) {
	_Static_assert((-1 >> 1) == -1, "Shift is not arithmetic");
	int i = 0;
	for (i = 0; i < MAX_CODES; i++) {
		if (-64 <= value && value < 64) {
			i++;
			break;
		} else {
			value = value >> 7;
		}
	}
	return i;
}

uint8_t leb128_encode(intptr_t value, uint8_t *data) {
	_Static_assert((-1 >> 1) == -1, "Shift is not arithmetic");
	int i = 0;
	for (i = 0; i < MAX_CODES; i++) {
		if (-64 <= value && value < 64) {
			data[i] = value & 127;
			i++;
			break;
		} else {
			data[i] = (value & 127) | 128;
			value = value >> 7;
		}
	}
	return i;
}

value_size leb128_decode(uint8_t *data) {
	value_size ret = {.value = 0};
	for (ret.size = 0; ret.size < MAX_CODES; ret.size++) {
		intptr_t shift = 7 * ret.size;
		intptr_t continue_bit = 128llu << shift;
		ret.value |= (intptr_t)data[ret.size] << shift;
		if ((ret.value & continue_bit) == 0) {
			// Sign extend
			ret.value |= ((ret.value << 1) & continue_bit) * ~0llu;
			ret.size++;
			break;
		} else {
			ret.value &= ~continue_bit;
		}
	}
	return ret;
}
