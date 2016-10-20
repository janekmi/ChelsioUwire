#ifndef __ISCSI_TEXT_PRIVATE_H__
#define __ISCSI_TEXT_PRIVATE_H__

#include <common/os_builtin.h>
#include <iscsi_text.h>

iscsi_keyval		 *iscsi_kvlist_alloc(int, iscsi_keydef *);
iscsi_string_pair	 *iscsi_string_pair_find_by_key(chiscsi_queue *, char *);

iscsi_value		 *iscsi_value_list_find_value(iscsi_value *, iscsi_value *);
iscsi_value		 *kv_find_value_by_field(iscsi_keyval *, iscsi_value *, int);

void    iscsi_kvlist_free(int, iscsi_keyval *);
int     iscsi_kvlist_fill_default(int, iscsi_keyval *);
int     iscsi_key_decode_kvq(int, int, chiscsi_queue *, iscsi_keyval *, int,
			     char *, int);
int     iscsi_value_list_remove_by_ptr(iscsi_value **, iscsi_value *);
void    iscsi_string_pair_free(iscsi_string_pair *);
//void	iscsi_pqirq_display(char *, chiscsi_queue *);

/* no all zero IPs */

int     iscsi_string_is_address_ipv6(char *);
int     iscsi_string_to_ip(char *buf, unsigned int *, char *, int);

int	kv_check_compute_list_selection(iscsi_keyval *, iscsi_keyval *);
int     kv_decode_response(int, char *, unsigned int *);
int     kv_encode_response(char *, unsigned int);
int     kv_size_response(unsigned int);

int     kv_decode_number_range(int, char *, iscsi_value *, char *);
int     kv_encode_number_range(char *, iscsi_value *);
int     kv_size_number_range(iscsi_value *);

int     kv_decode_boolean(int, char *, iscsi_value *, char *);
int     kv_encode_boolean(char *, iscsi_value *);
int     kv_size_boolean(iscsi_value *);

int     kv_compute_boolean_or(iscsi_keyval *, iscsi_keyval *);
int     kv_compute_boolean_and(iscsi_keyval *, iscsi_keyval *);
int	kv_check_compute_boolean_or(iscsi_keyval *, iscsi_keyval *);
int	kv_check_compute_boolean_and(iscsi_keyval *, iscsi_keyval *);

int     kv_decode_text(int, char *, iscsi_value *, char *);
int     kv_encode_text(char *, iscsi_value *);
int     kv_size_text(iscsi_value *);
int     kv_post_decode_check_str(iscsi_keyval *, iscsi_value *, char *);

int     kv_decode_number(int, char *, iscsi_value *, char *);
int     kv_encode_number(char *, iscsi_value *);
int     kv_size_number(iscsi_value *);

int     kv_compute_number_min(iscsi_keyval *, iscsi_keyval *);
int     kv_compute_number_max(iscsi_keyval *, iscsi_keyval *);
int     kv_check_compute_number_min(iscsi_keyval *, iscsi_keyval *);
int     kv_check_compute_number_max(iscsi_keyval *, iscsi_keyval *);

int     kv_calc_numeric_size(unsigned int);
int     kv_decode_numeric(int, char *, unsigned int *, char *);
int     kv_encode_numeric(char *, unsigned int);

int     kv_number_array_compare(unsigned char *, unsigned int, unsigned char *,
				unsigned int);
int     kv_decode_encoded_numeric(int, char *, iscsi_value *, char *);
int     kv_size_encoded_numeric(iscsi_value *);
int     kv_encode_encoded_numeric(char *, iscsi_value *);

#endif /* ifndef __ISCSI_TEXT_PRIVATE_H__ */
