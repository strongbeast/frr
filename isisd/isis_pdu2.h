#ifndef ISIS_PDU2_H
#define ISIS_PDU2_H

struct isis_pdu;

struct isis_pdu *isis_alloc_pdu(uint8_t pdu_type, uint8_t hdr_len,
                                size_t size);
int isis_start_pdu(struct isis_pdu *pdu);
void isis_mark_pdu_lifetime(struct isis_pdu *pdu);
void isis_mark_pdu_checksum(struct isis_pdu *pdu);
void isis_mark_pdu_auth_data(struct isis_pdu *pdu);
void isis_calculate_pdu_auth(struct isis_pdu *pdu);

#endif
