
/* Read a record from the stream. */
void fetch_record (int cnx, uint8_t **buf, size_t *buflen);

/* Fetch the label contained in a record */
void record_label (uint8_t *recbuf, size_t recbuflen, uint8_t **label, size_t *labellen);
