/**
 * @file: helper.h
 * @brief: just to keep the main header file clean
 * 
 * DATE     2026-10-26
 */

/* helpers*/
/* Write Varint — encodes val, advances pos, returns error on overflow */
#define WV(val)                                                           \
    do {                                                                  \
        int _n = ql_varint_encode(buf + pos, cap - pos, (uint64_t)(val)); \
        if (_n < 0)                                                       \
            return _n;                                                    \
        pos += (size_t)_n;                                                \
    } while (0)
/* Write Bytes — copies raw bytes, advances pos, returns error on overflow */
#define WB(ptr, len)                  \
    do {                              \
        size_t _l = (size_t)(len);    \
        if (pos + _l > cap)           \
            return QLITE_ERR_BUF;     \
        memcpy(buf + pos, (ptr), _l); \
        pos += _l;                    \
    } while (0)

#define TP_VARINT(id, val)                                    \
    do {                                                      \
        if (tp_write_varint(buf, &pos, cap, (id), (val)) < 0) \
            return QLITE_ERR_BUF;                             \
    } while (0)
#define TP_BYTES(id, data, len)                                      \
    do {                                                             \
        if (tp_write_bytes(buf, &pos, cap, (id), (data), (len)) < 0) \
            return QLITE_ERR_BUF;                                    \
    } while (0)
#define TP_CID(id, cid)                                    \
    do {                                                   \
        if (tp_write_cid(buf, &pos, cap, (id), (cid)) < 0) \
            return QLITE_ERR_BUF;                          \
    } while (0)

#define RV(field)                                             \
    do {                                                      \
        ql_varint_t _v;                                       \
        int _n = ql_varint_decode(buf + pos, len - pos, &_v); \
        if (_n < 0 || pos + (size_t)_n > len)                 \
            return QLITE_ERR_BUF;                             \
        (field) = (__typeof__(field))_v;                      \
        pos += (size_t)_n;                                    \
    } while (0)

#define RB(dst, n)                    \
    do {                              \
        size_t _l = (size_t)(n);      \
        if (pos + _l > len)           \
            return QLITE_ERR_BUF;     \
        memcpy((dst), buf + pos, _l); \
        pos += _l;                    \
    } while (0)
