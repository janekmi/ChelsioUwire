#ifndef CLICK_ERROR_HH
#define CLICK_ERROR_HH

#include <stdio.h>
#include <stdarg.h>
#include <errno.h>

class ErrorHandler {
public: 
    ErrorHandler() : _nerrors(0), _nwarnings(0), _prefix(0) { }
    ~ErrorHandler() { }

    unsigned int nwarnings() const { return _nwarnings; }
    unsigned int nerrors() const { return _nerrors; }
    void reset_counts() { _nerrors = _nwarnings = 0; }

    void snap_errors() { _nerrors_snapshot = _nerrors; }
    bool any_errors() { return _nerrors_snapshot != _nerrors; }

    void set_prefix(const char *pfx) { _prefix = pfx; }

    inline void warning(const char *format, ...);
    inline int error(const char *format, ...);

private:
    unsigned int _nerrors;
    unsigned int _nwarnings;
    unsigned int _nerrors_snapshot;
    const char *_prefix;
};

void ErrorHandler::warning(const char *format, ...)
{
    va_list ap;

    if (_prefix)
	fprintf(stderr, "%s: ", _prefix);
    va_start(ap, format);
    vfprintf(stderr, format, ap);
    fprintf(stderr, "\n");
    va_end(ap);
    _nwarnings++;
}

int ErrorHandler::error(const char *format, ...)
{
    va_list ap;

    if (_prefix)
	fprintf(stderr, "%s: ", _prefix);
    va_start(ap, format);
    vfprintf(stderr, format, ap);
    fprintf(stderr, "\n");
    va_end(ap);
    _nerrors++;
    return -EINVAL;
}
#endif

/* vim: set ts=8 sw=4: */
