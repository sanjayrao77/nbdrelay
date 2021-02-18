
#ifdef DEBUG
#ifdef _SYS_SYSLOG_H
#define GOTOERROR do { syslog(LOG_ERR,"-DDEBUG Error in %s:%d %s",__FILE__,__LINE__,__FUNCTION__); goto error; } while (0)
// #define GOTOERROR do { fprintf(stderr,"Error in %s:%d %s\n",__FILE__,__LINE__,__FUNCTION__); goto error; } while (0)
#else
#define GOTOERROR do { fprintf(stderr,"-DDEBUG Error in %s:%d %s\n",__FILE__,__LINE__,__FUNCTION__); goto error; } while (0)
#endif
#define WHEREAMI do { fprintf(stderr,"%s:%d %s DEBUG STAMP\n",__FILE__,__LINE__,__FUNCTION__); } while (0)
#define DEBUGOUT(a) fprintf a
#else
#define GOTOERROR do { goto error; } while (0)
#define WHEREAMI do{}while(0)
#define DEBUGOUT(a) do{}while(0)
#endif

#ifdef DEBUG2
#define D2WHEREAMI do { fprintf(stderr,"%s:%d DEBUG STAMP\n",__FILE__,__LINE__); } while (0)
#else
#define D2WHEREAMI do{}while(0)
#endif

#define HERE do { fprintf(stderr,"%s:%d %s DEBUG STAMP\n",__FILE__,__LINE__,__FUNCTION__); } while (0)

typedef void ignore;

#define CLEARFUNC(a) void clear_##a(struct a *dest) { static struct a blank; memcpy(dest,&blank,sizeof(struct a)); }
#define SCLEARFUNC(a) static CLEARFUNC(a)
#define SICLEARFUNC(a) static inline CLEARFUNC(a)
#define H_CLEARFUNC(a) void clear_##a(struct a *dest)
#define ignore_ifclose(a) do { if (a!=-1) close(a); } while (0)
#define ignore_iffclose(a) do { if (a) fclose(a); } while (0)
#define iffree(a) do { if (a) free(a); } while (0)
#define ifclose(a) do { if (a!=-1) close(a); } while (0)
#define iffclose(a) do { if (a) fclose(a); } while (0)
#define iffputs(a,b) do { if (b) fputs(a,b); } while (0)
#define _BADMIN(a,b) ((a<=b)?a:b)
#define _BADMAX(a,b) ((a>=b)?a:b)
#define _FASTCMP(a,b) ((a>b)-(a<b))

#define ZTMALLOC(n,t) ({ t *_p; _p=malloc((n)*sizeof(t)); if (_p) memset(_p,0,(n)*sizeof(t)); _p; })

// normally blank is MAP_FAILED==-1 but we often use 0
#define ifmunmap(a,b) do { if (a>0) munmap(a,b); } while (0)
