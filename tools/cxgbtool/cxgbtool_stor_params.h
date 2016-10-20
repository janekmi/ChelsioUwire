#ifndef _CXGBTOOL_STOR_PARAMS_H_
#define _CXGBTOOL_STOR_PARAMS_H_

enum {
        V_DSIO,         /* DataSequenceInOrder  */
        V_DPIO,         /* DataPDUInOrder       */
        V_IFMARKER,     /* IFMarker             */
        V_OFMARKER,     /* OFMarker             */
        V_MAXCONN,      /* MaxConnections       */
        V_ERL,          /* ErrorRecoveryLevel   */
        V_LOGINRETRY,   /* LoginRetryCount      */
        V_INITR2T,      /* InitialR2T           */
        V_MAXR2T,       /* MaxOutstandingR2T    */
        V_FSTBL,        /* FirstBurstLength     */
        V_MAXBL,        /* MaxBurstLength       */
        V_MAXRDSL,      /* MaxRecvDataSegmentLength             */
        V_CMDSMAX,      /* CommandsMax          */
        V_IDATA,        /* ImmediateData        */
        V_T2W,          /* DefaultTime2Wait     */
        V_T2R,          /* DefaultTime2Retain   */
        V_LITMO,        /* LoginTimeout         */
        V_LOTMO,        /* LogoutTimeout        */
        V_NOOPI,        /* NoopOutInterval      */
        V_NOOPT,        /* NoopOutTimeout       */
        V_DACK,         /* DelayedAck           */
        V_RCVTMO,       /* RecoveryTimeout      */
        V_PINGTMO,      /* PingTimeout          */
        V_HDGST,        /* HeaderDigest         */
        V_DGGST,        /* DataDigest           */
        V_AUTHPOL,      /* AuthPolicy           */
        V_AUTHM,        /* AuthMethod           */
        V_LURTMO,       /* LunResetTimeout      */
        V_ABORTTMO,     /* AbortTimeout         */
        V_MTU,          /* MTU                  */

        V_PARAM_MAX,
};

enum {
        val_def,
        val_min,
        val_max,
        val_set,
};

enum { NO, YES };

char val_string[][3] = { "No", "Yes"};

static int param_set[V_PARAM_MAX][4] = {
/*        default,      min,    max,            settable */
        { YES,          NO,     YES,            YES},   /* DataSequenceInOrder  */
        { YES,          NO,     YES,            YES},   /* DataPDUInOrder       */
        { 0,            0,      0,              NO},    /* IFMarker             */
        { 0,            0,      0,              NO},    /* OFMarker             */
        { 1,            1,      65535,          YES},   /* MaxConnections       */
        { 0,            0,      2,              YES},   /* ErrorRecoveryLevel   */
        { 10,           0,      10,             YES},   /* LoginRetryCount      */
        { YES,          NO,     YES,            YES},   /* InitialR2T           */
        { 1,            1,      65535,          YES},   /* MaxOutstandingR2T    */
        { 262144,       512,    16777215,       YES},   /* FirstBurstLength     */
        { 16776192,     512,    16777215,       YES},   /* MaxBurstLength       */
        { 8192,         512,    16000,          YES},   /* MaxRecvDataSegmentLength             */
        { 0,            0,      0,              NO},    /* CommandsMax          */
        { YES,          NO,     YES,            YES},   /* ImmediateData        */
        { 20,           0,      3600,           YES},   /* DefaultTime2Wait     */
        { 20,           0,      3600,           YES},   /* DefaultTime2Retain   */
        { 0,            0,      0,              NO},    /* LoginTimeout         */
        { 0,            0,      0,              NO},    /* LogoutTimeout        */
        { 0,            0,      0,              NO},    /* NoopOutInterval      */
        { 0,            0,      0,              NO},    /* NoopOutTimeout       */
        { 0,            0,      0,              NO},    /* DelayedAck           */
        { 16,           0,      255,            YES},   /* RecoveryTimeout      */
        { 15,           0,      300,            YES},   /* PingTimeout          */
        { 3,            0,      3,              YES},   /* HeaderDigest         */
        { 3,            0,      3,              YES},   /* DataDigest           */
        { 0,            0,      1,              YES},   /* AuthPolicy           */
        { 0,            0,      3,              YES},   /* AuthMethod           */
        { 0,            0,      0,              YES},   /* LunResetTimeout      */
        { 0,            0,      0,              YES},   /* AbortTimeout         */
        { 1500,         1500,   9600,           YES},   /* MTU                  */
};

#endif /* _CXGBTOOL_STOR_PARAMS_H_ */
