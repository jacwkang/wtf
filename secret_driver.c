#include <minix/drivers.h>
#include <minix/driver.h>
#include <stdio.h>
#include <stdlib.h>
#include <minix/ds.h>
#include <sys/ucred.h> // include for ucred struct

#define NO_OWNER -1
#define SECRET_SIZE 8912

// secretkeeper holds the secret
static void *secretkeeper;
static uid_t owner;
static int openFDs; /* this is a counter of open fd's */
/*
 *  * Function prototypes for the secret driver.
 *   */
FORWARD _PROTOTYPE( char * secret_name,   (void) );
FORWARD _PROTOTYPE( int secret_open,      (struct driver *d, message *m) );
FORWARD _PROTOTYPE( int secret_close,     (struct driver *d, message *m) );
FORWARD _PROTOTYPE( struct device * secret_prepare, (int device) );
FORWARD _PROTOTYPE( int secret_transfer,  (int procnr, int opcode,
                                          u64_t position, iovec_t *iov,
                                          unsigned nr_req) );
FORWARD _PROTOTYPE( void secret_geometry, (struct partition *entry) );
FORWARD _PROTOTYPE( int secret_prepare, (struct driver *d, message *m) );
FORWARD _PROTOTYPE( int ioctl, (struct driver *d, message *m) );

/* SEF functions and variables. */
FORWARD _PROTOTYPE( void sef_local_startup, (void) );
FORWARD _PROTOTYPE( int sef_cb_init, (int type, sef_init_info_t *info) );
FORWARD _PROTOTYPE( int sef_cb_lu_state_save, (int) );
FORWARD _PROTOTYPE( int lu_state_restore, (void) );

/* Allows owner of a secret to change ownership to another user */
PRIVATE int ioctl (message *m) {
   int returnValue;
   struct ucred credential;
   uid_t grantee; /* the uid of the new owner of the secret */
   res = sys_safecopyfrom(m->IO_ENDPT, (vir_bytes)m->IO_GRANT,
      0, (vir_bytes)&grantee, sizeof(grantee), D);
   
   
   returnValue = getnucred(m->USER_ENDPT, &credential);
   
   /* Ensure that getnucred did not break */
   if (returnValue != -1) {
      
   }

   return i;
}


/* Entry points to the secret driver. */
PRIVATE struct driver secret_tab =
{
    secret_name,
    secret_open,
    secret_close,
    nop_ioctl,
    secret_prepare,
    secret_transfer,
    nop_cleanup,
    secret_geometry,
    nop_alarm,
    nop_cancel,
    nop_select,
    nop_ioctl,
    do_nop,
};

/** Represents the /dev/secret device. */
PRIVATE struct device secret_device;

/** State variable to count the number of times the device has been opened. */
PRIVATE int open_counter;

PRIVATE char * secret_name(void)
{
    printf("secret_name()\n");
    return "secret";
}

PRIVATE int secret_open(message *m)
{
    struct ucred process_owner; /* has info of process trying to open secret */

    getnucred(m->USER_ENDPT, &process_owner);

    /* if there is no current owner */
    if (owner == NO_OWNER) {
        switch (m->COUNT) {
            case O_WRONLY:
                /* get uid of calling process and set owner */
                owner = secret_owner.uid;
                openFDs++;

            case O_RDONLY:
                openFDs++;

            case O_RDWR:
                printf("Permission denied");
                return EACCES;
        }
    }
    /* if secret is full */
    else {
        switch (m->COUNT) {
            case O_WRONLY:
                printf("cannot create /dev/Secret: No space left on device");
                return ENOSPC;

            case O_RDWR:
                printf("Permission denied");
                return EACCES;

            case O_RDONLY:
                /* if the process trying to open is not the secret owner */
                if (owner != process_owner) {
                    printf("Permission denied: secret is owned by process %d", owner);
                    return EACCES;
                }
                else {
                    /* You must keep track of how many open file descriptors 
                     * there are, however, because the secret resets when the 
                     * last file descriptor closes after a read file descriptor
                     * has been opened */
                    openFDs++; 
                }
        }
    }

    return OK;
}

PRIVATE int secret_close(message *m)
{
    
    return OK;
}

PRIVATE struct device * secret_prepare(dev)
    int dev;
{
    secret_device.dv_base.lo = 0;
    secret_device.dv_base.hi = 0;
    secret_device.dv_size.lo = SECRET_SIZE;
    secret_device.dv_size.hi = 0;
    return &secret_device;
}

PRIVATE int secret_transfer(proc_nr, opcode, position, iov, nr_req)
    int proc_nr;
    int opcode;
    u64_t position;
    iovec_t *iov;
    unsigned nr_req;
{
    int bytes, ret;

    printf("secret_transfer()\n");

    bytes = SECRET_SIZE - position.lo < iov->iov_size ?
            SECRET_SIZE - position.lo : iov->iov_size;

    if (bytes <= 0)
    {
        return OK;
    }
    switch (opcode)
    {
        case DEV_GATHER_S:
            ret = sys_safecopyto(proc_nr, iov->iov_addr, 0,
                                (vir_bytes) (HELLO_MESSAGE + position.lo),
                                 bytes, D);
            iov->iov_size -= bytes;
            break;

        default:
            return EINVAL;
    }
    return ret;
}

PRIVATE void secret_geometry(entry)
    struct partition *entry;
{
    printf("secret_geometry()\n");
    entry->cylinders = 0;
    entry->heads     = 0;
    entry->sectors   = 0;
}

PRIVATE int sef_cb_lu_state_save(int state) {
/* Save the state. */
    ds_publish_u32("open_counter", open_counter, DSF_OVERWRITE);

    return OK;
}

PRIVATE int lu_state_restore() {
/* Restore the state. */
    u32_t value;

    ds_retrieve_u32("open_counter", &value);
    ds_delete_u32("open_counter");
    open_counter = (int) value;

    return OK;
}

PRIVATE void sef_local_startup()
{
    /*
     * Register init callbacks. Use the same function for all event types
     */
    sef_setcb_init_fresh(sef_cb_init);
    sef_setcb_init_lu(sef_cb_init);
    sef_setcb_init_restart(sef_cb_init);

    /*
     * Register live update callbacks.
     */
    /* - Agree to update immediately when LU is requested in a valid state. */
    sef_setcb_lu_prepare(sef_cb_lu_prepare_always_ready);
    /* - Support live update starting from any standard state. */
    sef_setcb_lu_state_isvalid(sef_cb_lu_state_isvalid_standard);
    /* - Register a custom routine to save the state. */
    sef_setcb_lu_state_save(sef_cb_lu_state_save);

    /* Let SEF perform startup. */
    sef_startup();
}

PRIVATE int sef_cb_init(int type, sef_init_info_t *info)
{
/* Initialize the secret driver. */
    int do_announce_driver = TRUE;

    owner = NO_OWNER;
    secretkeeper = malloc(SECRET_SIZE);
    openFDs = 0;

    open_counter = 0;
    switch(type) {
        case SEF_INIT_FRESH:
            printf("%s", HELLO_MESSAGE);
        break;

        case SEF_INIT_LU:
            /* Restore the state. */
            lu_state_restore();
            do_announce_driver = FALSE;

            printf("%sHey, I'm a new version!\n", HELLO_MESSAGE);
        break;

        case SEF_INIT_RESTART:
            printf("%sHey, I've just been restarted!\n", HELLO_MESSAGE);
        break;
    }

    /* Announce we are up when necessary. */
    if (do_announce_driver) {
        driver_announce();
    }

    /* Initialization completed successfully. */
    return OK;
}

PUBLIC int main(int argc, char **argv)
{
   // int owner = NO_OWNER; -> i moved this line to the init function
   
    /*
     * Perform initialization.
     */
    sef_local_startup();

    /*
     * Run the main loop.
     */
    driver_task(&secret_tab, DRIVER_STD);
    return OK;
}

