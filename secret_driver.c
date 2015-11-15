#include <minix/drivers.h>
/*#include <minix/driver.h>*/
#include <minix/chardriver.h>
#include <stdio.h>
#include <stdlib.h>
#include <minix/ds.h>
#include <minix/syslib.h>
/*#include <sys/ioc_secret.h>*/
#include <sys/ucred.h>
/*#include <minix/ucred.h>
#include <minix/const.h>*/

#define NO_OWNER -1
#define O_WRONLY 2
#define O_RDONLY 4
#define O_RDWR 6
#define SECRET_SIZE 8912

/** Secretkeeper holds the secret */
static void *secretkeeper;
/* ID of the current owner */
static uid_t owner;
static int openFDs; /* this is a counter of open fd's */
/** Size of the current secret */
static int size;
/** Represents the /dev/secret device. */
struct device secret_device;
/** Flag to determine if device is currently being used */
int occupied;

/*
 * Function prototypes for the secret driver.
 */
FORWARD _PROTOTYPE( char * secret_name,   (void) );
FORWARD _PROTOTYPE( int secret_open,      (struct driver *d, message *m) );
FORWARD _PROTOTYPE( int secret_close,     (struct driver *d, message *m) );
FORWARD _PROTOTYPE( int ioctl, (struct driver *d, message *m) );
FORWARD _PROTOTYPE( struct device *secret_prepare, (int device) );
/*FORWARD _PROTOTYPE( struct device * secret_prepare, (int device) );*/
FORWARD _PROTOTYPE( int secret_transfer,  (int procnr, int opcode,
                                          u64_t position, iovec_t *iov,
                                          unsigned nr_req) );
FORWARD _PROTOTYPE( void secret_geometry, (struct partition *entry) );


/* SEF functions and variables. */
FORWARD _PROTOTYPE( void sef_local_startup, (void) );
FORWARD _PROTOTYPE( int sef_cb_init, (int type, sef_init_info_t *info) );
FORWARD _PROTOTYPE( int sef_cb_lu_state_save, (int) );
FORWARD _PROTOTYPE( int lu_state_restore, (void) );


/* Entry points to the secret driver. */
struct chardriver secret_tab =
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
    NULL
}


/* Allows owner of a secret to change ownership to another user */
PRIVATE int ioctl (struct driver *d, message *m) {
   int returnValue, res;
   struct ucred *credential = calloc(1, sizeof(struct ucred));
   
   uid_t grantee; /* the uid of the new owner of the secret */
   res = sys_safecopyfrom(m->IO_ENDPT, (vir_bytes)m->IO_GRANT,
    0, (vir_bytes)&grantee, sizeof(grantee), D);
   
   returnValue = getnucred(m->IO_ENDPT, credential);
   
   if (returnValue != -1) {
      owner = grantee;
      return OK;
   }

   return ENOTTY;
}

/** State variable to count the number of times the device has been opened. */
PRIVATE int open_counter;

PRIVATE char * secret_name(void)
{
    printf("secret_name()\n");
    return "secret";
}

PRIVATE int secret_open(struct driver *d, message *m)
{
    struct ucred process_owner; /* has info of process trying to open secret */

    getnucred(m->IO_ENDPT, &process_owner);

    /* if there is no current owner */
    if (owner == NO_OWNER) {
        switch (m->COUNT) {
            case O_WRONLY:
                /* get uid of calling process and set owner */
                owner = process_owner.uid;
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
                if (owner != process_owner.uid) {
                    printf("Permission denied: this secret is owned by another process");
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

PRIVATE int secret_close(struct driver *d, message *m)
{
    openFDs--;

    if (openFDs == 0) {
        owner = NO_OWNER;
        free(secretkeeper);
        secretkeeper = malloc(SECRET_SIZE);
    }

    return OK;
}

PRIVATE struct device *secret_prepare(int device)
{
    secret_device.dv_base.lo = 0;
    secret_device.dv_base.hi = 0;
    secret_device.dv_size.lo = SECRET_SIZE;
    secret_device.dv_size.hi = 0;
    return &secret_device;
}

PRIVATE int secret_transfer(int procnr, int opcode, u64_t position, iovec_t *iov, unsigned nr_req)
{
    int bytes, ret;

    printf("secret_transfer()\n");

    switch (opcode)
    {
        case DEV_GATHER_S: /* Reading */
            bytes = iov->iov_size > size ? iov->iov_size : size;
          
            if (bytes <= 0) {
               return OK;
            }
          
            ret = sys_safecopyto((endpoint_t) procnr, (cp_grant_id_t) iov->iov_addr, 0,
                                (vir_bytes) secretkeeper,
                                 bytes, D);
            iov->iov_size -= bytes;
            break;
          
        case DEV_SCATTER_S: /* Writing */
            bytes = iov->iov_size + size < SECRET_SIZE ? iov->iov_size : (SECRET_SIZE - size);
          
            if (bytes <= 0) {
               return OK;
            }
          
            ret = sys_safecopyfrom((endpoint_t) procnr, (cp_grant_id_t) iov->iov_addr, 0,
             (vir_bytes) (secretkeeper), bytes, D);
          
            size += bytes;
            break;

        default:
            return EINVAL;
    }
    return ret;
}

PRIVATE void secret_geometry(struct partition *entry)
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
            printf("%s", (char *) secretkeeper);
        break;

        case SEF_INIT_LU:
            /* Restore the state. */
            lu_state_restore();
            do_announce_driver = FALSE;

            printf("%sHey, I'm a new version!\n", (char *) secretkeeper);
        break;

        case SEF_INIT_RESTART:
            printf("%sHey, I've just been restarted!\n", (char *) secretkeeper);
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
   
    /*
     * Perform initialization.
     */
    sef_local_startup();

    /*
     * Run the main loop.
     */

    /*driver_task(&secret_tab, DRIVER_STD);*/
    chardriver_task(&secret_tab, CHARDRIVER_SYNC);

    return OK;
}

