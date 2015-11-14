#include <minix/drivers.h>
#include <minix/chardriver.h>
#include <stdio.h>
#include <stdlib.h>
#include <minix/ds.h>
#include <minix/syslib.h>
/*#include <sys/ioc_secret.h>
*/
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
/** Flag to determine if device is currently being used */
int occupied;

/*
 * Function prototypes for the secret driver.
 */
static int secret_open(message *m);
static int secret_close(message *m);
static struct device * secret_prepare(dev_t device);
static int secret_transfer(endpoint_t endpt, int opcode, u64_t position,
	iovec_t *iov, unsigned int nr_req, endpoint_t user_endpt, unsigned int
	flags);
static int ioctl(message *m);

/* SEF functions and variables. */
static void sef_local_startup(void);
static int sef_cb_init(int type, sef_init_info_t *info);
static int sef_cb_lu_state_save(int);
static int lu_state_restore(void);

/* Entry points to the secret driver. */
static struct chardriver secret_tab =
{
    secret_open,
    secret_close,
    ioctl,
    secret_prepare,
    secret_transfer,
    nop_cleanup,
    nop_alarm,
    nop_cancel,
    nop_select,
    NULL
};

/** Represents the /dev/secret device. */
static struct device secret_device;

/* Allows owner of a secret to change ownership to another user */
static int ioctl (message *m) {
   int returnValue, res;
   struct ucred *credential = calloc(1, sizeof(struct ucred));

   uid_t grantee; /* the uid of the new owner of the secret */
   res = sys_safecopyfrom(m->USER_ENDPT, (vir_bytes)m->IO_GRANT,
     (vir_bytes)&grantee, sizeof(grantee));

   returnValue = getnucred(m->USER_ENDPT, credential);

   if (returnValue != -1) {
      owner = grantee;
      return OK;
   }

   return ENOTTY;
}

/** State variable to count the number of times the device has been opened. */
static int open_counter;

static int secret_open(message *m)
{
    struct ucred process_owner; /* has info of process trying to open secret */

    getnucred(m->USER_ENDPT, &process_owner);

    /* if there is no current owner */
    if (owner == NO_OWNER) {
        switch (m->COUNT) {
            case O_WRONLY:
                /* get uid of calling process and set owner */
                owner = process_owner.uid;
                printf("process with uid %d now owns the secret\n", owner);
                openFDs++;
                break;

            case O_RDONLY:
                openFDs++;
                break;

            case O_RDWR:
                printf("3\n");
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
                    openFDs++;
                }
                break;
        }
    }

    return OK;
}

static int secret_close(message *m)
{
    openFDs--;

    if (openFDs == 0) {
        owner = NO_OWNER;
        free(secretkeeper);
        secretkeeper = malloc(SECRET_SIZE);
    }

    return OK;
}

static struct device * secret_prepare(dev_t UNUSED(dev))
{
    secret_device.dv_base = make64(0, 0);
    secret_device.dv_size = make64(SECRET_SIZE, 0);
    return &secret_device;
}

static int secret_transfer(endpoint_t endpt, int opcode, u64_t position,
    iovec_t *iov, unsigned nr_req, endpoint_t UNUSED(user_endpt),
    unsigned int UNUSED(flags))
{
    int bytes, ret;

    /*printf("secret_transfer()\n");*/

    if (nr_req != 1)
    {
        /* This should never trigger for character drivers at the moment. */
        printf("HELLO: vectored transfer request, using first element only\n");
    }

    bytes = SECRET_SIZE - ex64lo(position) < iov->iov_size ?
            SECRET_SIZE - ex64lo(position) : iov->iov_size;

    if (bytes <= 0)
    {
        return OK;
    }
    switch (opcode)
    {
        case DEV_GATHER_S:
            printf("here");
            ret = sys_safecopyto(endpt, (cp_grant_id_t) iov->iov_addr, 0,
                                (vir_bytes) ((char *)secretkeeper + ex64lo(position)),
                                 bytes);
            iov->iov_size -= bytes;
            break;

        default:
            return EINVAL;
    }
    return ret;
}

static int sef_cb_lu_state_save(int UNUSED(state)) {
/* Save the state. */
    ds_publish_u32("open_counter", open_counter, DSF_OVERWRITE);

    return OK;
}

static int lu_state_restore() {
/* Restore the state. */
    u32_t value;

    ds_retrieve_u32("open_counter", &value);
    ds_delete_u32("open_counter");
    open_counter = (int) value;

    return OK;
}

static void sef_local_startup()
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

static int sef_cb_init(int type, sef_init_info_t *UNUSED(info))
{
/* Initialize the secret driver. */
    int do_announce_driver = TRUE;

    owner = NO_OWNER;
    secretkeeper = malloc(SECRET_SIZE);
    openFDs = 0;

    open_counter = 0;
    switch(type) {
        case SEF_INIT_FRESH:
            printf("\nService secret is now running\n"); 
        break;

        case SEF_INIT_LU:
            /* Restore the state. */
            lu_state_restore();
            do_announce_driver = FALSE;

            printf("Hey, I'm a new version!\n");
        break;

        case SEF_INIT_RESTART:
            printf("Hey, I've just been restarted!\n");
        break;
    }

    /* Announce we are up when necessary. */
    if (do_announce_driver) {
        chardriver_announce();
    }

    /* Initialization completed successfully. */
    return OK;
}

int main(void)
{
    /*
     * Perform initialization.
     */
    sef_local_startup();

    /*
     * Run the main loop.
     */
    chardriver_task(&secret_tab, CHARDRIVER_SYNC);
    return OK;
}

