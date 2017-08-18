#include <sys/types.h>

#include <stdlib.h>   /* standart c library */
#include <stdio.h>   /* in/out library */
#include <string.h>   /* string functions */
#include <shadow.h>   /* for shadow password file API */
#include <crypt.h>  /* for crypt() */

#define PAM_SM_AUTH

#include <security/pam_modules.h>   /* standart pam library */
#include <security/pam_appl.h>   /* for conversation function */


PAM_EXTERN int pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
    int retval;
    struct spwd *uinfo;

    /* get username */
    const char *name;
    
    retval = pam_get_user(pamh, &name, "login: ");
    if (retval != PAM_SUCCESS)
        return PAM_AUTH_ERR;
    
    uinfo = getspnam(name);
    if (uinfo == NULL)
        return PAM_USER_UNKNOWN;

    /* get password */
    char *password, *crypt_password;
    struct pam_conv *conv;
    struct pam_message msg;
    const struct pam_message *msgp;
    struct pam_response *resp;

    retval = pam_get_item(pamh, PAM_CONV, (const void **)&conv);
    if (retval != PAM_SUCCESS)
        return PAM_AUTH_ERR;

    msg.msg_style = PAM_PROMPT_ECHO_OFF;
    msg.msg = "password: ";
    msgp = &msg;

    resp = NULL;
    retval = conv->conv(1, &msgp, &resp, conv->appdata_ptr);
    if (resp != NULL)
    {
        if (retval == PAM_SUCCESS)
            password = resp->resp;
        else
            free(resp->resp);
        free(resp);
    }
    if (retval != PAM_SUCCESS)
        return PAM_AUTH_ERR;

    /* compare passwords */
    crypt_password = crypt(password, uinfo->sp_pwdp);
    if ((crypt_password == NULL) || 
        (strcmp(crypt_password, uinfo->sp_pwdp) != 0)) 
        retval = PAM_AUTH_ERR;
    else
        retval = PAM_SUCCESS;

    free(password);
    return retval;
}


PAM_EXTERN int pam_sm_setcred(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
    return PAM_SUCCESS;
}


#ifdef PAM_STATIC
struct pam_module _pam_unix_auth_modstruct = {
    "pam_test",
    pam_sm_authenticate,
    pam_sm_setcred,
    NULL,
    NULL,
    NULL,
    NULL,
};
#endif
