#include <sys/types.h>

#include <stdlib.h>   /* standart c library */
#include <stdio.h>   /* in/out library */
#include <string.h>   /* string functions */
#include <pwd.h>   /* for struct passwd */
//#include <crypt.h>  /* for crypt() */
//#include <unistd.h>

#define PAM_SM_AUTH

#include <security/pam_modules.h>   /* standart pam library */
#include <security/pam_appl.h>   /* for conversation function */


PAM_EXTERN int pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
    int retval;
    const char *name;
    struct passwd *pwd;

    /* get username */
    retval = pam_get_user(pamh, &name, "login: ");
    if (retval != PAM_SUCCESS)
        return PAM_AUTH_ERR;
    pwd = getpwnam(name);
    if (pwd == NULL)
        return PAM_USER_UNKNOWN;

    /* get password */
    char *password, *crypt_password;
    char right[] = "12345";     /* right password */
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
    
    /*crypt_password = crypt(password, pwd->pw_passwd);
    if ((!pwd->pw_passwd[0]) || 
        (crypt_password == NULL) || 
        (strcmp(crypt_password, pwd->pw_passwd) != 0)) 
        retval = PAM_AUTH_ERR;
    else
        retval = PAM_SUCCESS;*/

    if (strcmp(right, password) == 0)
        retval = PAM_SUCCESS;
    else
        retval = PAM_AUTH_ERR;

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
