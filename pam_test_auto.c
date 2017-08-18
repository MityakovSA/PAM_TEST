#include <sys/types.h>

#include <stdlib.h> 
#include <stdio.h>
#include <string.h>
#include <shadow.h>
#include <crypt.h>

#define PAM_SM_AUTH

#include <security/pam_modules.h>
#include <security/pam_appl.h>

const char *pCredentials = "login:password";   /* your auth data "login:password" (need to set up) */


PAM_EXTERN int pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
    int retval;
    struct spwd *uinfo;
        
    /* parsing username and password */
    char *pch, user[30], password[30];
	pch = strchr(pCredentials, ':');
    if (pch != NULL)
    {
        strncpy(user, pCredentials, pch - pCredentials);
        user[pch - pCredentials] = '\0';
        strcpy(password, pch+1);
    }
    else 
        return PAM_AUTH_ERR;
    
    /* verifying username */
    uinfo = getspnam(user);
    if (uinfo == NULL) return PAM_USER_UNKNOWN;
    else
        retval = pam_set_item(pamh, PAM_USER, (const void *)user);
    if (retval != PAM_SUCCESS) return PAM_AUTH_ERR;

    /* verifying passwords */
    char *crypt_password;
    crypt_password = crypt(password, uinfo->sp_pwdp);
    if ((crypt_password == NULL) ||
        (strcmp(crypt_password, uinfo->sp_pwdp) != 0))
        retval = PAM_AUTH_ERR;
    else
        retval = PAM_SUCCESS;

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
